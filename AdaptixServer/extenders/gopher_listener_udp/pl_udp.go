package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

type UDPConfig struct {
	HostBind           string `json:"host_bind"`
	PortBind           int    `json:"port_bind"`
	Callback_addresses string `json:"callback_addresses"`
	EncryptKey         string `json:"encrypt_key"`
	Timeout            int    `json:"timeout"`
	Protocol           string `json:"protocol"`
}

type UDPConnection struct {
	addr         *net.UDPAddr
	lastActivity time.Time
	ctx          context.Context
	handleCancel context.CancelFunc
}

type UDP struct {
	AgentConnects Map
	JobConnects   Map
	Conn          *net.UDPConn
	Config        UDPConfig
	Name          string
	Active        bool
	stopChan      chan struct{}
}

const (
	INIT_PACK     = 1
	EXFIL_PACK    = 2
	JOB_PACK      = 3
	TUNNEL_PACK   = 4
	TERMINAL_PACK = 5
)

type StartMsg struct {
	Type int    `msgpack:"id"`
	Data []byte `msgpack:"data"`
}

type InitPack struct {
	Id   uint   `msgpack:"id"`
	Type uint   `msgpack:"type"`
	Data []byte `msgpack:"data"`
}

type ExfilPack struct {
	Id   uint   `msgpack:"id"`
	Type uint   `msgpack:"type"`
	Task string `msgpack:"task"`
}

type JobPack struct {
	Id   uint   `msgpack:"id"`
	Type uint   `msgpack:"type"`
	Task string `msgpack:"task"`
}

type TunnelPack struct {
	Id        uint   `msgpack:"id"`
	Type      uint   `msgpack:"type"`
	ChannelId int    `msgpack:"channel_id"`
	Key       []byte `msgpack:"key"`
	Iv        []byte `msgpack:"iv"`
	Alive     bool   `msgpack:"alive"`
	Reason    byte   `msgpack:"reason"`
}

type TermPack struct {
	Id     uint   `msgpack:"id"`
	TermId int    `msgpack:"term_id"`
	Key    []byte `msgpack:"key"`
	Iv     []byte `msgpack:"iv"`
	Alive  bool   `msgpack:"alive"`
	Status string `msgpack:"status"`
}

func (handler *UDP) Start(ts Teamserver) error {
	address := fmt.Sprintf("%s:%d", handler.Config.HostBind, handler.Config.PortBind)

	fmt.Println("  ", "Started UDP listener: "+address)

	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}

	handler.Conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	handler.stopChan = make(chan struct{})
	handler.Active = true

	go handler.handlePackets(ts)

	time.Sleep(500 * time.Millisecond)
	return nil
}

func (handler *UDP) handlePackets(ts Teamserver) {
	buffer := make([]byte, 65535)

	for {
		select {
		case <-handler.stopChan:
			return
		default:
			_ = handler.Conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := handler.Conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			go handler.handlePacket(buffer[:n], addr, ts)
		}
	}
}

func (handler *UDP) handlePacket(data []byte, addr *net.UDPAddr, ts Teamserver) {
	var (
		recvData        []byte
		decryptedData   []byte
		sendData        []byte
		encKey          []byte
		err             error
		initMsg         StartMsg
	)

	// 保存原始数据引用
	recvData = data

	encKey, err = hex.DecodeString(handler.Config.EncryptKey)
	if err != nil {
		return
	}

	// 解密数据
	decryptedData, err = DecryptData(recvData, encKey)
	if err != nil {
		return
	}

	err = msgpack.Unmarshal(decryptedData, &initMsg)
	if err != nil {
		return
	}

	switch initMsg.Type {

	case INIT_PACK:
		var initPack InitPack
		err := msgpack.Unmarshal(initMsg.Data, &initPack)
		if err != nil {
			return
		}

		agentId := fmt.Sprintf("%08x", initPack.Id)
		agentType := fmt.Sprintf("%08x", initPack.Type)
		ExternalIP := addr.IP.String()

		if !ModuleObject.ts.TsAgentIsExists(agentId) {
			_, err = ModuleObject.ts.TsAgentCreate(agentType, agentId, initPack.Data, handler.Name, ExternalIP, false)
			if err != nil {
				return
			}
		} else {
			emptyMark := ""
			_ = ModuleObject.ts.TsAgentUpdateDataPartial(agentId, struct {
				Mark *string `json:"mark"`
			}{Mark: &emptyMark})
		}

		connection := UDPConnection{
			addr:         addr,
			lastActivity: time.Now(),
		}
		connection.ctx, connection.handleCancel = context.WithCancel(context.Background())

		handler.AgentConnects.Put(agentId, connection)

		sendData, err = ModuleObject.ts.TsAgentGetHostedTasks(agentId, 0x1900000)
		if err != nil {
			return
		}

		if sendData != nil && len(sendData) > 0 {
			err = handler.sendPacket(addr, sendData)
			if err != nil {
				return
			}
		}

		_ = ModuleObject.ts.TsAgentSetTick(agentId)

	case EXFIL_PACK:
		var exfilPack ExfilPack
		err := msgpack.Unmarshal(initMsg.Data, &exfilPack)
		if err != nil {
			return
		}

		agentId := fmt.Sprintf("%08x", exfilPack.Id)

		if !ModuleObject.ts.TsTaskRunningExists(agentId, exfilPack.Task) {
			return
		}

		// 传递解密后的完整数据而不是加密数据
		_ = ModuleObject.ts.TsAgentProcessData(agentId, decryptedData)
		_ = ModuleObject.ts.TsAgentSetTick(agentId)

	case JOB_PACK:
		var jobPack JobPack
		err := msgpack.Unmarshal(initMsg.Data, &jobPack)
		if err != nil {
			return
		}

		agentId := fmt.Sprintf("%08x", jobPack.Id)

		if !ModuleObject.ts.TsTaskRunningExists(agentId, jobPack.Task) {
			return
		}

		// 传递解密后的完整数据而不是加密数据
		_ = ModuleObject.ts.TsAgentProcessData(agentId, decryptedData)
		_ = ModuleObject.ts.TsAgentSetTick(agentId)

	case TUNNEL_PACK:
		// UDP 不适合实现持久隧道，因为它是无连接协议
		// 这里简化处理：接收数据并尝试转发，但不建立持久连接
		var tunPack TunnelPack
		err := msgpack.Unmarshal(initMsg.Data, &tunPack)
		if err != nil {
			return
		}

		agentId := fmt.Sprintf("%08x", tunPack.Id)

		if !ModuleObject.ts.TsTunnelChannelExists(tunPack.ChannelId) {
			return
		}

		if !tunPack.Alive {
			if tunPack.Reason < 1 || tunPack.Reason > 8 {
				tunPack.Reason = 5
			}
			ts.TsTunnelConnectionHalt(tunPack.ChannelId, tunPack.Reason)
			return
		}

		// 通知 teamserver 隧道连接已恢复（但 UDP 模式下是单次数据包处理）
		ts.TsTunnelConnectionResume(agentId, tunPack.ChannelId, false)

		// 尝试向隧道写入数据（如果有的话）
		if len(decryptedData) > 4 {
			pr, pw, err := ModuleObject.ts.TsTunnelGetPipe(agentId, tunPack.ChannelId)
			if err != nil {
				return
			}

			// 解密隧道数据
			blockDec, _ := aes.NewCipher(tunPack.Key)
			decStream := cipher.NewCTR(blockDec, tunPack.Iv)

			// 跳过消息头部，提取实际隧道数据
			tunnelData := decryptedData[4:]
			if len(tunnelData) > 0 {
				decBuffer := make([]byte, len(tunnelData))
				decStream.XORKeyStream(decBuffer, tunnelData)
				_, _ = pw.Write(decBuffer)
			}

			// 尝试读取响应数据并发送回去
			readBuffer := make([]byte, 4096)
			_ = pr.(*io.PipeReader).SetDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := pr.Read(readBuffer)
			if err == nil && n > 0 {
				blockEnc, _ := aes.NewCipher(tunPack.Key)
				encStream := cipher.NewCTR(blockEnc, tunPack.Iv)

				encData := make([]byte, n)
				encStream.XORKeyStream(encData, readBuffer[:n])

				msgLen := make([]byte, 4)
				binary.BigEndian.PutUint32(msgLen, uint32(len(encData)))
				message := append(msgLen, encData...)
				_ = handler.sendPacket(addr, message)
			}

			_ = pr.Close()
			_ = pw.Close()
		}

	case TERMINAL_PACK:
		// UDP 不适合实现持久终端，因为它是无连接协议
		// 这里简化处理：接收数据并尝试转发，但不建立持久连接
		var termPack TermPack
		err := msgpack.Unmarshal(initMsg.Data, &termPack)
		if err != nil {
			return
		}

		agentId := fmt.Sprintf("%08x", termPack.Id)
		terminalId := fmt.Sprintf("%08x", termPack.TermId)

		if !ModuleObject.ts.TsTerminalConnExists(terminalId) {
			return
		}

		if !termPack.Alive {
			_ = ts.TsAgentTerminalCloseChannel(terminalId, termPack.Status)
			return
		}

		// 通知 teamserver 终端连接已恢复（但 UDP 模式下是单次数据包处理）
		ts.TsTerminalConnResume(agentId, terminalId, false)

		// 尝试向终端写入数据（如果有的话）
		if len(decryptedData) > 4 {
			pr, pw, err := ModuleObject.ts.TsTerminalGetPipe(agentId, terminalId)
			if err != nil {
				return
			}

			// 解密终端数据
			blockDec, _ := aes.NewCipher(termPack.Key)
			decStream := cipher.NewCTR(blockDec, termPack.Iv)

			// 跳过消息头部，提取实际终端数据
			termData := decryptedData[4:]
			if len(termData) > 0 {
				decBuffer := make([]byte, len(termData))
				decStream.XORKeyStream(decBuffer, termData)
				_, _ = pw.Write(decBuffer)
			}

			// 尝试读取响应数据并发送回去
			readBuffer := make([]byte, 4096)
			_ = pr.(*io.PipeReader).SetDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := pr.Read(readBuffer)
			if err == nil && n > 0 {
				blockEnc, _ := aes.NewCipher(termPack.Key)
				encStream := cipher.NewCTR(blockEnc, termPack.Iv)

				encData := make([]byte, n)
				encStream.XORKeyStream(encData, readBuffer[:n])

				msgLen := make([]byte, 4)
				binary.BigEndian.PutUint32(msgLen, uint32(len(encData)))
				message := append(msgLen, encData...)
				_ = handler.sendPacket(addr, message)
			}

			_ = pr.Close()
			_ = pw.Close()
		}
	}
}

func (handler *UDP) Stop() error {
	var (
		err          error = nil
		listenerPath       = ListenerDataDir + "/" + handler.Name
	)

	// 首先标记为非活动状态
	handler.Active = false

	// 关闭停止通道，通知 goroutine 停止
	if handler.stopChan != nil {
		close(handler.stopChan)
	}

	// 关闭 UDP 连接
	if handler.Conn != nil {
		_ = handler.Conn.Close()
	}

	// 取消所有连接的 context
	handler.AgentConnects.ForEach(func(key string, valueConn interface{}) bool {
		connection, _ := valueConn.(UDPConnection)
		if connection.handleCancel != nil {
			connection.handleCancel()
		}
		return true
	})

	// 删除监听器数据目录
	_, err = os.Stat(listenerPath)
	if err == nil {
		err = os.RemoveAll(listenerPath)
		if err != nil {
			return fmt.Errorf("failed to remove %s folder: %s", listenerPath, err.Error())
		}
	}

	return nil
}

func (handler *UDP) sendPacket(addr *net.UDPAddr, data []byte) error {
	if handler.Conn == nil {
		return errors.New("conn is nil")
	}

	_, err := handler.Conn.WriteToUDP(data, addr)
	return err
}

func EncryptData(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return ciphertext, nil
}

func DecryptData(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
