package main

import (
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"
)

type TCPConfig struct {
	Port       int    `json:"port_bind"`
	Prepend    string `json:"prepend_data"`
	EncryptKey string `json:"encrypt_key"`

	Protocol string `json:"protocol"`
}

type TCP struct {
	Config        TCPConfig
	Name          string
	Active        bool
	Listener      net.Listener
	AgentConnects Map
}

func (handler *TCP) Start() error {
	var err error = nil
	address := fmt.Sprintf("0.0.0.0:%d", handler.Config.Port)

	fmt.Println("  ", "Started TCP listener: "+address)

	handler.Listener, err = net.Listen("tcp", address)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := handler.Listener.Accept()
			if err != nil {
				return
			}
			go handler.handleConnection(conn)
		}
	}()
	handler.Active = true

	return err
}

func (handler *TCP) Stop() error {
	if handler.Listener != nil {
		_ = handler.Listener.Close()
	}

	handler.AgentConnects.ForEach(func(key string, valueConn interface{}) bool {
		conn, ok := valueConn.(net.Conn)
		if ok && conn != nil {
			_ = conn.Close()
		}
		return true
	})

	return nil
}

func (handler *TCP) handleConnection(conn net.Conn) {
	var (
		data       []byte
		agentType  string
		agentId    string
		agentInfo  []byte
		err        error
	)

	remoteAddr := conn.RemoteAddr().String()

	data, err = readData(conn)
	if err != nil {
		_ = conn.Close()
		return
	}

	agentType, agentId, agentInfo, err = parseAgentData(data, handler.Config.EncryptKey)
	if err != nil {
		_ = conn.Close()
		return
	}

	if !ModuleObject.ts.TsAgentIsExists(agentId) {
		_, err = ModuleObject.ts.TsAgentCreate(agentType, agentId, agentInfo, handler.Name, remoteAddr, false)
		if err != nil {
			_ = conn.Close()
			return
		}
	}

	handler.AgentConnects.Put(agentId, conn)

	for {
		sendData, err := ModuleObject.ts.TsAgentGetHostedAll(agentId, 0x1900000)
		if err != nil {
			break
		}

		if sendData != nil && len(sendData) > 0 {
			err = writeData(conn, sendData)
			if err != nil {
				break
			}

			data, err = readData(conn)
			if err != nil {
				break
			}

			_ = ModuleObject.ts.TsAgentSetTick(agentId)
			_ = ModuleObject.ts.TsAgentProcessData(agentId, data)
		} else {
			if !isConnected(conn) {
				break
			}
		}
	}

	handler.AgentConnects.Delete(agentId)
	_ = conn.Close()
}

func readData(conn net.Conn) ([]byte, error) {
	bufLen := make([]byte, 4)
	_, err := conn.Read(bufLen)
	if err != nil {
		return nil, err
	}

	dataLen := int(bufLen[0])<<24 | int(bufLen[1])<<16 | int(bufLen[2])<<8 | int(bufLen[3])
	if dataLen <= 0 || dataLen > 0x1900000 {
		return nil, fmt.Errorf("invalid data length: %d", dataLen)
	}

	data := make([]byte, dataLen)
	_, err = conn.Read(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func writeData(conn net.Conn, data []byte) error {
	dataLen := len(data)
	bufLen := []byte{
		byte(dataLen >> 24),
		byte(dataLen >> 16),
		byte(dataLen >> 8),
		byte(dataLen),
	}

	_, err := conn.Write(bufLen)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)
	return err
}

func isConnected(conn net.Conn) bool {
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})

	_, err := conn.Read(buf)
	if err != nil {
		return false
	}
	return true
}

func parseAgentData(data []byte, encKeyHex string) (string, string, []byte, error) {
	encKey, err := hex.DecodeString(encKeyHex)
	if err != nil {
		return "", "", nil, err
	}

	rc4crypt, err := rc4.NewCipher(encKey)
	if err != nil {
		return "", "", nil, err
	}

	agentInfo := make([]byte, len(data))
	rc4crypt.XORKeyStream(agentInfo, data)

	agentType := fmt.Sprintf("%08x", binary.BigEndian.Uint32(agentInfo[:4]))
	agentInfo = agentInfo[4:]
	agentId := fmt.Sprintf("%08x", binary.BigEndian.Uint32(agentInfo[:4]))
	agentInfo = agentInfo[4:]

	return agentType, agentId, agentInfo, nil
}
