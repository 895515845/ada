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

type UDPConfig struct {
	Port       int    `json:"port_bind"`
	Prepend    string `json:"prepend_data"`
	EncryptKey string `json:"encrypt_key"`

	Protocol string `json:"protocol"`
}

type UDP struct {
	Config        UDPConfig
	Name          string
	Active        bool
	Listener      *net.UDPConn
	AgentConnects Map
}

func (handler *UDP) Start() error {
	var err error = nil
	address := fmt.Sprintf("0.0.0.0:%d", handler.Config.Port)

	fmt.Println("  ", "Started UDP listener: "+address)

	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}

	handler.Listener, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := handler.Listener.ReadFromUDP(buf)
			if err != nil {
				return
			}
			go handler.handlePacket(buf[:n], addr)
		}
	}()
	handler.Active = true

	return err
}

func (handler *UDP) Stop() error {
	if handler.Listener != nil {
		_ = handler.Listener.Close()
	}

	handler.AgentConnects.ForEach(func(key string, valueConn interface{}) bool {
		conn, ok := valueConn.(*net.UDPAddr)
		if ok && conn != nil {
			// UDP doesn't have explicit close, just remove from map
		}
		return true
	})

	return nil
}

func (handler *UDP) handlePacket(data []byte, addr *net.UDPAddr) {
	var (
		agentType  string
		agentId    string
		agentInfo  []byte
		err        error
	)

	remoteAddr := addr.String()

	agentType, agentId, agentInfo, err = parseAgentData(data, handler.Config.EncryptKey)
	if err != nil {
		return
	}

	if !ModuleObject.ts.TsAgentIsExists(agentId) {
		_, err = ModuleObject.ts.TsAgentCreate(agentType, agentId, agentInfo, handler.Name, remoteAddr, false)
		if err != nil {
			return
		}
	}

	handler.AgentConnects.Put(agentId, addr)

	sendData, err := ModuleObject.ts.TsAgentGetHostedAll(agentId, 0x1900000)
	if err != nil {
		handler.AgentConnects.Delete(agentId)
		return
	}

	if sendData != nil && len(sendData) > 0 {
		err = writeData(handler.Listener, sendData, addr)
		if err != nil {
			handler.AgentConnects.Delete(agentId)
			return
		}

		_ = ModuleObject.ts.TsAgentSetTick(agentId)
		_ = ModuleObject.ts.TsAgentProcessData(agentId, data)
	}
}

func writeData(conn *net.UDPConn, data []byte, addr *net.UDPAddr) error {
	dataLen := len(data)
	bufLen := []byte{
		byte(dataLen >> 24),
		byte(dataLen >> 16),
		byte(dataLen >> 8),
		byte(dataLen),
	}

	_, err := conn.WriteToUDP(bufLen, addr)
	if err != nil {
		return err
	}

	_, err = conn.WriteToUDP(data, addr)
	return err
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
