package main

import (
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync" // Used for Map
)

// Helper Map wrapper to match existing API usage
type Map struct {
	sync.Map
}

func (m *Map) Put(key string, value interface{}) {
	m.Store(key, value)
}

func (m *Map) Delete(key string) {
	m.LoadAndDelete(key)
}

func (m *Map) ForEach(f func(key string, valueConn interface{}) bool) {
	m.Range(func(k, v interface{}) bool {
		return f(k.(string), v)
	})
}

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
            
            // Critical fix: Copy data before passing to goroutine
            // Otherwise 'buf' is overwritten by next read while goroutine is processing
            packetData := make([]byte, n)
            copy(packetData, buf[:n])
            
			go handler.handlePacket(packetData, addr)
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
		agentType string
		agentId   string
		err       error
	)

	// Packet structure expected: [Encrypted Header (8 bytes: Type+ID)] + [Encrypted Payload (Data)]
	if len(data) < 8 {
		return
	}

	remoteAddr := addr.String()
	header := data[:8]
	payload := data[8:] // Encrypted payload

	// 1. Parse Header to get ID (and Type)
	// parseAgentData decrypts the buffer and reads Type/ID. 
	// If we pass just header, it reads Type/ID and returns empty Info.
	agentType, agentId, _, err = parseAgentData(header, handler.Config.EncryptKey)
	if err != nil {
		return
	}

	// 2. Routing Logic
	if !ModuleObject.ts.TsAgentIsExists(agentId) {
		// New Agent (Beat Packet)
		// Beat Packet Payload is "Encrypted Info".
		// parseAgentData(data) would return Type, ID, and Decrypted Info.
		// So we re-parse full data to get the Info for Creation.
		_, _, agentInfo, err := parseAgentData(data, handler.Config.EncryptKey)
		if err != nil {
			return
		}

		_, err = ModuleObject.ts.TsAgentCreate(agentType, agentId, agentInfo, handler.Name, remoteAddr, false)
		if err != nil {
			return
		}
	} else {
		// Existing Agent
		emptyMark := ""
		_ = ModuleObject.ts.TsAgentUpdateDataPartial(agentId, struct {
			Mark *string `json:"mark"`
		}{Mark: &emptyMark})
	}

	handler.AgentConnects.Put(agentId, addr)

	// 3. Process Payload (if any)
	// Payload is Encrypted(Data). ProcessData expects this format.
	if len(payload) > 0 {
		_ = ModuleObject.ts.TsAgentSetTick(agentId)
		// ProcessData expects Encrypted Data. 
		// Since we constructed the packet as Encrypt(Header) + Encrypt(Data),
		// 'payload' IS Encrypt(Data). Perfect.
		_ = ModuleObject.ts.TsAgentProcessData(agentId, payload)
	}

	// 4. Send Tasks
	// Use TsAgentGetHostedAll to support Tunnels etc.
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
	}
}

func writeData(conn *net.UDPConn, data []byte, addr *net.UDPAddr) error {
	// Directly send data. No length header packet.
	// UDP packet size limit is handled by the network stack/MTU, 
	// we assume data < 64KB. If larger, we'd need application-level fragmentation 
	// but for now we just remove the splitting to fix connectivity.
	_, err := conn.WriteToUDP(data, addr)
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
