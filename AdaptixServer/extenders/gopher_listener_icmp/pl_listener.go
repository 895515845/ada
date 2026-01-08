// Package main implements listener validation and management for ICMP
// 此包实现ICMP监听器的验证和管理功能
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/Adaptix-Framework/axc2"
)

// HandlerListenerValid 验证ICMP监听器配置
// HandlerListenerValid validates the ICMP listener configuration
func (m *ModuleExtender) HandlerListenerValid(data string) error {
	var (
		err  error
		conf ICMPConfig
	)

	err = json.Unmarshal([]byte(data), &conf)
	if err != nil {
		return err
	}

	// 验证监听地址 - Validate listen address
	if conf.ListenAddr == "" {
		return errors.New("ListenAddr is required")
	}

	// 验证监听地址格式 - Validate listen address format
	ip := net.ParseIP(conf.ListenAddr)
	if ip == nil {
		return errors.New("ListenAddr must be a valid IP address")
	}

	// 验证回调地址 - Validate callback addresses
	if conf.Callback_addresses == "" {
		return errors.New("callback_addresses is required")
	}
	lines := strings.Split(strings.TrimSpace(conf.Callback_addresses), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 对于ICMP，回调地址可以只是IP（不需要端口）
		// For ICMP, callback address can be just IP (no port needed)
		callbackIP := net.ParseIP(line)
		if callbackIP == nil {
			// 尝试解析域名格式
			// Try parsing as hostname
			if len(line) == 0 || len(line) > 253 {
				return fmt.Errorf("Invalid callback address: %s\n", line)
			}
			parts := strings.Split(line, ".")
			for _, part := range parts {
				if len(part) == 0 || len(part) > 63 {
					return fmt.Errorf("Invalid callback address: %s\n", line)
				}
			}
		}
	}

	// 验证超时时间 - Validate timeout
	if conf.Timeout < 1 {
		return errors.New("Timeout must be greater than 0")
	}

	// 验证加密密钥 - Validate encryption key
	match, _ := regexp.MatchString("^[0-9a-f]{32}$", conf.EncryptKey)
	if len(conf.EncryptKey) != 32 || !match {
		return errors.New("encrypt_key must be 32 hex characters")
	}

	// 验证最大分片大小 - Validate max fragment size
	if conf.MaxFragmentSize < 100 || conf.MaxFragmentSize > MAX_ICMP_PAYLOAD_SIZE {
		return fmt.Errorf("max_fragment_size must be between 100 and %d", MAX_ICMP_PAYLOAD_SIZE)
	}

	return nil
}

// HandlerCreateListenerDataAndStart 创建并启动ICMP监听器
// HandlerCreateListenerDataAndStart creates and starts the ICMP listener
func (m *ModuleExtender) HandlerCreateListenerDataAndStart(name string, configData string, listenerCustomData []byte) (adaptix.ListenerData, []byte, any, error) {
	var (
		listenerData adaptix.ListenerData
		customdData  []byte
	)

	var (
		listener *ICMP
		conf     ICMPConfig
		err      error
	)

	if listenerCustomData == nil {
		err = json.Unmarshal([]byte(configData), &conf)
		if err != nil {
			return listenerData, customdData, listener, err
		}

		// 格式化回调地址 - Format callback addresses
		conf.Callback_addresses = strings.ReplaceAll(conf.Callback_addresses, " ", "")
		conf.Callback_addresses = strings.ReplaceAll(conf.Callback_addresses, "\n", ", ")
		conf.Callback_addresses = strings.TrimSuffix(conf.Callback_addresses, ", ")

		conf.Protocol = "icmp"

		// 设置默认值 - Set default values
		if conf.MaxFragmentSize == 0 {
			conf.MaxFragmentSize = DEFAULT_FRAGMENT_SIZE
		}

	} else {
		err = json.Unmarshal(listenerCustomData, &conf)
		if err != nil {
			return listenerData, customdData, listener, err
		}
	}

	// 创建监听器实例 - Create listener instance
	listener = &ICMP{
		Name:          name,
		Config:        conf,
		AgentConnects: NewMap(),
		JobConnects:   NewMap(),
		BeaconManager: NewBeaconManager(),
	}

	// 启动监听器 - Start listener
	err = listener.Start(m.ts)
	if err != nil {
		return listenerData, customdData, listener, err
	}

	// 构建监听器数据 - Build listener data
	listenerData = adaptix.ListenerData{
		BindHost:  listener.Config.ListenAddr,
		BindPort:  "ICMP",
		AgentAddr: conf.Callback_addresses,
		Status:    "Listen",
	}

	if !listener.Active {
		listenerData.Status = "Closed"
	}

	// 序列化配置 - Serialize configuration
	var buffer bytes.Buffer
	err = json.NewEncoder(&buffer).Encode(listener.Config)
	if err != nil {
		return listenerData, customdData, listener, err
	}
	customdData = buffer.Bytes()

	return listenerData, customdData, listener, nil
}

// HandlerEditListenerData 编辑监听器配置
// HandlerEditListenerData edits the listener configuration
func (m *ModuleExtender) HandlerEditListenerData(name string, listenerObject any, configData string) (adaptix.ListenerData, []byte, bool) {
	var (
		listenerData adaptix.ListenerData
		customdData  []byte
		ok           bool = false
	)

	var (
		err  error
		conf ICMPConfig
	)

	listener := listenerObject.(*ICMP)
	if listener.Name == name {

		err = json.Unmarshal([]byte(configData), &conf)
		if err != nil {
			return listenerData, customdData, false
		}

		// 格式化回调地址 - Format callback addresses
		conf.Callback_addresses = strings.ReplaceAll(conf.Callback_addresses, " ", "")
		conf.Callback_addresses = strings.ReplaceAll(conf.Callback_addresses, "\n", ", ")
		conf.Callback_addresses = strings.TrimSuffix(conf.Callback_addresses, ", ")

		// 更新可编辑配置 - Update editable configuration
		listener.Config.Callback_addresses = conf.Callback_addresses
		listener.Config.Timeout = conf.Timeout
		listener.Config.ErrorAnswer = conf.ErrorAnswer

		// 构建监听器数据 - Build listener data
		listenerData = adaptix.ListenerData{
			BindHost:  listener.Config.ListenAddr,
			BindPort:  "ICMP",
			AgentAddr: listener.Config.Callback_addresses,
			Status:    "Listen",
		}
		if !listener.Active {
			listenerData.Status = "Closed"
		}

		// 序列化配置 - Serialize configuration
		var buffer bytes.Buffer
		err = json.NewEncoder(&buffer).Encode(listener.Config)
		if err != nil {
			return listenerData, customdData, false
		}
		customdData = buffer.Bytes()

		ok = true
	}

	return listenerData, customdData, ok
}

// HandlerListenerStop 停止监听器
// HandlerListenerStop stops the specified listener
func (m *ModuleExtender) HandlerListenerStop(name string, listenerObject any) (bool, error) {
	var (
		err error = nil
		ok  bool  = false
	)

	listener := listenerObject.(*ICMP)
	if listener.Name == name {
		err = listener.Stop()
		ok = true
	}

	return ok, err
}

// HandlerListenerGetProfile 获取监听器配置文件
// HandlerListenerGetProfile returns the listener's profile
func (m *ModuleExtender) HandlerListenerGetProfile(name string, listenerObject any) ([]byte, bool) {
	var (
		object bytes.Buffer
		ok     bool = false
	)

	listener := listenerObject.(*ICMP)
	if listener.Name == name {
		_ = json.NewEncoder(&object).Encode(listener.Config)
		ok = true
	}

	return object.Bytes(), ok
}

// formatPort 格式化端口号为字符串（ICMP使用"ICMP"作为端口标识）
// formatPort formats port to string (ICMP uses "ICMP" as port identifier)
func formatPort(port int) string {
	if port > 0 {
		return strconv.Itoa(port)
	}
	return "ICMP"
}
