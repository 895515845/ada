// Package main implements the Gopher ICMP listener plugin for AdaptixServer
// 此包实现了AdaptixServer的Gopher ICMP监听器插件
package main

import (
	"errors"
	"io"

	"github.com/Adaptix-Framework/axc2"
)

// 隧道类型常量 - Tunnel type constants
const (
	TUNNEL_TYPE_SOCKS4     = 1
	TUNNEL_TYPE_SOCKS5     = 2
	TUNNEL_TYPE_LOCAL_PORT = 4
	TUNNEL_TYPE_REVERSE    = 5

	ADDRESS_TYPE_IPV4   = 1
	ADDRESS_TYPE_DOMAIN = 3
	ADDRESS_TYPE_IPV6   = 4

	SOCKS5_SERVER_FAILURE          byte = 1
	SOCKS5_NOT_ALLOWED_RULESET     byte = 2
	SOCKS5_NETWORK_UNREACHABLE     byte = 3
	SOCKS5_HOST_UNREACHABLE        byte = 4
	SOCKS5_CONNECTION_REFUSED      byte = 5
	SOCKS5_TTL_EXPIRED             byte = 6
	SOCKS5_COMMAND_NOT_SUPPORTED   byte = 7
	SOCKS5_ADDR_TYPE_NOT_SUPPORTED byte = 8
)

// Teamserver 定义与团队服务器交互的接口
// Teamserver interface defines methods for interacting with the team server
type Teamserver interface {
	// Agent相关方法 - Agent related methods
	TsAgentIsExists(agentId string) bool
	TsAgentCreate(agentCrc string, agentId string, beat []byte, listenerName string, ExternalIP string, Async bool) (adaptix.AgentData, error)
	TsAgentSetTick(agentId string) error
	TsAgentProcessData(agentId string, bodyData []byte) error
	TsAgentGetHostedAll(agentId string, maxDataSize int) ([]byte, error)
	TsAgentGetHostedTasks(agentId string, maxDataSize int) ([]byte, error)
	TsAgentUpdateDataPartial(agentId string, updateData interface{}) error

	// 任务相关方法 - Task related methods
	TsTaskRunningExists(agentId string, taskId string) bool
	TsTunnelChannelExists(channelId int) bool

	// 终端相关方法 - Terminal related methods
	TsAgentTerminalCloseChannel(terminalId string, status string) error
	TsTerminalConnExists(terminalId string) bool
	TsTerminalConnResume(agentId string, terminalId string, ioDirect bool)
	TsTerminalGetPipe(AgentId string, terminalId string) (*io.PipeReader, *io.PipeWriter, error)

	// 隧道相关方法 - Tunnel related methods
	TsTunnelGetPipe(AgentId string, channelId int) (*io.PipeReader, *io.PipeWriter, error)
	TsTunnelConnectionResume(AgentId string, channelId int, ioDirect bool)
	TsTunnelConnectionClose(channelId int)
	TsTunnelConnectionHalt(channelId int, errorCode byte)
	TsTunnelConnectionData(channelId int, data []byte)
}

// ModuleExtender 模块扩展器结构体
// Module extender structure that holds the teamserver reference
type ModuleExtender struct {
	ts Teamserver
}

// 全局变量 - Global variables
var (
	ModuleObject    *ModuleExtender
	ModuleDir       string
	ListenerDataDir string
	ListenersObject []any // *ICMP
)

// InitPlugin 初始化插件
// InitPlugin initializes the plugin with teamserver reference and directories
func InitPlugin(ts any, moduleDir string, listenerDir string) any {
	ModuleDir = moduleDir
	ListenerDataDir = listenerDir

	ModuleObject = &ModuleExtender{
		ts: ts.(Teamserver),
	}
	return ModuleObject
}

// ListenerValid 验证监听器配置
// ListenerValid validates the listener configuration
func (m *ModuleExtender) ListenerValid(data string) error {
	return m.HandlerListenerValid(data)
}

// ListenerStart 启动监听器
// ListenerStart starts the listener with the given configuration
func (m *ModuleExtender) ListenerStart(name string, data string, listenerCustomData []byte) (adaptix.ListenerData, []byte, error) {
	listenerData, customData, listener, err := m.HandlerCreateListenerDataAndStart(name, data, listenerCustomData)
	if err != nil {
		return listenerData, customData, err
	}

	ListenersObject = append(ListenersObject, listener)

	return listenerData, customData, nil
}

// ListenerEdit 编辑监听器配置
// ListenerEdit modifies the listener configuration
func (m *ModuleExtender) ListenerEdit(name string, data string) (adaptix.ListenerData, []byte, error) {
	for _, value := range ListenersObject {
		listenerData, customData, ok := m.HandlerEditListenerData(name, value, data)
		if ok {
			return listenerData, customData, nil
		}
	}
	return adaptix.ListenerData{}, nil, errors.New("listener not found")
}

// ListenerStop 停止监听器
// ListenerStop stops the specified listener
func (m *ModuleExtender) ListenerStop(name string) error {
	var (
		index int
		err   error
		ok    bool
	)

	for ind, value := range ListenersObject {
		ok, err = m.HandlerListenerStop(name, value)
		if ok {
			index = ind
			break
		}
	}

	if ok {
		ListenersObject = append(ListenersObject[:index], ListenersObject[index+1:]...)
	} else {
		return errors.New("listener not found")
	}

	return err
}

// ListenerGetProfile 获取监听器配置
// ListenerGetProfile returns the listener's profile configuration
func (m *ModuleExtender) ListenerGetProfile(name string) ([]byte, error) {
	for _, value := range ListenersObject {
		profile, ok := m.HandlerListenerGetProfile(name, value)
		if ok {
			return profile, nil
		}
	}
	return nil, errors.New("listener not found")
}

// ListenerInteralHandler 内部处理器（ICMP不使用）
// ListenerInteralHandler is not used for ICMP listener
func (m *ModuleExtender) ListenerInteralHandler(name string, data []byte) (string, error) {
	return "", errors.New("listener not found")
}
