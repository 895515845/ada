package main

import (
	"fmt"
	"net"
)

type UDPConfig struct {
	Port       int    `json:"port_bind"`
	Prepend    string `json:"prepend_data"`
	EncryptKey string `json:"encrypt_key"`

	Protocol string `json:"protocol"`
}

type UDP struct {
	Listener net.PacketConn
	Config   UDPConfig
	Name     string
	Active   bool
}

func (handler *UDP) Start() error {
	var err error = nil
	address := fmt.Sprintf(":%d", handler.Config.Port)

	fmt.Println("  ", "Started UDP listener: "+address)

	handler.Listener, err = net.ListenPacket("udp", address)
	if err != nil {
		return err
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := handler.Listener.ReadFrom(buf)
			if err != nil {
				return
			}

			data := make([]byte, n)
			copy(data, buf[:n])

			go func(data []byte, addr net.Addr) {
				agentId, err := ModuleObject.ListenerInteralHandler(handler.Name, data)
				if err == nil && agentId != "" {
					sendData, err := ModuleObject.ts.TsAgentGetHostedTasks(agentId, 0x1900000)
					if err == nil && sendData != nil && len(sendData) > 0 {
						handler.Listener.WriteTo(sendData, addr)
					}
				}
			}(data, addr)
		}
	}()

	handler.Active = true
	return err
}

func (handler *UDP) Stop() error {
	var err error = nil

	if handler.Listener != nil {
		err = handler.Listener.Close()
	}

	handler.Active = false
	return err
}
