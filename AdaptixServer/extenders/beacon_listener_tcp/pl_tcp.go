package main

import (
	"fmt"
	"net"
)

type TCPConfig struct {
	Port       int    `json:"port_bind"`
	Prepend    string `json:"prepend_data"`
	EncryptKey string `json:"encrypt_key"`

	Protocol string `json:"protocol"`
}

type TCP struct {
	Listener net.Listener
	Config   TCPConfig
	Name     string
	Active   bool
}

func (handler *TCP) Start() error {
	var err error = nil
	address := fmt.Sprintf("0.0.0.0:%d", handler.Config.Port)

	fmt.Println("  ", "Started TCP listener: "+address)

	handler.Listener, err = net.Listen("tcp", address)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := handler.Listener.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()

				buffer := make([]byte, 65535)
				n, err := conn.Read(buffer)
				if err != nil {
					return
				}

				data := make([]byte, n)
				copy(data, buffer[:n])

				agentId, err := ModuleObject.ListenerInteralHandler(handler.Name, data)
				if err == nil && agentId != "" {
					sendData, err := ModuleObject.ts.TsAgentGetHostedTasks(agentId, 0x1900000)
					if err == nil && sendData != nil && len(sendData) > 0 {
						conn.Write(sendData)
					}
				}
			}(conn)
		}
	}()

	handler.Active = true
	return err
}

func (handler *TCP) Stop() error {
	var err error = nil

	if handler.Listener != nil {
		err = handler.Listener.Close()
	}

	handler.Active = false
	return err
}
