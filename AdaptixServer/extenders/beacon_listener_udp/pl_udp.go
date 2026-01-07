package main

type UDPConfig struct {
	Port       int    `json:"port_bind"`
	Prepend    string `json:"prepend_data"`
	EncryptKey string `json:"encrypt_key"`

	Protocol string `json:"protocol"`
}

type UDP struct {
	Config UDPConfig
	Name   string
	Active bool
}
