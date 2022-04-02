package main

import (
	"bytes"
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"os"
	"strings"
	"time"
)

// command to send a query for update wireguard settings manually or diagnosis usages
func query_main(args []string) {
	var server_str string = "10.77.1.1:55550"
	var peers_str []string
	//var verbose bool = false

	var ps *string
	for _, arg := range args {
		if ps != nil {
			*ps = arg
			ps = nil
			continue
		}

		switch arg {
		case "-s", "--server":
			ps = &server_str
			break
		case "-v":
			//verbose = true
			break
		default:
			peers_str = append(peers_str, arg)
			break
		}
	}

	if ps != nil {
		printf("parameter value not set\n")
		os.Exit(1)
		return
	}

	if server_str == "" {
		usage()
		return
	}

	if !strings.Contains(server_str, ":") {
		server_str += ":55550"
	}

	raddr, err := net.ResolveUDPAddr("udp", server_str)
	if err != nil {
		printf("error resolve address '%s': %v\n", server_str, err)
		os.Exit(1)
		return
	}

	peers := make([]wgtypes.Key, len(peers_str))
	for i := range peers_str {
		peers[i], err = wgtypes.ParseKey(peers_str[i])
		if err != nil {
			if len(server_str) > 9 {
				server_str = server_str[:6]+"..."
			}
			printf("error parse key '%s': %v\n", server_str, err)
			os.Exit(1)
			return
		}
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		printf("error dial '%s': %v\n", server_str, err)
		os.Exit(1)
		return
	}

	buffer := new(bytes.Buffer)
	buffer.Grow(MaxPacketSize)
	for _, peer := range peers {
		req := NewPacketBody()
		req.Type = PacketTypeFindPeer
		req.SetKey(peer)
		req.Reserved = 0

		if buffer.Len() + req.PacketSize() > MaxPacketSize {
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
			_, err = conn.Write(buffer.Bytes())
			if err != nil {
				printf("error send packet: %v\n", err)
			}
			buffer.Reset()
		}

		WritePacket(buffer, req)
	}

	if buffer.Len() > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
		_, err = conn.Write(buffer.Bytes())
		if err != nil {
			printf("error send packet: %v\n", err)
		}
		buffer.Reset()
	}

	_ = conn.SetReadDeadline(time.Now().Add(time.Second * 30))

	recv_peer := make([]wgtypes.Key, 0, len(peers))
	for {
		recv_buf := make([]byte, 2048)
		n, rerr := conn.Read(recv_buf)
		recv_buf = recv_buf[:n]

		for len(recv_buf) > 4 {
			p, _buf, err := ReadPacket(recv_buf)
			if err != nil {
				printf("error read packet: %v\n", err)
				continue
			}

			var key wgtypes.Key
			var addr *net.UDPAddr
			if p.PacketType() == PacketTypeNack {
				key = p.(*PacketBody).GetKey()
				addr = nil
			}
			if res, ok := p.(ResponsePacket); ok {
				key = res.GetKey()
				addr = res.GetUDPAddr()
			}

			duplicate := false
			for _, exists_key := range recv_peer {
				if keyEquals(exists_key, key) {
					duplicate = true
				}
			}

			if addr == nil {
				fmt.Printf("%s not_resolved\n", key.String())
			} else {
				if duplicate {
					fmt.Printf("%s  %s\n", key.String(), addr.String(), "(duplicate)")
				} else {
					fmt.Printf("%s %s\n", key.String(), addr.String())
				}
			}

			if !duplicate {
				recv_peer = append(recv_peer, key)

				if len(recv_peer) >= len(peers) {
					return
				}
			}

			recv_buf = _buf
		}

		if rerr != nil {
			if netErr, ok := rerr.(net.Error); ok {
				if netErr.Timeout() {
					return
				}
			}
			printf("error read socket: %v\n", err)
		}
	}
}
