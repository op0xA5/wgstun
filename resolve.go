package main

import (
	"bytes"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"time"
)

// ResolveResult saves peer info on wireguard server
type ResolveResult struct {
	// result values is valid, should check this before use Endpoint or other values
	Valid         bool
	Key           wgtypes.Key
	Endpoint      *net.UDPAddr
	// last handshake time
	HandshakeTime time.Time
}

type ResolveError struct {
	action string
	Addr string
	Err error
}
func (err ResolveError) Error() string {
	if err.action == "dail" {
		return "error dail '" + err.Addr + "': " + err.Err.Error()
	}
	return "error " + err.action + ": " + err.Err.Error()
}

// StunResolve query wgstun server for peer info
func StunResolve(raddr *net.UDPAddr, peers []wgtypes.Key) ([]ResolveResult, error) {
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, ResolveError{ "dail", raddr.String(), err}
	}

	return StunResolveConn(conn, peers)
}

// StunResolveConn query wgstun server use specified udp connection
func StunResolveConn(conn *net.UDPConn, peers []wgtypes.Key) ([]ResolveResult, error) {
	result := make([]ResolveResult, len(peers))
	for i, peer :=range peers {
		copy(result[i].Key[:], peer[:])
	}
	valid_count := 0

	buffer := new(bytes.Buffer)
	buffer.Grow(MaxPacketSize)
	for _, peer := range peers {
		req := NewPacketBody()
		req.Type = PacketTypeFindPeer
		req.SetKey(peer)
		req.Reserved = 0

		if buffer.Len() + req.PacketSize() > MaxPacketSize {
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
			_, err := conn.Write(buffer.Bytes())
			if err != nil {
				return nil, ResolveError{ "send packet", conn.RemoteAddr().String(), err}
			}
			buffer.Reset()
		}

		WritePacket(buffer, req)
	}

	if buffer.Len() > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
		_, err := conn.Write(buffer.Bytes())
		if err != nil {
			return nil, ResolveError{ "send packet", conn.RemoteAddr().String(), err}
		}
		buffer.Reset()
	}

	_ = conn.SetReadDeadline(time.Now().Add(time.Second * 30))

	var nack_keys []wgtypes.Key
	for {
		recv_buf := make([]byte, 2048)
		n, rerr := conn.Read(recv_buf)
		recv_buf = recv_buf[:n]

		for len(recv_buf) > 4 {
			p, _buf, err := ReadPacket(recv_buf)
			if err != nil {
				return nil, ResolveError{ "read packet", conn.RemoteAddr().String(), err}
			}

			var key wgtypes.Key
			if p.PacketType() == PacketTypeNack {
				key = p.(*PacketBody).GetKey()

				new_nack_key := true
				for i := range nack_keys {
					if keyEquals(result[i].Key, key) {
						new_nack_key = false
						break
					}
				}

				if new_nack_key {
					nack_keys = append(nack_keys, key)
					valid_count++
				}
			}
			if res, ok := p.(ResponsePacket); ok {
				key = res.GetKey()
				for i := range result {
					if (!result[i].Valid) && keyEquals(result[i].Key, key) {
						result[i].Valid = true
						result[i].Endpoint = res.GetUDPAddr()
						result[i].HandshakeTime = res.GetHandshakeTime()
						valid_count++
					}
				}
			}

			recv_buf = _buf
		}

		if valid_count == len(result) {
			return result, nil
		}

		if rerr != nil {
			if netErr, ok := rerr.(net.Error); ok {
				if netErr.Timeout() {
					return nil, ResolveError{ "timeout", conn.RemoteAddr().String(), rerr}
				}
			}
			return nil, ResolveError{ "read packet", conn.RemoteAddr().String(), rerr}
		}
	}
}
