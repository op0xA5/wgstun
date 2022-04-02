package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"hash/crc32"
	"net"
	"time"
)

/*
	Packet to store a command and data belongs to command, request or response use same packet struct.

	+-------+-------+----------+----------+
	| Magic |  Type |   Data   | Checksum |
	+-------+-------+----------+----------+
	| 16bit | 16bit |   ...    |   32bit  |
	+-------+-------+----------+----------+

	A packet typically have these fields:
	- Magic: an unit16 number equals PacketMagic
	- Type: an unit16 number to identify which command to request or response
	- Timestamp: when a packet sent
	- Reserved: for future use or padding struct
	- Checksum: a CRC32 checksum for all packet data except Checksum field

	A UDP packet can carry several packets, packet reader will read all packets continuous.
*/

const MaxPacketSize = 1280 /* recommend wireguard MTU */ - 20 /* IP Header */ - 8 /* UDP Header */

const PacketTypePing = 1 // Ping
const PacketTypePong = 2 // response to a Ping
const PacketTypeNack = 9 // Nack
const PacketTypeFindPeer = 10 // request to resolve ips
const PacketTypeIPv4 = 11 // response is a ipv4 record
const PacketTypeIPv6 = 12 // response is a ipv6 record
const PacketTypeGetMyIP = 20 // request to get client's public ip
const PacketTypeMyIPv4 = 21 // response to PacketTypeGetMyIP
const PacketTypeMyIPv6 = 22 // response to PacketTypeGetMyIP

const UnixTimestampFix = 946656000
const PacketMagic = 0x4877

// PacketHeader general packet header
type PacketHeader struct {
	Magic uint16
	Type  uint16
}
func GetPacketHeader(b []byte) *PacketHeader {
	b = b[:4]
	return &PacketHeader{
		Magic: binary.LittleEndian.Uint16(b),
		Type:  binary.LittleEndian.Uint16(b[2:]),
	}
}

// PacketBody general request or response packet
// use in type: Ping, Pong, Nack, FindPeer, GetMyIP
const __SizePacketBody = 48
type PacketBody struct {
	Magic     uint16
	Type      uint16
	Timestamp uint32
	Identity  [32]byte
	Reserved  uint32
	Checksum  uint32
}

func (p *PacketBody) PacketType() uint16 {
	return p.Type
}
func (*PacketBody) PacketSize() int {
	return __SizePacketBody
}

func NewPacketBody() *PacketBody {
	return &PacketBody{
		Magic:     PacketMagic,
		Timestamp: uint32(time.Now().Unix() - UnixTimestampFix),
	}
}

func (p *PacketBody) GetKey() wgtypes.Key {
	return p.Identity
}
func (p *PacketBody) SetKey(key wgtypes.Key) {
	p.Identity = key
}

// PacketIPv4Body packet with a IPv4 record
// use in type: PacketTypeIPv4, PacketTypeMyIPv4
const __SizePacketIPv4Body = 56
type PacketIPv4Body struct {
	Magic         uint16
	Type          uint16
	Timestamp     uint32
	Identity      [32]byte
	IP            [net.IPv4len]byte
	Reserved      uint16
	Port          uint16
	LastHandshake uint32
	Checksum      uint32
}

func (p *PacketIPv4Body) PacketType() uint16 {
	return p.Type
}
func (*PacketIPv4Body) PacketSize() int {
	return __SizePacketIPv4Body
}

// PacketIPv4Body packet with a IPv6 record
// use in type: PacketTypeIPv6, PacketTypeMyIPv6
const __SizePacketIPv6Body = 72
type PacketIPv6Body struct {
	Magic         uint16
	Type          uint16
	Timestamp     uint32
	Identity      [32]byte
	IP            [net.IPv6len]byte
	Reserved      uint16
	Port          uint16
	LastHandshake uint32
	Reserved2     uint32
	Checksum      uint32
}

func (p *PacketIPv6Body) PacketType() uint16 {
	return p.Type
}
func (*PacketIPv6Body) PacketSize() int {
	return __SizePacketIPv6Body
}

func NewPacketIPv4Body() *PacketIPv4Body {
	return &PacketIPv4Body{
		Magic:     PacketMagic,
		Type:      PacketTypeIPv4,
		Timestamp: uint32(time.Now().Unix() - UnixTimestampFix),
	}
}
func NewPacketIPv6Body() *PacketIPv6Body {
	return &PacketIPv6Body{
		Magic:     PacketMagic,
		Type:      PacketTypeIPv6,
		Timestamp: uint32(time.Now().Unix() - UnixTimestampFix),
	}
}

func (p *PacketIPv4Body) GetKey() wgtypes.Key {
	return p.Identity
}
func (p *PacketIPv4Body) SetKey(key wgtypes.Key) {
	p.Identity = key
}

func (p *PacketIPv4Body) GetIP() net.IP {
	ip := net.IP(p.IP[:])
	return ip.To4()
}
func (p *PacketIPv4Body) SetIP(ip net.IP) {
	if v4 := ip.To4(); v4 == nil {
		panic("cannot set v6 ip")
	}
	copy(p.IP[:], ip.To4())
}

func (p *PacketIPv4Body) SetUDPAddr(addr *net.UDPAddr) {
	p.SetIP(addr.IP)
	p.Port = uint16(addr.Port)
}

func (p *PacketIPv4Body) GetUDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   p.GetIP(),
		Port: int(p.Port),
	}
}

func (p *PacketIPv4Body) GetHandshakeTime() time.Time {
	timeLastHandshake := time.Unix(int64(p.LastHandshake)+UnixTimestampFix, 0)
	return timeLastHandshake
}
func (p *PacketIPv4Body) SetHandshakeTime(t time.Time) {
	p.LastHandshake = uint32(t.Unix() - UnixTimestampFix)
}

func (p *PacketIPv6Body) GetKey() wgtypes.Key {
	return p.Identity
}
func (p *PacketIPv6Body) SetKey(key wgtypes.Key) {
	p.Identity = key
}

func (p *PacketIPv6Body) GetIP() net.IP {
	ip := net.IP(p.IP[:])
	return ip.To16()
}
func (p *PacketIPv6Body) SetIP(ip net.IP) {
	copy(p.IP[:], ip.To16())
}

func (p *PacketIPv6Body) SetUDPAddr(addr *net.UDPAddr) {
	p.SetIP(addr.IP)
	p.Port = uint16(addr.Port)
}

func (p *PacketIPv6Body) GetUDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   p.GetIP(),
		Port: int(p.Port),
	}
}

func (p *PacketIPv6Body) GetHandshakeTime() time.Time {
	timeLastHandshake := time.Unix(int64(p.LastHandshake)+UnixTimestampFix, 0)
	return timeLastHandshake
}
func (p *PacketIPv6Body) SetHandshakeTime(t time.Time) {
	p.LastHandshake = uint32(t.Unix() - UnixTimestampFix)
}

// Packet general interface
type Packet interface {
	PacketType() uint16
	PacketSize() int
}

// ResponsePacket interface defines a packet can use as response
// PacketIPv4Body, PacketIPv6Body implements ResponsePacket
type ResponsePacket interface {
	Packet
	GetKey() wgtypes.Key
	GetUDPAddr() *net.UDPAddr
	GetHandshakeTime() time.Time
}

// ReadPacket reads a valid packet from bytes, return packet data and remains bytes or error if parse failed
func ReadPacket(b []byte) (Packet, []byte, error) {
	if len(b) < 4 {
		return nil, b, errors.New("packet size too short")
	}

	header := GetPacketHeader(b)
	if header.Magic != PacketMagic {
		return nil, b, errors.New("packet magic mismatch")
	}

	var packet Packet

	switch header.Type {
	case PacketTypePing, PacketTypePong, PacketTypeNack, PacketTypeFindPeer, PacketTypeGetMyIP:
		packet = new(PacketBody)
		break
	case PacketTypeIPv4, PacketTypeMyIPv4:
		packet = new(PacketIPv4Body)
		break
	case PacketTypeIPv6, PacketTypeMyIPv6:
		packet = new(PacketIPv6Body)
		break
	default:
		return nil, b, errors.New("unknown packet type")
	}

	packetSize := packet.PacketSize()
	if len(b) < packetSize {
		return nil, b, errors.New("packet size too short")
	}

	checksum := crc32.ChecksumIEEE(b[:packetSize-4])
	_checksum := binary.LittleEndian.Uint32(b[packetSize-4:])
	if checksum != _checksum {
		return nil, b, errors.New("packet checksum error")
	}

	r := bytes.NewReader(b)
	err := binary.Read(r, binary.LittleEndian, packet)
	return packet, b[packetSize:], err
}

// WritePacket write packet into buffer
func WritePacket(w *bytes.Buffer, p Packet) {
	packetSize := p.PacketSize()
	pos := w.Len()
	posChecksum := pos+packetSize-4

	w.Grow(packetSize)
	_ = binary.Write(w, binary.LittleEndian, p)
	buffer := w.Bytes()

	checksum := crc32.ChecksumIEEE(buffer[pos:posChecksum])
	binary.LittleEndian.PutUint32(buffer[posChecksum:], checksum)
}