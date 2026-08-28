package interceptor

import (
	"encoding/binary"
	"net"
)

// WinDivert Layers
const (
	WINDIVERT_LAYER_NETWORK         = 0
	WINDIVERT_LAYER_NETWORK_FORWARD = 1
	WINDIVERT_LAYER_FLOW            = 2
	WINDIVERT_LAYER_SOCKET          = 3
	WINDIVERT_LAYER_REFLECT         = 4
)

// WinDivert Parameters for WinDivertSetParam
const (
	WINDIVERT_PARAM_QUEUE_LENGTH = 0
	WINDIVERT_PARAM_QUEUE_TIME   = 1
	WINDIVERT_PARAM_QUEUE_SIZE   = 2
)

// WinDivert Flags
const (
	WINDIVERT_FLAG_SNIFF       = 0x0001
	WINDIVERT_FLAG_DROP        = 0x0002
	WINDIVERT_FLAG_RECV_ONLY   = 0x0004
	WINDIVERT_FLAG_READ_ONLY   = WINDIVERT_FLAG_RECV_ONLY
	WINDIVERT_FLAG_SEND_ONLY   = 0x0008
	WINDIVERT_FLAG_WRITE_ONLY  = WINDIVERT_FLAG_SEND_ONLY
	WINDIVERT_FLAG_NO_CHECKSUM = 0x0010
	WINDIVERT_FLAG_FRAGMENTS   = 0x0020
)

// WinDivert Helper Flags
const (
	WINDIVERT_HELPER_NO_IP_CHECKSUM     = 0x0001
	WINDIVERT_HELPER_NO_ICMP_CHECKSUM   = 0x0002
	WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM = 0x0004
	WINDIVERT_HELPER_NO_TCP_CHECKSUM    = 0x0008
	WINDIVERT_HELPER_NO_UDP_CHECKSUM    = 0x0010
)

// WinDivertAddress matches WINDIVERT_ADDRESS in WinDivert 2.2.
// Size: 80 bytes.
type WinDivertAddress struct {
	Timestamp int64
	Layer     uint8
	Event     uint8
	Flags     uint16
	Reserved1 uint32

	// Union data (Network / Flow / Socket / Reflect / 64 bytes buffer)
	IfIdx    uint32
	SubIfIdx uint32
	Data     [56]byte
}

// Flags bitmask in WinDivertAddress.Flags
const (
	WINDIVERT_ADDRESS_FLAG_SNIFFED      = 1 << 0
	WINDIVERT_ADDRESS_FLAG_OUTBOUND     = 1 << 1
	WINDIVERT_ADDRESS_FLAG_LOOPBACK     = 1 << 2
	WINDIVERT_ADDRESS_FLAG_IMPOSTOR     = 1 << 3
	WINDIVERT_ADDRESS_FLAG_IPV6         = 1 << 4
	WINDIVERT_ADDRESS_FLAG_IP_CHECKSUM  = 1 << 5
	WINDIVERT_ADDRESS_FLAG_TCP_CHECKSUM = 1 << 6
	WINDIVERT_ADDRESS_FLAG_UDP_CHECKSUM = 1 << 7
)

// IsOutbound returns true if the packet was outbound.
func (addr *WinDivertAddress) IsOutbound() bool {
	return (addr.Flags & WINDIVERT_ADDRESS_FLAG_OUTBOUND) != 0
}

// IsLoopback returns true if the packet is loopback.
func (addr *WinDivertAddress) IsLoopback() bool {
	return (addr.Flags & WINDIVERT_ADDRESS_FLAG_LOOPBACK) != 0
}

// IsIPv6 returns true if the packet is IPv6.
func (addr *WinDivertAddress) IsIPv6() bool {
	return (addr.Flags & WINDIVERT_ADDRESS_FLAG_IPV6) != 0
}

// SetOutbound sets the outbound flag.
func (addr *WinDivertAddress) SetOutbound(outbound bool) {
	if outbound {
		addr.Flags |= WINDIVERT_ADDRESS_FLAG_OUTBOUND
	} else {
		addr.Flags &^= WINDIVERT_ADDRESS_FLAG_OUTBOUND
	}
}

// IP Header Protocol Numbers
const (
	IPPROTO_ICMP = 1
	IPPROTO_TCP  = 6
	IPPROTO_UDP  = 17
)

// TCP Flags
const (
	TCP_FIN = 1 << 0
	TCP_SYN = 1 << 1
	TCP_RST = 1 << 2
	TCP_PSH = 1 << 3
	TCP_ACK = 1 << 4
	TCP_URG = 1 << 5
	TCP_ECE = 1 << 6
	TCP_CWR = 1 << 7
)

// IPv4Header represents standard 20-byte minimum IPv4 Header.
type IPv4Header struct {
	VersionIHL uint8
	TOS        uint8
	Length     uint16
	ID         uint16
	FragOff    uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
}

// TCPHeader represents standard 20-byte minimum TCP Header.
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8 // in 32-bit words (5 = 20 bytes)
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
}

// ParseIPv4Header parses an IPv4 header from raw packet bytes.
func ParseIPv4Header(packet []byte) (*IPv4Header, int, error) {
	if len(packet) < 20 {
		return nil, 0, ErrPacketTooShort
	}
	ihl := int(packet[0]&0x0F) * 4
	if ihl < 20 || len(packet) < ihl {
		return nil, 0, ErrInvalidHeaderLength
	}

	hdr := &IPv4Header{
		VersionIHL: packet[0],
		TOS:        packet[1],
		Length:     binary.BigEndian.Uint16(packet[2:4]),
		ID:         binary.BigEndian.Uint16(packet[4:6]),
		FragOff:    binary.BigEndian.Uint16(packet[6:8]),
		TTL:        packet[8],
		Protocol:   packet[9],
		Checksum:   binary.BigEndian.Uint16(packet[10:12]),
		SrcIP:      append(net.IP(nil), packet[12:16]...),
		DstIP:      append(net.IP(nil), packet[16:20]...),
	}
	return hdr, ihl, nil
}

// ParseIPv4Fast parses an IPv4 header without any heap allocations.
func ParseIPv4Fast(packet []byte) (proto uint8, srcIP, dstIP [4]byte, ihl int, err error) {
	if len(packet) < 20 {
		return 0, srcIP, dstIP, 0, ErrPacketTooShort
	}
	ihl = int(packet[0]&0x0F) * 4
	if ihl < 20 || len(packet) < ihl {
		return 0, srcIP, dstIP, 0, ErrInvalidHeaderLength
	}
	proto = packet[9]
	copy(srcIP[:], packet[12:16])
	copy(dstIP[:], packet[16:20])
	return proto, srcIP, dstIP, ihl, nil
}

// ParseTCPFast parses a TCP header without any heap allocations.
func ParseTCPFast(packet []byte, offset int) (srcPort, dstPort uint16, flags uint8, dataOffset int, err error) {
	if len(packet) < offset+20 {
		return 0, 0, 0, 0, ErrPacketTooShort
	}
	tcpBytes := packet[offset:]
	dataOffset = int(tcpBytes[12]>>4) * 4
	if dataOffset < 20 || len(tcpBytes) < dataOffset {
		return 0, 0, 0, 0, ErrInvalidHeaderLength
	}
	srcPort = binary.BigEndian.Uint16(tcpBytes[0:2])
	dstPort = binary.BigEndian.Uint16(tcpBytes[2:4])
	flags = tcpBytes[13]
	return srcPort, dstPort, flags, dataOffset, nil
}

// ParseTCPHeader parses a TCP header starting at offset in raw packet bytes (legacy helper).
func ParseTCPHeader(packet []byte, offset int) (*TCPHeader, int, error) {
	srcPort, dstPort, flags, dataOffset, err := ParseTCPFast(packet, offset)
	if err != nil {
		return nil, 0, err
	}
	tcpBytes := packet[offset:]
	hdr := &TCPHeader{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     binary.BigEndian.Uint32(tcpBytes[4:8]),
		AckNum:     binary.BigEndian.Uint32(tcpBytes[8:12]),
		DataOffset: uint8(dataOffset / 4),
		Flags:      flags,
		Window:     binary.BigEndian.Uint16(tcpBytes[14:16]),
		Checksum:   binary.BigEndian.Uint16(tcpBytes[16:18]),
		Urgent:     binary.BigEndian.Uint16(tcpBytes[18:20]),
	}
	return hdr, dataOffset, nil
}


