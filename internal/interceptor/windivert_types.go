//go:build windows

package interceptor

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



