package interceptor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// Standard IP Protocol Numbers
const (
	IPPROTO_ICMP = 1
	IPPROTO_TCP  = 6
	IPPROTO_UDP  = 17
)

var (
	ErrPacketTooShort      = errors.New("packet is too short")
	ErrInvalidHeaderLength = errors.New("invalid header length")
)

// SessionKey uniquely identifies a client TCP session by source IP and port.
// Designed with zero-allocation in mind (fixed-size byte array value type).
type SessionKey struct {
	IP   [16]byte // Holds 4-byte IPv4 (in first 4 bytes) or 16-byte IPv6
	Port uint16
	IsV6 bool
}

// MakeSessionKeyIPv4 creates a zero-alloc SessionKey from raw 4-byte IPv4.
func MakeSessionKeyIPv4(ip [4]byte, port uint16) SessionKey {
	var k SessionKey
	copy(k.IP[:4], ip[:])
	k.Port = port
	return k
}

// MakeSessionKeyIPv6 creates a zero-alloc SessionKey from raw 16-byte IPv6.
func MakeSessionKeyIPv6(ip [16]byte, port uint16) SessionKey {
	var k SessionKey
	copy(k.IP[:], ip[:])
	k.Port = port
	k.IsV6 = true
	return k
}

// MakeSessionKeyFromNetIP creates a SessionKey from a standard net.IP.
func MakeSessionKeyFromNetIP(ip net.IP, port uint16) SessionKey {
	var k SessionKey
	if ip4 := ip.To4(); ip4 != nil {
		copy(k.IP[:4], ip4)
	} else {
		copy(k.IP[:], ip)
		k.IsV6 = true
	}
	k.Port = port
	return k
}

// DisplayString returns formatted IP:Port string for logging.
func (k SessionKey) DisplayString() string {
	if k.IsV6 {
		return fmt.Sprintf("[%s]:%d", net.IP(k.IP[:]).String(), k.Port)
	}
	return fmt.Sprintf("%d.%d.%d.%d:%d", k.IP[0], k.IP[1], k.IP[2], k.IP[3], k.Port)
}

// SessionInfo stores original destination information for redirected connections.
type SessionInfo struct {
	OriginalDstIP   net.IP
	OriginalDstPort uint16
	IfIdx           uint32 // Original physical network interface index
	SubIfIdx        uint32 // Original sub-interface index
	CreatedAt       time.Time
	LastSeen        atomic.Int64
}

// FilterEvaluator checks if a host or IP should be blocked.
type FilterEvaluator interface {
	ShouldBlock(hostOrIP string) bool
}

// RoutingEvaluator resolves upstream proxy routing decisions.
type RoutingEvaluator interface {
	ResolveRouting(targetHost string, targetPort uint16) (isDirect bool, proxyURL string, err error)
}

// DNSEvaluator processes intercepted UDP DNS query packets.
type DNSEvaluator interface {
	ProcessDNSQuery(ctx context.Context, clientAddr net.Addr, dstIP net.IP, payload []byte) (respData []byte, passthrough bool)
}

// Interceptor defines the common interface for packet interception and original destination resolution.
type Interceptor interface {
	Start(ctx context.Context) error
	Close() error
	LookupOriginalDestination(clientAddr net.Addr) (origIP net.IP, origPort uint16, found bool)
	LookupOriginalDestinationConn(conn net.Conn) (origIP net.IP, origPort uint16, found bool)
	DeleteSession(clientAddr net.Addr)
	SetDryRun(dryRun bool, forwardCond string, filterEng FilterEvaluator, routingEng RoutingEvaluator)
	SetDNSEngine(dnsEng DNSEvaluator)
	SetDNSServers(dnsServers []string)
}

// ConflictingPortInfo stores details about a non-tproxy process using a given port or port range.
type ConflictingPortInfo struct {
	LocalPort   uint16
	RemotePort  uint16
	LocalIP     net.IP
	RemoteIP    net.IP
	State       string
	PID         uint32
	ProcessName string
	ProcessPath string
}

// IsLoopback returns true if the socket is bound to a loopback address (127.0.0.1 or ::1).
func (c *ConflictingPortInfo) IsLoopback() bool {
	if c.LocalIP == nil {
		return false
	}
	return c.LocalIP.IsLoopback()
}
