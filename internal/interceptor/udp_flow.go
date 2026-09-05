package interceptor

import (
	"fmt"
	"net"
	"sync"
)

// UDPFlowKey identifies a unidirectional UDP flow: Client (IP:Port) -> Target (IP:Port).
// Fixed-size struct designed for zero-allocation map lookups.
type UDPFlowKey struct {
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
	IsV6    bool
}

// MakeUDPFlowKeyIPv4 creates a zero-alloc flow key for IPv4.
func MakeUDPFlowKeyIPv4(srcIP, dstIP [4]byte, srcPort, dstPort uint16) UDPFlowKey {
	var k UDPFlowKey
	copy(k.SrcIP[:4], srcIP[:])
	copy(k.DstIP[:4], dstIP[:])
	k.SrcPort = srcPort
	k.DstPort = dstPort
	return k
}

// MakeUDPFlowKeyIPv6 creates a zero-alloc flow key for IPv6.
func MakeUDPFlowKeyIPv6(srcIP, dstIP [16]byte, srcPort, dstPort uint16) UDPFlowKey {
	var k UDPFlowKey
	copy(k.SrcIP[:], srcIP[:])
	copy(k.DstIP[:], dstIP[:])
	k.SrcPort = srcPort
	k.DstPort = dstPort
	k.IsV6 = true
	return k
}

// ClientString returns formatted client IP:Port.
func (k UDPFlowKey) ClientString() string {
	if k.IsV6 {
		return fmt.Sprintf("[%s]:%d", net.IP(k.SrcIP[:]).String(), k.SrcPort)
	}
	return fmt.Sprintf("%d.%d.%d.%d:%d", k.SrcIP[0], k.SrcIP[1], k.SrcIP[2], k.SrcIP[3], k.SrcPort)
}

// TargetString returns formatted target IP:Port.
func (k UDPFlowKey) TargetString() string {
	if k.IsV6 {
		return fmt.Sprintf("[%s]:%d", net.IP(k.DstIP[:]).String(), k.DstPort)
	}
	return fmt.Sprintf("%d.%d.%d.%d:%d", k.DstIP[0], k.DstIP[1], k.DstIP[2], k.DstIP[3], k.DstPort)
}

// UDPFlowTable tracks active UDP flows to deduplicate audit logging and maintain high packet forwarding performance.
type UDPFlowTable struct {
	flows sync.Map // map[UDPFlowKey]int64 (Unix timestamp in seconds of last seen)
	ttl   int64    // TTL in seconds (default: 60)
}

// NewUDPFlowTable creates a new flow table with given TTL in seconds.
func NewUDPFlowTable(ttlSec int64) *UDPFlowTable {
	if ttlSec <= 0 {
		ttlSec = 60
	}
	return &UDPFlowTable{
		ttl: ttlSec,
	}
}

// CheckAndRecord checks if the flow is known within TTL.
// Returns isNewFlow = true if this is the first packet for the flow or if the previous session expired.
// When isNewFlow is true, the caller should output an audit log entry.
func (t *UDPFlowTable) CheckAndRecord(key UDPFlowKey, nowSec int64) bool {
	val, loaded := t.flows.Load(key)
	if !loaded {
		t.flows.Store(key, nowSec)
		return true
	}

	lastSeen, ok := val.(int64)
	if !ok || nowSec-lastSeen > t.ttl {
		// Session expired, treat as a new flow session
		t.flows.Store(key, nowSec)
		return true
	}

	// Periodically update timestamp to keep active sessions alive without per-packet atomic writes
	if nowSec-lastSeen >= 5 {
		t.flows.Store(key, nowSec)
	}
	return false
}

// Cleanup removes flow entries that have been inactive longer than TTL.
func (t *UDPFlowTable) Cleanup(nowSec int64) int {
	cleaned := 0
	t.flows.Range(func(k, v any) bool {
		lastSeen, ok := v.(int64)
		if !ok || nowSec-lastSeen > t.ttl {
			t.flows.Delete(k)
			cleaned++
		}
		return true
	})
	return cleaned
}

// Len returns the number of active flows in the table.
func (t *UDPFlowTable) Len() int {
	count := 0
	t.flows.Range(func(k, v any) bool {
		count++
		return true
	})
	return count
}
