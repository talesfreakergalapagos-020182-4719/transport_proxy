package interceptor

import (
	"testing"
)

func TestUDPFlowKey_Format(t *testing.T) {
	k4 := MakeUDPFlowKeyIPv4([4]byte{192, 168, 1, 100}, [4]byte{8, 8, 8, 8}, 12345, 53)
	if k4.ClientString() != "192.168.1.100:12345" {
		t.Errorf("Unexpected IPv4 ClientString: %s", k4.ClientString())
	}
	if k4.TargetString() != "8.8.8.8:53" {
		t.Errorf("Unexpected IPv4 TargetString: %s", k4.TargetString())
	}

	srcV6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dstV6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	k6 := MakeUDPFlowKeyIPv6(srcV6, dstV6, 54321, 123)
	if k6.ClientString() != "[2001:db8::1]:54321" {
		t.Errorf("Unexpected IPv6 ClientString: %s", k6.ClientString())
	}
	if k6.TargetString() != "[2001:db8::2]:123" {
		t.Errorf("Unexpected IPv6 TargetString: %s", k6.TargetString())
	}
}

func TestUDPFlowTable_CheckAndRecord(t *testing.T) {
	table := NewUDPFlowTable(30)
	key := MakeUDPFlowKeyIPv4([4]byte{10, 0, 0, 1}, [4]byte{1, 1, 1, 1}, 50000, 123)

	now := int64(1000)

	// First packet: must be considered new flow
	if !table.CheckAndRecord(key, now) {
		t.Errorf("Expected first packet to be new flow")
	}

	// Immediate second packet: must NOT be considered new flow (deduplication)
	if table.CheckAndRecord(key, now) {
		t.Errorf("Expected subsequent packet within TTL to be deduplicated")
	}

	// Packet after 10 seconds (still within 30s TTL): must NOT be considered new flow
	if table.CheckAndRecord(key, now+10) {
		t.Errorf("Expected packet at now+10 to be deduplicated")
	}

	// Packet after 45 seconds (35s after last keepalive at now+10, exceeds 30s TTL): must be considered new flow
	if !table.CheckAndRecord(key, now+45) {
		t.Errorf("Expected packet after TTL expiry to be new flow")
	}
}

func TestUDPFlowTable_Cleanup(t *testing.T) {
	table := NewUDPFlowTable(30)
	k1 := MakeUDPFlowKeyIPv4([4]byte{10, 0, 0, 1}, [4]byte{1, 1, 1, 1}, 50000, 123)
	k2 := MakeUDPFlowKeyIPv4([4]byte{10, 0, 0, 2}, [4]byte{1, 1, 1, 1}, 50001, 123)

	now := int64(1000)
	table.CheckAndRecord(k1, now)
	table.CheckAndRecord(k2, now+20)

	if table.Len() != 2 {
		t.Errorf("Expected 2 flows, got %d", table.Len())
	}

	// Cleanup at now+25: neither flow should be cleaned (k1 age 25 <= 30, k2 age 5 <= 30)
	cleaned := table.Cleanup(now + 25)
	if cleaned != 0 || table.Len() != 2 {
		t.Errorf("Expected 0 cleaned, got %d (len: %d)", cleaned, table.Len())
	}

	// Cleanup at now+35: k1 expired (age 35 > 30), k2 still valid (age 15 <= 30)
	cleaned = table.Cleanup(now + 35)
	if cleaned != 1 || table.Len() != 1 {
		t.Errorf("Expected 1 cleaned, got %d (len: %d)", cleaned, table.Len())
	}

	// Cleanup at now+60: k2 expired as well
	cleaned = table.Cleanup(now + 60)
	if cleaned != 1 || table.Len() != 0 {
		t.Errorf("Expected 1 cleaned, got %d (len: %d)", cleaned, table.Len())
	}
}
