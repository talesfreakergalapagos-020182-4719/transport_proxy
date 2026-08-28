package interceptor

import (
	"encoding/binary"
	"math/rand"
	"net"
	"testing"
	"time"
)

// fullIPv4Checksum calculates standard Internet checksum over IPv4 header.
func fullIPv4Checksum(hdr []byte) uint16 {
	ihl := int(hdr[0]&0x0F) * 4
	var sum uint32
	for i := 0; i < ihl; i += 2 {
		if i == 10 { // Skip checksum field itself
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// fullTCPChecksumIPv4 calculates full standard TCP checksum over IPv4 pseudo-header + TCP header + payload.
func fullTCPChecksumIPv4(packet []byte) uint16 {
	ihl := int(packet[0]&0x0F) * 4
	srcIP := packet[12:16]
	dstIP := packet[16:20]
	tcpLen := len(packet) - ihl

	var sum uint32
	// Pseudo-header: SrcIP
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	// Pseudo-header: DstIP
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	// Pseudo-header: Zero + Protocol (6)
	sum += uint32(IPPROTO_TCP)
	// Pseudo-header: TCP Length
	sum += uint32(tcpLen)

	// TCP Segment (header + payload)
	tcpData := packet[ihl:]
	for i := 0; i < len(tcpData)-1; i += 2 {
		if i == 16 { // Skip TCP checksum field
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(tcpData[i : i+2]))
	}
	if len(tcpData)%2 == 1 {
		sum += uint32(tcpData[len(tcpData)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// fullTCPChecksumIPv6 calculates full standard TCP checksum over IPv6 pseudo-header + TCP header + payload.
func fullTCPChecksumIPv6(packet []byte) uint16 {
	srcIP := packet[8:24]
	dstIP := packet[24:40]
	tcpLen := len(packet) - 40

	var sum uint32
	// Pseudo-header: SrcIP (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(srcIP[i : i+2]))
	}
	// Pseudo-header: DstIP (16 bytes)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(dstIP[i : i+2]))
	}
	// Pseudo-header: TCP Length (32-bit in IPv6 pseudo header)
	sum += uint32(tcpLen)
	// Pseudo-header: Next Header (TCP = 6)
	sum += uint32(IPPROTO_TCP)

	// TCP Segment
	tcpData := packet[40:]
	for i := 0; i < len(tcpData)-1; i += 2 {
		if i == 16 { // Skip TCP checksum field
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(tcpData[i : i+2]))
	}
	if len(tcpData)%2 == 1 {
		sum += uint32(tcpData[len(tcpData)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// Helper to build a valid IPv4 + TCP packet
func makeTestIPv4TCPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	const ihl = 20
	const tcphl = 20
	totalLen := ihl + tcphl + len(payload)
	pkt := make([]byte, totalLen)

	// IPv4 Header
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = IPPROTO_TCP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	csumIP := fullIPv4Checksum(pkt[:ihl])
	binary.BigEndian.PutUint16(pkt[10:12], csumIP)

	// TCP Header
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	pkt[32] = 0x50 // Data offset = 5 (20 bytes)
	copy(pkt[40:], payload)

	csumTCP := fullTCPChecksumIPv4(pkt)
	binary.BigEndian.PutUint16(pkt[36:38], csumTCP)

	return pkt
}

// Helper to build a valid IPv6 + TCP packet
func makeTestIPv6TCPPacket(srcIP, dstIP [16]byte, srcPort, dstPort uint16, payload []byte) []byte {
	const ip6hl = 40
	const tcphl = 20
	totalLen := ip6hl + tcphl + len(payload)
	pkt := make([]byte, totalLen)

	// IPv6 Header
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(tcphl+len(payload)))
	pkt[6] = IPPROTO_TCP
	pkt[7] = 64
	copy(pkt[8:24], srcIP[:])
	copy(pkt[24:40], dstIP[:])

	// TCP Header
	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	pkt[52] = 0x50 // Data offset = 5 (20 bytes)
	copy(pkt[60:], payload)

	csumTCP := fullTCPChecksumIPv6(pkt)
	binary.BigEndian.PutUint16(pkt[56:58], csumTCP)

	return pkt
}

func TestRFC1624_IncrementalChecksum_IPv4(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for iter := 0; iter < 10000; iter++ {
		origSrc := [4]byte{byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
		origDst := [4]byte{byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
		origSrcPort := uint16(rng.Intn(65535) + 1)
		origDstPort := uint16(rng.Intn(65535) + 1)

		payloadLen := rng.Intn(500)
		payload := make([]byte, payloadLen)
		rng.Read(payload)

		pkt := makeTestIPv4TCPPacket(origSrc, origDst, origSrcPort, origDstPort, payload)

		// Generate new destination / source
		newDst := [4]byte{byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
		newDstPort := uint16(rng.Intn(65535) + 1)

		// Test Forward NAT rewrite (DstIP and DstPort changed)
		err := RewriteIPv4TCP(pkt, nil, net.IP(newDst[:]), 0, newDstPort)
		if err != nil {
			t.Fatalf("RewriteIPv4TCP failed: %v", err)
		}

		expectedIPCsum := fullIPv4Checksum(pkt[:20])
		actualIPCsum := binary.BigEndian.Uint16(pkt[10:12])
		if expectedIPCsum != actualIPCsum {
			t.Fatalf("IPv4 Csum mismatch on iter %d: expected 0x%04x, got 0x%04x", iter, expectedIPCsum, actualIPCsum)
		}

		expectedTCPCsum := fullTCPChecksumIPv4(pkt)
		actualTCPCsum := binary.BigEndian.Uint16(pkt[36:38])
		if expectedTCPCsum != actualTCPCsum {
			t.Fatalf("TCP Csum mismatch on Forward NAT iter %d: expected 0x%04x, got 0x%04x", iter, expectedTCPCsum, actualTCPCsum)
		}

		// Test Reverse NAT rewrite (SrcIP and SrcPort changed)
		newSrc := [4]byte{byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))}
		newSrcPort := uint16(rng.Intn(65535) + 1)
		err = RewriteIPv4TCP(pkt, net.IP(newSrc[:]), nil, newSrcPort, 0)
		if err != nil {
			t.Fatalf("RewriteIPv4TCP reverse failed: %v", err)
		}

		expectedIPCsum = fullIPv4Checksum(pkt[:20])
		actualIPCsum = binary.BigEndian.Uint16(pkt[10:12])
		if expectedIPCsum != actualIPCsum {
			t.Fatalf("IPv4 Csum mismatch reverse iter %d: expected 0x%04x, got 0x%04x", iter, expectedIPCsum, actualIPCsum)
		}

		expectedTCPCsum = fullTCPChecksumIPv4(pkt)
		actualTCPCsum = binary.BigEndian.Uint16(pkt[36:38])
		if expectedTCPCsum != actualTCPCsum {
			t.Fatalf("TCP Csum mismatch on Reverse NAT iter %d: expected 0x%04x, got 0x%04x", iter, expectedTCPCsum, actualTCPCsum)
		}
	}
}

func TestRFC1624_IncrementalChecksum_IPv6(t *testing.T) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for iter := 0; iter < 10000; iter++ {
		var origSrc, origDst [16]byte
		rng.Read(origSrc[:])
		rng.Read(origDst[:])
		origSrcPort := uint16(rng.Intn(65535) + 1)
		origDstPort := uint16(rng.Intn(65535) + 1)

		payloadLen := rng.Intn(500)
		payload := make([]byte, payloadLen)
		rng.Read(payload)

		pkt := makeTestIPv6TCPPacket(origSrc, origDst, origSrcPort, origDstPort, payload)

		var newDst [16]byte
		rng.Read(newDst[:])
		newDstPort := uint16(rng.Intn(65535) + 1)

		// Test Forward NAT rewrite
		err := RewriteIPv6TCP(pkt, nil, net.IP(newDst[:]), 0, newDstPort)
		if err != nil {
			t.Fatalf("RewriteIPv6TCP failed: %v", err)
		}

		expectedTCPCsum := fullTCPChecksumIPv6(pkt)
		actualTCPCsum := binary.BigEndian.Uint16(pkt[56:58])
		if expectedTCPCsum != actualTCPCsum {
			t.Fatalf("IPv6 TCP Csum mismatch Forward NAT iter %d: expected 0x%04x, got 0x%04x", iter, expectedTCPCsum, actualTCPCsum)
		}

		// Test Reverse NAT rewrite
		var newSrc [16]byte
		rng.Read(newSrc[:])
		newSrcPort := uint16(rng.Intn(65535) + 1)
		err = RewriteIPv6TCP(pkt, net.IP(newSrc[:]), nil, newSrcPort, 0)
		if err != nil {
			t.Fatalf("RewriteIPv6TCP reverse failed: %v", err)
		}

		expectedTCPCsum = fullTCPChecksumIPv6(pkt)
		actualTCPCsum = binary.BigEndian.Uint16(pkt[56:58])
		if expectedTCPCsum != actualTCPCsum {
			t.Fatalf("IPv6 TCP Csum mismatch Reverse NAT iter %d: expected 0x%04x, got 0x%04x", iter, expectedTCPCsum, actualTCPCsum)
		}
	}
}

func BenchmarkRewriteIPv4TCP(b *testing.B) {
	srcIP := [4]byte{192, 168, 1, 100}
	dstIP := [4]byte{93, 184, 216, 34}
	pkt := makeTestIPv4TCPPacket(srcIP, dstIP, 54321, 443, make([]byte, 1000))
	newDst := net.ParseIP("127.0.0.1")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RewriteIPv4TCP(pkt, nil, newDst, 0, 18080)
	}
}

func BenchmarkRewriteIPv6TCP(b *testing.B) {
	var srcIP, dstIP [16]byte
	copy(srcIP[:], net.ParseIP("2001:db8::1"))
	copy(dstIP[:], net.ParseIP("2001:db8::2"))
	pkt := makeTestIPv6TCPPacket(srcIP, dstIP, 54321, 443, make([]byte, 1000))
	newDst := net.ParseIP("::1")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RewriteIPv6TCP(pkt, nil, newDst, 0, 18080)
	}
}
