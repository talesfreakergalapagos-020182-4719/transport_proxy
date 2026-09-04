package interceptor

import (
	"encoding/binary"
	"net"
	"os"
	"strings"
	"testing"
)

func TestSessionKeyIPv4AndIPv6(t *testing.T) {
	// 1. IPv4 session key
	rawIP4 := [4]byte{192, 168, 1, 100}
	k4 := MakeSessionKeyIPv4(rawIP4, 54321)
	if k4.IsV6 {
		t.Errorf("Expected IsV6=false for IPv4 session key")
	}
	if k4.Port != 54321 {
		t.Errorf("Expected port 54321, got %d", k4.Port)
	}
	expectedStr4 := "192.168.1.100:54321"
	if k4.DisplayString() != expectedStr4 {
		t.Errorf("Expected DisplayString %q, got %q", expectedStr4, k4.DisplayString())
	}

	// From net.IP (IPv4)
	k4Net := MakeSessionKeyFromNetIP(net.ParseIP("192.168.1.100"), 54321)
	if k4Net != k4 {
		t.Errorf("MakeSessionKeyFromNetIP did not match MakeSessionKeyIPv4: %+v vs %+v", k4Net, k4)
	}

	// 2. IPv6 session key
	rawIP6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	k6 := MakeSessionKeyIPv6(rawIP6, 8080)
	if !k6.IsV6 {
		t.Errorf("Expected IsV6=true for IPv6 session key")
	}
	if k6.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", k6.Port)
	}
	expectedStr6 := "[2001:db8::1]:8080"
	if k6.DisplayString() != expectedStr6 {
		t.Errorf("Expected DisplayString %q, got %q", expectedStr6, k6.DisplayString())
	}

	// From net.IP (IPv6)
	k6Net := MakeSessionKeyFromNetIP(net.ParseIP("2001:db8::1"), 8080)
	if k6Net != k6 {
		t.Errorf("MakeSessionKeyFromNetIP did not match MakeSessionKeyIPv6: %+v vs %+v", k6Net, k6)
	}
}

func TestFallbackScanSNI_And_ValidHostname(t *testing.T) {
	// Test isValidHostname
	validHosts := []string{"example.com", "api.github.com", "sub-domain.test.org", "my.server.local"}
	for _, h := range validHosts {
		if !isValidHostname(h) {
			t.Errorf("Expected %q to be valid hostname", h)
		}
	}

	invalidHosts := []string{
		"",
		"ab",                      // too short (<3)
		"nodot",                    // no dot
		"invalid space.com",        // space
		"bad@domain.com",           // special char
		strings.Repeat("a", 254) + ".com", // too long (>253)
	}
	for _, h := range invalidHosts {
		if isValidHostname(h) {
			t.Errorf("Expected %q to be invalid hostname", h)
		}
	}

	// Test fallbackScanSNI with simulated TLS extension chunk
	// Construct a synthetic SNI extension:
	// Type 0x0000 (server_name)
	// ext_len = 2 (list_len) + 1 (name_type) + 2 (name_len) + 11 (len("example.com")) = 16
	target := "example.com"
	ext := make([]byte, 0, 32)
	ext = append(ext, 0x00, 0x00)                                   // type = server_name
	ext = binary.BigEndian.AppendUint16(ext, uint16(5+len(target))) // extLen
	ext = binary.BigEndian.AppendUint16(ext, uint16(3+len(target))) // listLen
	ext = append(ext, 0x00)                                         // nameType = host_name
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(target)))   // nameLen
	ext = append(ext, []byte(target)...)

	// Embed inside padding bytes
	packet := append([]byte{0x16, 0x03, 0x01, 0x00, 0x50}, ext...)
	packet = append(packet, 0xaa, 0xbb, 0xcc)

	gotSNI := fallbackScanSNI(packet)
	if gotSNI != target {
		t.Errorf("fallbackScanSNI failed: expected %q, got %q", target, gotSNI)
	}

	// Test malformed / invalid scenarios
	if res := fallbackScanSNI([]byte{0x00, 0x00, 0x00}); res != "" {
		t.Errorf("Expected empty SNI for short slice, got %q", res)
	}

	// Invalid nameType (not 0)
	extBadType := make([]byte, len(ext))
	copy(extBadType, ext)
	extBadType[6] = 0x01 // Bad name type
	if res := fallbackScanSNI(extBadType); res != "" {
		t.Errorf("Expected empty SNI for non-zero nameType, got %q", res)
	}
}

func TestIPv6TCPChecksum_And_Fragmentation(t *testing.T) {
	srcIP := net.ParseIP("2001:db8::1").To16()
	dstIP := net.ParseIP("2001:db8::2").To16()

	// 1. CalculateTCPChecksumIPv6
	tcpSegment := make([]byte, 20) // Minimal TCP header (no payload)
	binary.BigEndian.PutUint16(tcpSegment[0:2], 12345) // SrcPort
	binary.BigEndian.PutUint16(tcpSegment[2:4], 80)    // DstPort
	tcpSegment[12] = 0x50                              // DataOffset = 5 (20 bytes)

	csum := CalculateTCPChecksumIPv6(srcIP, dstIP, tcpSegment)
	if csum == 0 {
		t.Errorf("Expected non-zero TCP checksum for IPv6")
	}

	// Odd-length segment
	oddSegment := make([]byte, 21)
	copy(oddSegment, tcpSegment)
	csumOdd := CalculateTCPChecksumIPv6(srcIP, dstIP, oddSegment)
	if csumOdd == 0 {
		t.Errorf("Expected non-zero checksum for odd-length segment")
	}

	// 2. FragmentIPv6TCP
	// Build a valid IPv6 + TCP packet with payload
	const ip6HdrLen = 40
	const tcpHdrLen = 20
	payloadSize := 1000
	packet := make([]byte, ip6HdrLen+tcpHdrLen+payloadSize)

	packet[0] = 0x60 // IPv6 version
	packet[6] = IPPROTO_TCP
	binary.BigEndian.PutUint16(packet[4:6], uint16(tcpHdrLen+payloadSize))
	copy(packet[8:24], srcIP)
	copy(packet[24:40], dstIP)

	packet[40+12] = 0x50 // TCP header length = 20 bytes
	packet[40+13] = TCP_ACK | TCP_PSH

	for i := 0; i < payloadSize; i++ {
		packet[ip6HdrLen+tcpHdrLen+i] = byte(i % 256)
	}

	// Test short packets / non-IPv6 / small payload
	shortFrags := FragmentIPv6TCP(packet[:50], 500)
	if len(shortFrags) != 1 {
		t.Errorf("Expected 1 fragment for short packet, got %d", len(shortFrags))
	}

	noFrag := FragmentIPv6TCP(packet, 2000)
	if len(noFrag) != 1 {
		t.Errorf("Expected 1 fragment when packet <= MTU, got %d", len(noFrag))
	}

	// Split packet with MTU 400 (Headers=60, max payload per fragment = 340)
	mtu := 400
	frags := FragmentIPv6TCP(packet, mtu)
	if len(frags) != 3 { // 340 + 340 + 320 = 1000
		t.Fatalf("Expected 3 fragments for 1000 bytes with MTU 400, got %d", len(frags))
	}

	// Verify each fragment
	var reassembled []byte
	for idx, f := range frags {
		if len(f) > mtu {
			t.Errorf("Fragment %d exceeds MTU: %d > %d", idx, len(f), mtu)
		}
		// First fragments shouldn't have PSH flag
		if idx < len(frags)-1 {
			if f[ip6HdrLen+13]&TCP_PSH != 0 {
				t.Errorf("Non-last fragment %d unexpectedly has PSH flag set", idx)
			}
		} else {
			if f[ip6HdrLen+13]&TCP_PSH == 0 {
				t.Errorf("Last fragment should have PSH flag set")
			}
		}
		reassembled = append(reassembled, f[ip6HdrLen+tcpHdrLen:]...)
	}

	if len(reassembled) != payloadSize {
		t.Errorf("Reassembled payload size mismatch: expected %d, got %d", payloadSize, len(reassembled))
	}
}

func TestFindProcessUsingPort_LivePort(t *testing.T) {
	// Listen on an available loopback port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("Unable to bind test port: %v", err)
	}
	defer ln.Close()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("Failed to split host port: %v", err)
	}
	var port uint16
	for _, c := range portStr {
		port = port*10 + uint16(c-'0')
	}

	info, err := FindProcessUsingPort(port)
	if err != nil {
		t.Logf("FindProcessUsingPort returned error (may require specific platform table): %v", err)
		return
	}
	if info != nil {
		currentPID := uint32(os.Getpid())
		if info.PID != currentPID {
			t.Logf("Process using port %d: PID=%d, Name=%s (Current test PID=%d)", port, info.PID, info.ProcessName, currentPID)
		} else {
			if info.ProcessName == "" {
				t.Errorf("Expected non-empty ProcessName for current process")
			}
		}
	}
}
