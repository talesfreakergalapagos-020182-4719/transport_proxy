package interceptor

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"
)

func TestExtractHTTPHost(t *testing.T) {
	httpReq := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\n\r\n")
	host := ExtractHTTPHost(httpReq)
	if host != "example.com" {
		t.Fatalf("ExtractHTTPHost failed: expected 'example.com', got %q", host)
	}

	httpReqWithPort := []byte("GET /index.html HTTP/1.1\r\nHost: example.com:80\r\nUser-Agent: curl/7.68.0\r\n\r\n")
	hostPort := ExtractHTTPHost(httpReqWithPort)
	if hostPort != "example.com" {
		t.Fatalf("ExtractHTTPHost with port failed: expected 'example.com', got %q", hostPort)
	}

	httpReqAbs := []byte("GET http://test.org:8080/api/v1 HTTP/1.1\r\nHost: ignored.org\r\n\r\n")
	hostAbs := ExtractHTTPHost(httpReqAbs)
	if hostAbs != "test.org" {
		t.Fatalf("ExtractHTTPHost abs URL failed: expected 'test.org', got %q", hostAbs)
	}
}

func TestIsHTTPOrHTTPS(t *testing.T) {
	// 1. TLS HTTPS test
	tlsPacket := buildMockTLSClientHello("api.example.com")
	isWeb, proto, domain := IsHTTPOrHTTPS(tlsPacket)
	if !isWeb || proto != "HTTPS" || domain != "api.example.com" {
		t.Fatalf("Expected HTTPS/api.example.com, got isWeb=%v, proto=%s, domain=%s", isWeb, proto, domain)
	}

	// 2. HTTP test
	httpPacket := []byte("POST /v1/chat HTTP/1.1\r\nHost: llm.example.org:8443\r\n\r\n")
	isWeb, proto, domain = IsHTTPOrHTTPS(httpPacket)
	if !isWeb || proto != "HTTP" || domain != "llm.example.org" {
		t.Fatalf("Expected HTTP/llm.example.org, got isWeb=%v, proto=%s, domain=%s", isWeb, proto, domain)
	}

	// 3. Raw TCP / SSH banner test
	sshBanner := []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
	isWeb, proto, domain = IsHTTPOrHTTPS(sshBanner)
	if isWeb || proto != "RAW_TCP" || domain != "" {
		t.Fatalf("Expected RAW_TCP, got isWeb=%v, proto=%s, domain=%s", isWeb, proto, domain)
	}

	// 4. Empty payload test (Server-First protocol before client speaks)
	isWeb, proto, domain = IsHTTPOrHTTPS(nil)
	if isWeb || proto != "RAW_TCP" || domain != "" {
		t.Fatalf("Expected RAW_TCP on nil, got isWeb=%v, proto=%s, domain=%s", isWeb, proto, domain)
	}
}

func buildMockTLSClientHello(serverName string) []byte {
	var sniExt bytes.Buffer
	sniExt.WriteByte(0) // NameType host_name
	_ = binary.Write(&sniExt, binary.BigEndian, uint16(len(serverName)))
	sniExt.WriteString(serverName)

	var sniList bytes.Buffer
	_ = binary.Write(&sniList, binary.BigEndian, uint16(sniExt.Len()))
	sniList.Write(sniExt.Bytes())

	var extBlock bytes.Buffer
	_ = binary.Write(&extBlock, binary.BigEndian, uint16(0x0000)) // server_name ext type
	_ = binary.Write(&extBlock, binary.BigEndian, uint16(sniList.Len()))
	extBlock.Write(sniList.Bytes())

	var extensions bytes.Buffer
	_ = binary.Write(&extensions, binary.BigEndian, uint16(extBlock.Len()))
	extensions.Write(extBlock.Bytes())

	var ch bytes.Buffer
	_ = binary.Write(&ch, binary.BigEndian, uint16(0x0303)) // TLS 1.2
	ch.Write(make([]byte, 32))                              // Random
	ch.WriteByte(0)                                         // Session ID len 0
	_ = binary.Write(&ch, binary.BigEndian, uint16(2))      // Cipher suite len
	_ = binary.Write(&ch, binary.BigEndian, uint16(0x002f)) // Cipher suite
	ch.WriteByte(1)                                         // Comp len
	ch.WriteByte(0)                                         // Comp null
	ch.Write(extensions.Bytes())

	var handshake bytes.Buffer
	handshake.WriteByte(1) // ClientHello
	hLen := ch.Len()
	handshake.WriteByte(byte(hLen >> 16))
	handshake.WriteByte(byte(hLen >> 8))
	handshake.WriteByte(byte(hLen))
	handshake.Write(ch.Bytes())

	var record bytes.Buffer
	record.WriteByte(0x16) // Handshake
	_ = binary.Write(&record, binary.BigEndian, uint16(0x0301))
	_ = binary.Write(&record, binary.BigEndian, uint16(handshake.Len()))
	record.Write(handshake.Bytes())

	return record.Bytes()
}

func TestExtractTLS_SNI(t *testing.T) {
	expectedDomain := "secure.bank.example.com"
	packet := buildMockTLSClientHello(expectedDomain)

	got := ExtractTLS_SNI(packet)
	if got != expectedDomain {
		t.Fatalf("ExtractTLS_SNI failed: expected %q, got %q", expectedDomain, got)
	}
}

func TestRewriteIPv4TCP(t *testing.T) {
	// 20 bytes IP + 20 bytes TCP
	packet := make([]byte, 40)
	packet[0] = 0x45 // IPv4, IHL = 5
	packet[9] = 6    // TCP
	packet[12+0] = 10
	packet[12+1] = 0
	packet[12+2] = 0
	packet[12+3] = 1 // Src: 10.0.0.1
	packet[16+0] = 93
	packet[16+1] = 184
	packet[16+2] = 216
	packet[16+3] = 34                                // Dst: 93.184.216.34
	binary.BigEndian.PutUint16(packet[20:22], 54321) // SrcPort
	binary.BigEndian.PutUint16(packet[22:24], 443)   // DstPort
	packet[32] = 0x50                                // DataOffset 5

	newDstIP := net.ParseIP("127.0.0.1")
	newDstPort := uint16(18080)

	err := RewriteIPv4TCP(packet, nil, newDstIP, 0, newDstPort)
	if err != nil {
		t.Fatalf("RewriteIPv4TCP failed: %v", err)
	}

	ipHdr, ihl, err := ParseIPv4Header(packet)
	if err != nil || ihl != 20 {
		t.Fatalf("ParseIPv4Header failed: %v", err)
	}
	if ipHdr.DstIP.String() != "127.0.0.1" {
		t.Fatalf("Expected DstIP 127.0.0.1, got %v", ipHdr.DstIP)
	}

	tcpHdr, _, err := ParseTCPHeader(packet, 20)
	if err != nil {
		t.Fatalf("ParseTCPHeader failed: %v", err)
	}
	if tcpHdr.DstPort != 18080 {
		t.Fatalf("Expected DstPort 18080, got %d", tcpHdr.DstPort)
	}
}

func TestSessionInfo_LastSeen(t *testing.T) {
	info := &SessionInfo{
		OriginalDstIP:   net.ParseIP("93.184.216.34"),
		OriginalDstPort: 443,
	}
	info.LastSeen.Store(123456)

	if info.LastSeen.Load() != 123456 {
		t.Fatalf("Expected LastSeen 123456, got %d", info.LastSeen.Load())
	}
}

type mockFilter struct {
	allowedDomain string
}

func (m *mockFilter) ShouldBlock(hostOrIP string) bool {
	return hostOrIP != m.allowedDomain
}

func TestDryRun_Simulation(t *testing.T) {
	// 1. Build TLS packet for allowed domain
	allowedDomain := "github.com"
	packetAllowed := buildMockTLSClientHello(allowedDomain)
	extractedAllowed := ExtractTLS_SNI(packetAllowed)
	if extractedAllowed != allowedDomain {
		t.Fatalf("Expected %s, got %s", allowedDomain, extractedAllowed)
	}

	mf := &mockFilter{allowedDomain: allowedDomain}
	if mf.ShouldBlock(extractedAllowed) {
		t.Fatalf("Expected github.com to be ALLOWED in dry-run simulation")
	}

	// 2. Build TLS packet for blocked domain
	blockedDomain := "rocketnews24.com"
	packetBlocked := buildMockTLSClientHello(blockedDomain)
	extractedBlocked := ExtractTLS_SNI(packetBlocked)
	if extractedBlocked != blockedDomain {
		t.Fatalf("Expected %s, got %s", blockedDomain, extractedBlocked)
	}

	if !mf.ShouldBlock(extractedBlocked) {
		t.Fatalf("Expected rocketnews24.com to be BLOCKED in dry-run simulation")
	}
}

func TestFragmentIPv4_EdgeCases(t *testing.T) {
	// 1. Packet smaller than MTU
	packet := make([]byte, 100)
	packet[0] = 0x45 // IPv4, IHL=5 (20 bytes)
	frags := FragmentIPv4(packet, 1500)
	if len(frags) != 1 || len(frags[0]) != 100 {
		t.Fatalf("Expected 1 fragment of len 100, got %d", len(frags))
	}

	// 2. MTU too small (<= IP header len) -> should not panic or loop infinitely
	fragsSmallMTU := FragmentIPv4(packet, 10)
	if len(fragsSmallMTU) != 1 {
		t.Fatalf("Expected 1 fragment for tiny MTU fallback, got %d", len(fragsSmallMTU))
	}

	// 3. Valid fragmentation
	largePacket := make([]byte, 3000)
	largePacket[0] = 0x45
	fragsLarge := FragmentIPv4(largePacket, 1500)
	if len(fragsLarge) < 2 {
		t.Fatalf("Expected multiple fragments, got %d", len(fragsLarge))
	}
}

func TestExtractHTTPHost_ConnectMethod(t *testing.T) {
	// Standard CONNECT
	connectReq := []byte("CONNECT secure.corp.net:443 HTTP/1.1\r\nUser-Agent: curl\r\n\r\n")
	host := ExtractHTTPHost(connectReq)
	if host != "secure.corp.net" {
		t.Fatalf("Expected 'secure.corp.net', got %q", host)
	}

	// CONNECT with Host header
	connectReqWithHost := []byte("CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: example.org\r\n\r\n")
	hostWithHeader := ExtractHTTPHost(connectReqWithHost)
	if hostWithHeader != "example.org" {
		t.Fatalf("Expected 'example.org', got %q", hostWithHeader)
	}
}

func TestSession_PortReuseAndUpdate(t *testing.T) {
	var sessions syncMapHelper
	clientKey := MakeSessionKeyFromNetIP(net.ParseIP("192.168.1.50"), 54321)

	// Initial connection to Host A
	infoA := &SessionInfo{
		OriginalDstIP:   net.ParseIP("93.184.216.34"),
		OriginalDstPort: 443,
	}
	sessions.Store(clientKey, infoA)

	// Simulate client reconnecting from same port to Host B with SYN flag
	newDstIP := net.ParseIP("142.250.190.46")
	newDstPort := uint16(443)
	isSYN := true

	val, exists := sessions.Load(clientKey)
	if !exists {
		t.Fatalf("Expected session to exist")
	}

	existing := val.(*SessionInfo)
	if isSYN || !existing.OriginalDstIP.Equal(newDstIP) || existing.OriginalDstPort != newDstPort {
		infoB := &SessionInfo{
			OriginalDstIP:   newDstIP,
			OriginalDstPort: newDstPort,
		}
		sessions.Store(clientKey, infoB)
	}

	// Verify session now points to Host B
	updatedVal, _ := sessions.Load(clientKey)
	updatedInfo := updatedVal.(*SessionInfo)
	if !updatedInfo.OriginalDstIP.Equal(newDstIP) {
		t.Fatalf("Expected updated DstIP %v, got %v", newDstIP, updatedInfo.OriginalDstIP)
	}
}

type syncMapHelper struct {
	m sync.Map
}

func (s *syncMapHelper) Store(k SessionKey, v *SessionInfo) {
	s.m.Store(k, v)
}

func (s *syncMapHelper) Load(k SessionKey) (any, bool) {
	return s.m.Load(k)
}

func TestParseIPv6Header(t *testing.T) {
	// Build a valid 40-byte IPv6 header (TCP next header = 6)
	pkt := make([]byte, 60)
	pkt[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(pkt[4:6], 20) // Payload len = 20 (TCP header)
	pkt[6] = 6 // NextHeader = TCP
	pkt[7] = 64 // HopLimit

	srcIP := net.ParseIP("2001:db8::1").To16()
	dstIP := net.ParseIP("2001:db8::2").To16()
	copy(pkt[8:24], srcIP)
	copy(pkt[24:40], dstIP)

	hdr, ihl, err := ParseIPv6Header(pkt)
	if err != nil {
		t.Fatalf("ParseIPv6Header failed: %v", err)
	}
	if ihl != 40 {
		t.Fatalf("Expected IHL 40, got %d", ihl)
	}
	if hdr.Version != 6 {
		t.Fatalf("Expected version 6, got %d", hdr.Version)
	}
	if hdr.NextHeader != 6 {
		t.Fatalf("Expected NextHeader 6, got %d", hdr.NextHeader)
	}
	if !hdr.SrcIP.Equal(srcIP) {
		t.Fatalf("Expected SrcIP %v, got %v", srcIP, hdr.SrcIP)
	}
	if !hdr.DstIP.Equal(dstIP) {
		t.Fatalf("Expected DstIP %v, got %v", dstIP, hdr.DstIP)
	}

	// Test short packet error
	_, _, errShort := ParseIPv6Header(pkt[:30])
	if errShort == nil {
		t.Fatalf("Expected error on short packet, got nil")
	}

	// Test wrong version error
	pktWrongVer := make([]byte, 40)
	pktWrongVer[0] = 0x40 // IPv4
	_, _, errVer := ParseIPv6Header(pktWrongVer)
	if errVer == nil {
		t.Fatalf("Expected error on IPv4 version byte, got nil")
	}
}

func TestRewriteIPv6TCP(t *testing.T) {
	// Build a 60-byte IPv6 + TCP packet
	pkt := make([]byte, 60)
	pkt[0] = 0x60 // IPv6
	pkt[6] = 6    // TCP

	origSrcIP := net.ParseIP("fe80::1").To16()
	origDstIP := net.ParseIP("2001:4860:4860::8888").To16()
	copy(pkt[8:24], origSrcIP)
	copy(pkt[24:40], origDstIP)

	binary.BigEndian.PutUint16(pkt[40:42], 50000) // SrcPort
	binary.BigEndian.PutUint16(pkt[42:44], 443)   // DstPort

	// Forward NAT rewrite: DstIP to ::1, DstPort to 18080
	newDstIP := net.ParseIP("::1").To16()
	var newDstPort uint16 = 18080

	err := RewriteIPv6TCP(pkt, nil, newDstIP, 0, newDstPort)
	if err != nil {
		t.Fatalf("RewriteIPv6TCP failed: %v", err)
	}

	// Verify rewritten DstIP and DstPort
	rewrittenDstIP := net.IP(pkt[24:40])
	if !rewrittenDstIP.Equal(newDstIP) {
		t.Fatalf("Expected DstIP %v, got %v", newDstIP, rewrittenDstIP)
	}
	rewrittenDstPort := binary.BigEndian.Uint16(pkt[42:44])
	if rewrittenDstPort != 18080 {
		t.Fatalf("Expected DstPort 18080, got %d", rewrittenDstPort)
	}
	// SrcIP & SrcPort should remain untouched
	rewrittenSrcIP := net.IP(pkt[8:24])
	if !rewrittenSrcIP.Equal(origSrcIP) {
		t.Fatalf("Expected SrcIP unchanged (%v), got %v", origSrcIP, rewrittenSrcIP)
	}
	rewrittenSrcPort := binary.BigEndian.Uint16(pkt[40:42])
	if rewrittenSrcPort != 50000 {
		t.Fatalf("Expected SrcPort unchanged (50000), got %d", rewrittenSrcPort)
	}

	// Reverse NAT rewrite: SrcIP back to 2001:4860:4860::8888, SrcPort back to 443
	err = RewriteIPv6TCP(pkt, origDstIP, nil, 443, 0)
	if err != nil {
		t.Fatalf("RewriteIPv6TCP Reverse NAT failed: %v", err)
	}
	finalSrcIP := net.IP(pkt[8:24])
	if !finalSrcIP.Equal(origDstIP) {
		t.Fatalf("Expected SrcIP restored to %v, got %v", origDstIP, finalSrcIP)
	}
	finalSrcPort := binary.BigEndian.Uint16(pkt[40:42])
	if finalSrcPort != 443 {
		t.Fatalf("Expected SrcPort restored to 443, got %d", finalSrcPort)
	}
}

func TestRewriteIPv6TCP_EdgeCases(t *testing.T) {
	// 1. Packet too short
	shortPkt := make([]byte, 50)
	err := RewriteIPv6TCP(shortPkt, nil, net.ParseIP("::1"), 0, 80)
	if err == nil {
		t.Fatalf("Expected error for packet length < 60, got nil")
	}

	// 2. Wrong version
	v4Pkt := make([]byte, 60)
	v4Pkt[0] = 0x45
	err = RewriteIPv6TCP(v4Pkt, nil, net.ParseIP("::1"), 0, 80)
	if err == nil {
		t.Fatalf("Expected error for non-IPv6 packet, got nil")
	}

	// 3. Modifying only ports without modifying IPs
	validPkt := make([]byte, 60)
	validPkt[0] = 0x60
	err = RewriteIPv6TCP(validPkt, nil, nil, 12345, 54321)
	if err != nil {
		t.Fatalf("RewriteIPv6TCP port-only failed: %v", err)
	}
	if binary.BigEndian.Uint16(validPkt[40:42]) != 12345 {
		t.Fatalf("Expected SrcPort 12345, got %d", binary.BigEndian.Uint16(validPkt[40:42]))
	}
	if binary.BigEndian.Uint16(validPkt[42:44]) != 54321 {
		t.Fatalf("Expected DstPort 54321, got %d", binary.BigEndian.Uint16(validPkt[42:44]))
	}
}

func TestUDPParserAndBuilder(t *testing.T) {
	srcIPv4 := net.ParseIP("192.168.1.100")
	dstIPv4 := net.ParseIP("1.1.1.2")
	payload := []byte("hello dns")

	// 1. IPv4 UDP Packet Build & Parse
	pkt4 := BuildIPv4UDPPacket(srcIPv4, dstIPv4, 54321, 53, payload)
	if pkt4 == nil {
		t.Fatalf("BuildIPv4UDPPacket returned nil")
	}

	proto, sIP, dIP, ihl, err := ParseIPv4Fast(pkt4)
	if err != nil || proto != IPPROTO_UDP {
		t.Fatalf("ParseIPv4Fast failed: proto=%d, err=%v", proto, err)
	}
	if !net.IPv4(sIP[0], sIP[1], sIP[2], sIP[3]).Equal(srcIPv4) {
		t.Errorf("Expected SrcIP %v, got %v", srcIPv4, sIP)
	}
	if !net.IPv4(dIP[0], dIP[1], dIP[2], dIP[3]).Equal(dstIPv4) {
		t.Errorf("Expected DstIP %v, got %v", dstIPv4, dIP)
	}

	srcPort, dstPort, udpLen, dataOffset, err := ParseUDPFast(pkt4, ihl)
	if err != nil {
		t.Fatalf("ParseUDPFast failed: %v", err)
	}
	if srcPort != 54321 || dstPort != 53 {
		t.Errorf("Expected ports 54321->53, got %d->%d", srcPort, dstPort)
	}
	if int(udpLen) != 8+len(payload) {
		t.Errorf("Expected udpLen %d, got %d", 8+len(payload), udpLen)
	}
	if !bytes.Equal(pkt4[dataOffset:], payload) {
		t.Errorf("Payload mismatch: expected %q, got %q", payload, pkt4[dataOffset:])
	}

	// 2. IPv6 UDP Packet Build & Parse
	srcIPv6 := net.ParseIP("240d:1a:4df:c000::10")
	dstIPv6 := net.ParseIP("2606:4700:4700::1112")
	pkt6 := BuildIPv6UDPPacket(srcIPv6, dstIPv6, 60000, 53, payload)
	if pkt6 == nil {
		t.Fatalf("BuildIPv6UDPPacket returned nil")
	}

	ip6Hdr, ihl6, err := ParseIPv6Header(pkt6)
	if err != nil || ip6Hdr.NextHeader != IPPROTO_UDP {
		t.Fatalf("ParseIPv6Header failed: nextHdr=%d, err=%v", ip6Hdr.NextHeader, err)
	}
	if !ip6Hdr.SrcIP.Equal(srcIPv6) || !ip6Hdr.DstIP.Equal(dstIPv6) {
		t.Errorf("IPv6 Addr mismatch: src=%v, dst=%v", ip6Hdr.SrcIP, ip6Hdr.DstIP)
	}

	srcPort6, dstPort6, udpLen6, dataOffset6, err := ParseUDPFast(pkt6, ihl6)
	if err != nil {
		t.Fatalf("ParseUDPFast (v6) failed: %v", err)
	}
	if srcPort6 != 60000 || dstPort6 != 53 {
		t.Errorf("Expected IPv6 ports 60000->53, got %d->%d", srcPort6, dstPort6)
	}
	if int(udpLen6) != 8+len(payload) {
		t.Errorf("Expected IPv6 udpLen %d, got %d", 8+len(payload), udpLen6)
	}
	if !bytes.Equal(pkt6[dataOffset6:], payload) {
		t.Errorf("IPv6 Payload mismatch: expected %q, got %q", payload, pkt6[dataOffset6:])
	}
}

