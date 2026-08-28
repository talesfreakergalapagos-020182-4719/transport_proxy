package interceptor

import (
	"net"
	"testing"
)

func BenchmarkParseIPv4Fast(b *testing.B) {
	packet := make([]byte, 60)
	packet[0] = 0x45
	packet[9] = IPPROTO_TCP
	copy(packet[12:16], []byte{192, 168, 1, 50})
	copy(packet[16:20], []byte{93, 184, 216, 34})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _ = ParseIPv4Fast(packet)
	}
}

func BenchmarkParseTCPFast(b *testing.B) {
	packet := make([]byte, 40)
	packet[0] = 0x45
	packet[20] = 0x01 // SrcPort 256
	packet[22] = 0x01 // DstPort 256
	packet[32] = 0x50 // DataOffset 5 (20 bytes)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _ = ParseTCPFast(packet, 20)
	}
}

func BenchmarkSessionKeyLookup(b *testing.B) {
	r := &Redirector{}
	srcIP := [4]byte{192, 168, 1, 50}
	dstIP := net.ParseIP("93.184.216.34")
	key := MakeSessionKeyIPv4(srcIP, 54321)
	r.sessions.Store(key, &SessionInfo{
		OriginalDstIP:   dstIP,
		OriginalDstPort: 443,
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k := MakeSessionKeyIPv4(srcIP, 54321)
		_, _ = r.sessions.Load(k)
	}
}

func BenchmarkParseIPv6Fast(b *testing.B) {
	packet := make([]byte, 60)
	packet[0] = 0x60 // IPv6 version 6
	packet[6] = IPPROTO_TCP
	copy(packet[8:24], net.ParseIP("2001:db8::1"))
	copy(packet[24:40], net.ParseIP("2001:db8::2"))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _, _ = ParseIPv6Fast(packet)
	}
}

func BenchmarkParseIPv6Header(b *testing.B) {
	packet := make([]byte, 60)
	packet[0] = 0x60 // IPv6 version 6
	packet[6] = IPPROTO_TCP
	copy(packet[8:24], net.ParseIP("2001:db8::1"))
	copy(packet[24:40], net.ParseIP("2001:db8::2"))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ParseIPv6Header(packet)
	}
}

func BenchmarkExtractHTTPHost(b *testing.B) {
	httpReq := []byte("GET /index.html HTTP/1.1\r\nHost: api.github.com:443\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractHTTPHost(httpReq)
	}
}
