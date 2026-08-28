package interceptor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// IPv6Header holds parsed fields from an IPv6 packet header.
type IPv6Header struct {
	Version    uint8
	PayloadLen uint16
	NextHeader uint8 // 6 = TCP, 17 = UDP
	HopLimit   uint8
	SrcIP      net.IP
	DstIP      net.IP
}

// ParseIPv6Header parses a fixed 40-byte IPv6 header.
func ParseIPv6Header(data []byte) (*IPv6Header, int, error) {
	if len(data) < 40 {
		return nil, 0, fmt.Errorf("packet too short for IPv6 header: %d bytes", len(data))
	}
	version := data[0] >> 4
	if version != 6 {
		return nil, 0, fmt.Errorf("not an IPv6 packet: version %d", version)
	}

	hdr := &IPv6Header{
		Version:    version,
		PayloadLen: binary.BigEndian.Uint16(data[4:6]),
		NextHeader: data[6],
		HopLimit:   data[7],
		SrcIP:      append(net.IP(nil), data[8:24]...),
		DstIP:      append(net.IP(nil), data[24:40]...),
	}
	return hdr, 40, nil
}

// IsHTTPOrHTTPS inspects initial payload bytes to determine if the traffic is HTTP or HTTPS (TLS).
// Returns isWeb=true if detected as HTTP or HTTPS, the protocol label ("HTTPS", "HTTP", or "RAW_TCP"), and extracted domain.
func IsHTTPOrHTTPS(data []byte) (isWeb bool, protoType string, targetDomain string) {
	if len(data) == 0 {
		return false, "RAW_TCP", ""
	}

	// 1. Check TLS Handshake ClientHello (0x16 0x03)
	if len(data) >= 5 && data[0] == 0x16 && data[1] == 0x03 {
		sni := ExtractTLS_SNI(data)
		return true, "HTTPS", sni
	}

	// 2. Check HTTP Request Methods
	if bytes.HasPrefix(data, []byte("GET ")) ||
		bytes.HasPrefix(data, []byte("POST ")) ||
		bytes.HasPrefix(data, []byte("HEAD ")) ||
		bytes.HasPrefix(data, []byte("PUT ")) ||
		bytes.HasPrefix(data, []byte("DELETE ")) ||
		bytes.HasPrefix(data, []byte("CONNECT ")) ||
		bytes.HasPrefix(data, []byte("OPTIONS ")) ||
		bytes.HasPrefix(data, []byte("PATCH ")) ||
		bytes.HasPrefix(data, []byte("TRACE ")) {
		host := ExtractHTTPHost(data)
		return true, "HTTP", host
	}

	return false, "RAW_TCP", ""
}

// ExtractTLS_SNI parses a TLS ClientHello packet and extracts the Server Name Indication (SNI) hostname.
// If the payload is not a TLS ClientHello or has no SNI, it returns an empty string without error.
func ExtractTLS_SNI(data []byte) string {
	// Need at least 5 bytes TLS record header + 4 bytes Handshake header
	if len(data) < 9 {
		return ""
	}

	// TLS Record Layer: 0x16 = Handshake
	if data[0] != 0x16 {
		return ""
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		// Incomplete record or truncated
		recordLen = len(data) - 5
	}

	payload := data[5 : 5+recordLen]
	if len(payload) < 4 {
		return ""
	}

	// Handshake type: 0x01 = ClientHello
	if payload[0] != 0x01 {
		return ""
	}

	handshakeLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+handshakeLen {
		handshakeLen = len(payload) - 4
	}

	ch := payload[4 : 4+handshakeLen]
	// ClientHello minimum length:
	// Version(2) + Random(32) + SessionIDLen(1) = 35 bytes
	if len(ch) < 35 {
		return ""
	}

	pos := 34
	sessionIDLen := int(ch[pos])
	pos += 1 + sessionIDLen
	if len(ch) < pos+2 {
		return ""
	}

	// Cipher suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(ch[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if len(ch) < pos+1 {
		return ""
	}

	// Compression methods
	compressionLen := int(ch[pos])
	pos += 1 + compressionLen
	if len(ch) < pos+2 {
		return ""
	}

	// Extensions length
	extensionsLen := int(binary.BigEndian.Uint16(ch[pos : pos+2]))
	pos += 2
	if len(ch) < pos+extensionsLen {
		extensionsLen = len(ch) - pos
	}

	extensions := ch[pos : pos+extensionsLen]
	extPos := 0
	for extPos+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[extPos : extPos+2])
		extLen := int(binary.BigEndian.Uint16(extensions[extPos+2 : extPos+4]))
		extPos += 4

		if extPos+extLen > len(extensions) {
			break
		}

		// Extension 0x0000 = server_name (SNI)
		if extType == 0 {
			sniData := extensions[extPos : extPos+extLen]
			if len(sniData) < 2 {
				break
			}
			listLen := int(binary.BigEndian.Uint16(sniData[0:2]))
			sniPos := 2
			if len(sniData) < sniPos+listLen {
				listLen = len(sniData) - sniPos
			}

			for sniPos+3 <= 2+listLen {
				nameType := sniData[sniPos]
				nameLen := int(binary.BigEndian.Uint16(sniData[sniPos+1 : sniPos+3]))
				sniPos += 3
				if sniPos+nameLen > len(sniData) {
					break
				}
				// NameType 0 = host_name
				if nameType == 0 {
					return string(sniData[sniPos : sniPos+nameLen])
				}
				sniPos += nameLen
			}
		}

		extPos += extLen
	}

	// Fallback to pattern scanning if offset-based parsing missed SNI due to TLS fragmentation or novel extensions
	return fallbackScanSNI(data)
}

// fallbackScanSNI scans bytes for the TLS server_name (SNI) structure pattern.
func fallbackScanSNI(data []byte) string {
	for i := 0; i+9 <= len(data); i++ {
		if data[i] == 0x00 && data[i+1] == 0x00 { // ext_type == 0 (server_name)
			extLen := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
			if extLen < 5 || extLen > 512 || i+4+extLen > len(data) {
				continue
			}
			listLen := int(binary.BigEndian.Uint16(data[i+4 : i+6]))
			if listLen+2 > extLen || i+6+listLen > len(data) {
				continue
			}
			nameType := data[i+6]
			if nameType != 0 { // 0 = host_name
				continue
			}
			nameLen := int(binary.BigEndian.Uint16(data[i+7 : i+9]))
			if nameLen <= 0 || nameLen > 253 || i+9+nameLen > len(data) {
				continue
			}
			sni := string(data[i+9 : i+9+nameLen])
			if isValidHostname(sni) {
				return sni
			}
		}
	}
	return ""
}

func isValidHostname(h string) bool {
	if len(h) < 3 || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, c := range h {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// ExtractHTTPHost parses the first few lines of an HTTP request and extracts the Host hostname (without port).
// Uses zero-allocation byte slice scanning to avoid bufio/strings allocations on intercepted connections.
func ExtractHTTPHost(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// 1. Read request line (e.g. GET / HTTP/1.1 or CONNECT example.com:443 HTTP/1.1)
	firstLineEnd := bytes.IndexByte(data, '\n')
	if firstLineEnd == -1 {
		firstLineEnd = len(data)
	}
	reqLine := data[:firstLineEnd]
	if len(reqLine) > 0 && reqLine[len(reqLine)-1] == '\r' {
		reqLine = reqLine[:len(reqLine)-1]
	}

	parts := bytes.Fields(reqLine)
	if len(parts) < 2 {
		return ""
	}

	// If absolute URI (e.g. GET http://example.com/ HTTP/1.1)
	uri := parts[1]
	if bytes.HasPrefix(uri, []byte("http://")) || bytes.HasPrefix(uri, []byte("https://")) {
		afterProto := uri[bytes.Index(uri, []byte("://"))+3:]
		if slashIdx := bytes.IndexByte(afterProto, '/'); slashIdx != -1 {
			afterProto = afterProto[:slashIdx]
		}
		return cleanHostBytes(afterProto)
	}

	// 2. Scan header lines for "Host:" (case-insensitive)
	lines := data[firstLineEnd:]
	for len(lines) > 0 {
		if lines[0] == '\n' {
			lines = lines[1:]
			continue
		}
		if len(lines) >= 2 && lines[0] == '\r' && lines[1] == '\n' {
			lines = lines[2:]
			continue
		}

		lineEnd := bytes.IndexByte(lines, '\n')
		var line []byte
		if lineEnd == -1 {
			line = lines
			lines = nil
		} else {
			line = lines[:lineEnd]
			lines = lines[lineEnd+1:]
		}

		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			break // End of HTTP headers
		}

		// Case-insensitive check for "host:" without string allocations
		if len(line) >= 5 &&
			(line[0] == 'h' || line[0] == 'H') &&
			(line[1] == 'o' || line[1] == 'O') &&
			(line[2] == 's' || line[2] == 'S') &&
			(line[3] == 't' || line[3] == 'T') &&
			line[4] == ':' {
			hostVal := bytes.TrimSpace(line[5:])
			return cleanHostBytes(hostVal)
		}
	}

	// If CONNECT method without Host header, parts[1] contains target host:port
	if len(parts[0]) == 7 && bytes.EqualFold(parts[0], []byte("CONNECT")) && len(parts[1]) > 0 {
		return cleanHostBytes(parts[1])
	}

	return ""
}

func cleanHostBytes(h []byte) string {
	h = bytes.TrimSpace(h)
	// If IPv6 literal with port, e.g. [::1]:8080
	if len(h) > 0 && h[0] == '[' {
		if closeIdx := bytes.IndexByte(h, ']'); closeIdx != -1 {
			return string(h[1:closeIdx])
		}
	}
	// If host:port
	if colonIdx := bytes.LastIndexByte(h, ':'); colonIdx != -1 {
		return string(h[:colonIdx])
	}
	return string(h)
}

// RewriteIPv4TCP modifies destination IP/port or source IP/port in an IPv4 TCP packet in-place.
func RewriteIPv4TCP(packet []byte, newSrcIP, newDstIP net.IP, newSrcPort, newDstPort uint16) error {
	if len(packet) < 40 {
		return ErrPacketTooShort
	}

	ihl := int(packet[0]&0x0F) * 4
	if len(packet) < ihl+20 {
		return ErrPacketTooShort
	}

	// Update IPv4 addresses
	if newSrcIP != nil {
		if ip4 := newSrcIP.To4(); ip4 != nil {
			copy(packet[12:16], ip4)
		}
	}
	if newDstIP != nil {
		if ip4 := newDstIP.To4(); ip4 != nil {
			copy(packet[16:20], ip4)
		}
	}

	// Update TCP ports
	tcpOffset := ihl
	if newSrcPort != 0 {
		binary.BigEndian.PutUint16(packet[tcpOffset:tcpOffset+2], newSrcPort)
	}
	if newDstPort != 0 {
		binary.BigEndian.PutUint16(packet[tcpOffset+2:tcpOffset+4], newDstPort)
	}

	return nil
}

// RewriteIPv6TCP modifies destination IP/port or source IP/port in an IPv6 TCP packet in-place.
func RewriteIPv6TCP(packet []byte, newSrcIP, newDstIP net.IP, newSrcPort, newDstPort uint16) error {
	if len(packet) < 60 { // 40 bytes IPv6 header + 20 bytes TCP minimum header
		return ErrPacketTooShort
	}

	version := packet[0] >> 4
	if version != 6 {
		return fmt.Errorf("not an IPv6 packet: version %d", version)
	}

	// Update IPv6 addresses (SrcIP: 8..24, DstIP: 24..40)
	if newSrcIP != nil {
		if ip6 := newSrcIP.To16(); ip6 != nil {
			copy(packet[8:24], ip6)
		}
	}
	if newDstIP != nil {
		if ip6 := newDstIP.To16(); ip6 != nil {
			copy(packet[24:40], ip6)
		}
	}

	// Update TCP ports (fixed IPv6 header length is 40 bytes)
	const tcpOffset = 40
	if newSrcPort != 0 {
		binary.BigEndian.PutUint16(packet[tcpOffset:tcpOffset+2], newSrcPort)
	}
	if newDstPort != 0 {
		binary.BigEndian.PutUint16(packet[tcpOffset+2:tcpOffset+4], newDstPort)
	}

	return nil
}

// FragmentIPv4 fragments a large IPv4 packet into multiple packets with max length 'mtu'.
// It recalculates the IP checksums for each fragment. TCP checksums must be correct in the original packet.
func FragmentIPv4(packet []byte, mtu int) [][]byte {
	if len(packet) == 0 {
		return nil
	}
	version := packet[0] >> 4
	if version != 4 {
		return [][]byte{packet} // Only fragment IPv4
	}

	ipHdrLen := int(packet[0]&0x0F) * 4
	if len(packet) <= mtu || ipHdrLen >= len(packet) || ipHdrLen < 20 {
		return [][]byte{packet}
	}

	var fragments [][]byte
	payload := packet[ipHdrLen:]
	maxPayload := (mtu - ipHdrLen) &^ 7 // Must be multiple of 8
	if maxPayload <= 0 {
		return [][]byte{packet}
	}

	for offset := 0; offset < len(payload); offset += maxPayload {
		end := offset + maxPayload
		if end > len(payload) {
			end = len(payload)
		}

		frag := make([]byte, ipHdrLen+end-offset)
		copy(frag[:ipHdrLen], packet[:ipHdrLen])
		copy(frag[ipHdrLen:], payload[offset:end])

		// Update Total Length (bytes 2-3)
		binary.BigEndian.PutUint16(frag[2:4], uint16(len(frag)))

		// Update Flags and Fragment Offset (bytes 6-7)
		// Original DF flag is implicitly cleared. MF flag set if not last fragment.
		fragOffset := uint16(offset / 8)
		if end < len(payload) {
			fragOffset |= 0x2000 // MF (More Fragments) flag
		}
		binary.BigEndian.PutUint16(frag[6:8], fragOffset)

		// Recalculate IP Checksum (bytes 10-11)
		frag[10] = 0
		frag[11] = 0
		var csum uint32
		for i := 0; i < ipHdrLen; i += 2 {
			csum += uint32(frag[i])<<8 | uint32(frag[i+1])
		}
		for csum > 0xffff {
			csum = (csum >> 16) + (csum & 0xffff)
		}
		ipCsum := ^uint16(csum)
		binary.BigEndian.PutUint16(frag[10:12], ipCsum)

		fragments = append(fragments, frag)
	}

	return fragments
}

// ParseUDPFast parses a UDP header at offset 'ihl'.
func ParseUDPFast(packet []byte, ihl int) (srcPort, dstPort, udpLen uint16, dataOffset int, err error) {
	if len(packet) < ihl+8 {
		return 0, 0, 0, 0, ErrPacketTooShort
	}
	udpHeader := packet[ihl : ihl+8]
	srcPort = binary.BigEndian.Uint16(udpHeader[0:2])
	dstPort = binary.BigEndian.Uint16(udpHeader[2:4])
	udpLen = binary.BigEndian.Uint16(udpHeader[4:6])
	dataOffset = ihl + 8
	return srcPort, dstPort, udpLen, dataOffset, nil
}

// BuildIPv4UDPPacket constructs a full IPv4 UDP packet ready for WinDivert checksum calculation and injection.
func BuildIPv4UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return nil
	}

	const ipHdrLen = 20
	const udpHdrLen = 8
	totalLen := ipHdrLen + udpHdrLen + len(payload)
	pkt := make([]byte, totalLen)

	// IPv4 Header
	pkt[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	pkt[1] = 0x00 // DSCP / ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234) // Identification
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // Flags: Don't Fragment (DF)
	pkt[8] = 64                                  // TTL = 64
	pkt[9] = IPPROTO_UDP                         // Protocol = UDP (17)
	// Checksum at 10:12 calculated by WinDivert CalcChecksums
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)

	// UDP Header
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpHdrLen+len(payload)))
	pkt[26] = 0
	pkt[27] = 0

	// Payload
	copy(pkt[28:], payload)
	return pkt
}

// BuildIPv6UDPPacket constructs a full IPv6 UDP packet ready for WinDivert checksum calculation and injection.
func BuildIPv6UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	src16 := srcIP.To16()
	dst16 := dstIP.To16()
	if src16 == nil || dst16 == nil {
		return nil
	}

	const ip6HdrLen = 40
	const udpHdrLen = 8
	payloadLen := udpHdrLen + len(payload)
	totalLen := ip6HdrLen + payloadLen
	pkt := make([]byte, totalLen)

	// IPv6 Header
	pkt[0] = 0x60 // Version 6
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00
	binary.BigEndian.PutUint16(pkt[4:6], uint16(payloadLen))
	pkt[6] = IPPROTO_UDP // Next Header = UDP (17)
	pkt[7] = 64          // Hop Limit = 64
	copy(pkt[8:24], src16)
	copy(pkt[24:40], dst16)

	// UDP Header
	binary.BigEndian.PutUint16(pkt[40:42], srcPort)
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)
	binary.BigEndian.PutUint16(pkt[44:46], uint16(payloadLen))
	pkt[46] = 0
	pkt[47] = 0

	// Payload
	copy(pkt[48:], payload)
	return pkt
}

