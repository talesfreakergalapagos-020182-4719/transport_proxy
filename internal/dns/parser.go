package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// DNS Record Types (RFC 1035)
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeANY   uint16 = 255
)

// DNS Response Codes (RCODE)
const (
	RCodeNoError  uint8 = 0
	RCodeFormErr  uint8 = 1
	RCodeServFail uint8 = 2
	RCodeNXDomain uint8 = 3
	RCodeRefused  uint8 = 5
)

var (
	ErrPacketTooShort = errors.New("dns: packet too short")
	ErrInvalidQName   = errors.New("dns: invalid qname")
)

// Header represents a 12-byte DNS wire format header.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Question represents a DNS query question section.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// Message represents a parsed DNS query or response.
type Message struct {
	Header    Header
	Questions []Question
	Raw       []byte
}

// ParseQuery parses a raw DNS query packet and extracts header and first question.
func ParseQuery(data []byte) (*Message, error) {
	if len(data) < 12 {
		return nil, ErrPacketTooShort
	}

	msg := &Message{
		Header: Header{
			ID:      binary.BigEndian.Uint16(data[0:2]),
			Flags:   binary.BigEndian.Uint16(data[2:4]),
			QDCount: binary.BigEndian.Uint16(data[4:6]),
			ANCount: binary.BigEndian.Uint16(data[6:8]),
			NSCount: binary.BigEndian.Uint16(data[8:10]),
			ARCount: binary.BigEndian.Uint16(data[10:12]),
		},
		Raw: data,
	}

	offset := 12
	for i := 0; i < int(msg.Header.QDCount); i++ {
		name, newOffset, err := parseDomainName(data, offset)
		if err != nil {
			return nil, err
		}
		if newOffset+4 > len(data) {
			return nil, ErrPacketTooShort
		}

		qType := binary.BigEndian.Uint16(data[newOffset : newOffset+2])
		qClass := binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4])
		offset = newOffset + 4

		msg.Questions = append(msg.Questions, Question{
			Name:  name,
			Type:  qType,
			Class: qClass,
		})
	}

	return msg, nil
}

// parseDomainName parses a label-encoded domain name from data at offset.
func parseDomainName(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return "", offset, ErrPacketTooShort
	}

	var labels []string
	curr := offset
	jumped := false
	maxJumps := 10
	jumps := 0
	retOffset := offset

	for {
		if curr >= len(data) {
			return "", offset, ErrPacketTooShort
		}

		length := int(data[curr])
		if length == 0 {
			if !jumped {
				retOffset = curr + 1
			}
			break
		}

		// Compression pointer (top 2 bits set)
		if length&0xC0 == 0xC0 {
			if curr+1 >= len(data) {
				return "", offset, ErrPacketTooShort
			}
			if !jumped {
				retOffset = curr + 2
				jumped = true
			}
			pointer := int(binary.BigEndian.Uint16(data[curr:curr+2]) & 0x3FFF)
			if pointer >= len(data) {
				return "", offset, ErrInvalidQName
			}
			curr = pointer
			jumps++
			if jumps > maxJumps {
				return "", offset, errors.New("dns: pointer loop detected")
			}
			continue
		}

		curr++
		if curr+length > len(data) {
			return "", offset, ErrPacketTooShort
		}

		label := string(data[curr : curr+length])
		labels = append(labels, label)
		curr += length
	}

	return strings.ToLower(strings.Join(labels, ".")), retOffset, nil
}

// BuildErrorResponse creates a minimal DNS error response (e.g. NXDOMAIN, SERVFAIL, REFUSED)
// echoing the original transaction ID and question section.
func BuildErrorResponse(reqData []byte, rcode uint8) []byte {
	if len(reqData) < 12 {
		// Return generic 12-byte header
		resp := make([]byte, 12)
		resp[2] = 0x81 // QR=1 (response), RD=1
		resp[3] = 0x80 | (rcode & 0x0F)
		return resp
	}

	// Read Question section length
	msg, err := ParseQuery(reqData)
	questionLen := 0
	if err == nil && len(msg.Questions) > 0 {
		// Calculate length from byte 12 to end of question section
		offset := 12
		for i := 0; i < int(msg.Header.QDCount); i++ {
			for offset < len(reqData) {
				l := int(reqData[offset])
				if l == 0 {
					offset++
					break
				}
				if l&0xC0 == 0xC0 {
					offset += 2
					break
				}
				offset += 1 + l
			}
			offset += 4 // Type (2) + Class (2)
		}
		if offset <= len(reqData) {
			questionLen = offset - 12
		}
	}

	resp := make([]byte, 12+questionLen)
	// Echo Transaction ID
	copy(resp[0:2], reqData[0:2])

	// Flags: QR=1 (Response), Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=rcode
	flags := uint16(0x8180) | uint16(rcode&0x0F)
	if len(reqData) >= 4 {
		// Preserve original RD (Recursion Desired) flag
		rdBit := reqData[2] & 0x01
		flags = (flags &^ 0x0100) | (uint16(rdBit) << 8)
	}
	binary.BigEndian.PutUint16(resp[2:4], flags)

	if questionLen > 0 {
		binary.BigEndian.PutUint16(resp[4:6], msg.Header.QDCount) // QDCOUNT
		copy(resp[12:], reqData[12:12+questionLen])
	}

	return resp
}

// ExtractMinTTL parses the answer section of a raw DNS response to determine the minimum TTL (seconds).
// Returns defaultTTL (e.g. 300) if no answer records are found or on parse error.
func ExtractMinTTL(respData []byte, defaultTTL uint32) uint32 {
	if len(respData) < 12 {
		return defaultTTL
	}

	qdCount := int(binary.BigEndian.Uint16(respData[4:6]))
	anCount := int(binary.BigEndian.Uint16(respData[6:8]))
	if anCount == 0 {
		return defaultTTL
	}

	offset := 12
	// Skip question section
	for i := 0; i < qdCount && offset < len(respData); i++ {
		_, newOffset, err := parseDomainName(respData, offset)
		if err != nil {
			return defaultTTL
		}
		offset = newOffset + 4
	}

	minTTL := uint32(0xFFFFFFFF)
	found := false

	// Parse answer section
	for i := 0; i < anCount && offset < len(respData); i++ {
		_, newOffset, err := parseDomainName(respData, offset)
		if err != nil {
			break
		}
		offset = newOffset
		if offset+10 > len(respData) {
			break
		}

		ttl := binary.BigEndian.Uint32(respData[offset+4 : offset+8])
		rdLength := int(binary.BigEndian.Uint16(respData[offset+8 : offset+10]))
		offset += 10 + rdLength

		if ttl > 0 && ttl < minTTL {
			minTTL = ttl
			found = true
		}
	}

	if found && minTTL > 0 {
		if minTTL > 86400 {
			minTTL = 86400 // Cap at 1 day
		}
		return minTTL
	}

	return defaultTTL
}

// TypeToString returns string representation of standard DNS record type.
func TypeToString(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeAAAA:
		return "AAAA"
	case TypeCNAME:
		return "CNAME"
	case TypeNS:
		return "NS"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeSOA:
		return "SOA"
	case TypeSRV:
		return "SRV"
	case TypeANY:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}
