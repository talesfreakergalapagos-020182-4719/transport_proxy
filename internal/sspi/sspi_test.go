//go:build windows

package sspi

import (
	"encoding/base64"
	"runtime"
	"strings"
	"testing"
)

func TestSSPIContext_GenerateInitialToken(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("SSPI tests only run on Windows")
	}

	ctx, err := NewSSPIContext("NTLM", "")
	if err != nil {
		t.Fatalf("Failed to create SSPI context for NTLM: %v", err)
	}
	defer ctx.Release()

	token, done, err := ctx.NextStep("")
	if err != nil {
		if strings.Contains(err.Error(), "0x80090304") {
			t.Skipf("SSPI not available in this environment (SEC_E_NO_CREDENTIALS): %v", err)
			return
		}
		t.Fatalf("NextStep failed: %v", err)
	}

	if token == "" {
		t.Fatalf("Expected non-empty client token, got empty")
	}

	if done {
		t.Fatalf("Initial step should not mark completion")
	}

	t.Logf("Generated initial SSPI NTLM token (len=%d): %s...", len(token), token[:min(len(token), 32)])
}

func buildTestNTLMType2() string {
	targetName := []byte{'P', 0, 'R', 0, 'O', 0, 'X', 0, 'Y', 0} // 10 bytes
	targetInfo := []byte{
		0x01, 0x00, 0x0a, 0x00, 'P', 0, 'R', 0, 'O', 0, 'X', 0, 'Y', 0, // MsvAvNbServerName = PROXY
		0x00, 0x00, 0x00, 0x00, // MsvAvEOL
	}

	targetNameOffset := uint32(56) // 48 header + 8 version
	targetInfoOffset := targetNameOffset + uint32(len(targetName))

	// Flags: UNICODE(1) | REQUEST_TARGET(4) | NTLM(0x200) | ALWAYS_SIGN(0x8000) | TARGET_TYPE_SERVER(0x20000) |
	// EXTENDED_SESSIONSECURITY(0x80000) | TARGET_INFO(0x800000) | VERSION(0x2000000) | 128(0x20000000) | KEY_EXCH(0x40000000) | 56(0x80000000)
	flags := uint32(0xe28a8235)

	buf := make([]byte, targetInfoOffset+uint32(len(targetInfo)))
	copy(buf[0:8], []byte("NTLMSSP\x00"))
	buf[8] = 0x02 // Type 2
	buf[9] = 0x00
	buf[10] = 0x00
	buf[11] = 0x00

	// Target Name SecBuffer
	buf[12] = byte(len(targetName))
	buf[13] = 0
	buf[14] = byte(len(targetName))
	buf[15] = 0
	buf[16] = byte(targetNameOffset)
	buf[17] = byte(targetNameOffset >> 8)
	buf[18] = 0
	buf[19] = 0

	// Flags
	buf[20] = byte(flags)
	buf[21] = byte(flags >> 8)
	buf[22] = byte(flags >> 16)
	buf[23] = byte(flags >> 24)

	// Server Challenge (8 bytes)
	copy(buf[24:32], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	// Reserved (8 bytes)
	// (zeros)

	// Target Info SecBuffer
	buf[40] = byte(len(targetInfo))
	buf[41] = 0
	buf[42] = byte(len(targetInfo))
	buf[43] = 0
	buf[44] = byte(targetInfoOffset)
	buf[45] = byte(targetInfoOffset >> 8)
	buf[46] = 0
	buf[47] = 0

	// Version: Windows 10.0.19041, NTLMSSP Rev 15
	copy(buf[48:56], []byte{10, 0, 0x79, 0x4a, 0, 0, 0, 15})

	// Payload
	copy(buf[targetNameOffset:], targetName)
	copy(buf[targetInfoOffset:], targetInfo)

	return base64.StdEncoding.EncodeToString(buf)
}

func TestSSPIContext_FullClientServerHandshake(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("SSPI tests only run on Windows")
	}

	for _, pkg := range []string{"NTLM", "Negotiate"} {
		t.Run(pkg, func(t *testing.T) {
			clientCtx, err := NewSSPIContext(pkg, "")
			if err != nil {
				t.Fatalf("NewSSPIContext(%s) failed: %v", pkg, err)
			}
			defer clientCtx.Release()

			serverCtx, err := NewServerSSPIContext(pkg)
			if err != nil {
				t.Fatalf("NewServerSSPIContext(%s) failed: %v", pkg, err)
			}
			defer serverCtx.Release()

			// Step 1: Client Type 1
			token1, clientDone, err := clientCtx.NextStep("")
			if err != nil {
				if strings.Contains(err.Error(), "0x80090304") {
					t.Skipf("SSPI not available in this environment (SEC_E_NO_CREDENTIALS): %v", err)
					return
				}
				t.Fatalf("Client Step 1 failed: %v", err)
			}
			t.Logf("[%s] Client Step 1: token len=%d, done=%v", pkg, len(token1), clientDone)

			// Step 2: Server accepts Type 1 -> outputs Type 2 Challenge
			token2, serverDone, err := serverCtx.AcceptStep(token1)
			if err != nil {
				t.Fatalf("Server AcceptStep 1 failed: %v", err)
			}
			t.Logf("[%s] Server Step 1 (Challenge): token len=%d, done=%v", pkg, len(token2), serverDone)

			// Step 3: Client accepts Type 2 -> outputs Type 3 Response
			token3, clientDone, err := clientCtx.NextStep(token2)
			if err != nil {
				t.Fatalf("Client Step 2 failed: %v", err)
			}
			t.Logf("[%s] Client Step 2 (Response): token len=%d, done=%v", pkg, len(token3), clientDone)

			// Step 4: Server accepts Type 3 -> authentication complete!
			_, serverDone, err = serverCtx.AcceptStep(token3)
			if err != nil {
				t.Fatalf("Server AcceptStep 2 failed: %v", err)
			}
			t.Logf("[%s] Server Step 2 (Auth Complete): done=%v", pkg, serverDone)

			if !serverDone {
				t.Fatalf("Expected server SSPI to be completed")
			}
		})
	}
}


func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

