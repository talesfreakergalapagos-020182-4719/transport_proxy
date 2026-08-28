package sspi

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// AuthenticateProxyTunnel performs the HTTP CONNECT handshake with optional SSPI authentication
// (Negotiate/NTLM/Kerberos) on an established TCP connection to an upstream proxy.
// targetAddr is the destination host:port (e.g., "example.com:443" or "93.184.216.34:80").
// proxyHost is the hostname of the upstream proxy (for SPN construction).
func AuthenticateProxyTunnel(conn net.Conn, targetAddr string, proxyHost string, timeout time.Duration) (*bufio.Reader, error) {
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		defer func() {
			_ = conn.SetDeadline(time.Time{}) // Reset deadline after handshake
		}()
	}

	reader := bufio.NewReader(conn)

	// Step 1: Initial unauthenticated CONNECT request
	initialReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", targetAddr, targetAddr)
	if _, err := conn.Write([]byte(initialReq)); err != nil {
		return nil, fmt.Errorf("failed to send initial CONNECT request: %w", err)
	}

	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil {
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32768))
	_ = resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// No authentication required
		return reader, nil
	}

	if resp.StatusCode != http.StatusProxyAuthRequired {
		return nil, fmt.Errorf("proxy returned unexpected status %d: %s", resp.StatusCode, resp.Status)
	}

	// Step 2: Parse Proxy-Authenticate headers
	authHeaders := resp.Header.Values("Proxy-Authenticate")
	selectedScheme := ""
	for _, h := range authHeaders {
		parts := strings.Fields(h)
		if len(parts) > 0 {
			scheme := strings.ToLower(parts[0])
			if scheme == "negotiate" {
				selectedScheme = "Negotiate"
				break
			} else if scheme == "ntlm" && selectedScheme == "" {
				selectedScheme = "NTLM"
			}
		}
	}

	if selectedScheme == "" {
		return nil, fmt.Errorf("proxy requires authentication, but no supported schemes (Negotiate/NTLM) found in: %v", authHeaders)
	}

	log.Printf("[SSPI]  407 Proxy Auth Required -> Negotiating Windows SSO (%s) for %s...", selectedScheme, proxyHost)

	// Step 3: SSPI Handshake loop on the SAME connection
	spn := ""
	if selectedScheme == "Negotiate" && proxyHost != "" {
		if host, _, err := net.SplitHostPort(proxyHost); err == nil {
			spn = "HTTP/" + host
		} else {
			spn = "HTTP/" + proxyHost
		}
	}

	sspiCtx, err := NewSSPIContext(selectedScheme, spn)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSPI context: %w", err)
	}
	defer sspiCtx.Release()

	serverChallenge := ""
	for loop := 0; loop < 5; loop++ {
		clientToken, done, err := sspiCtx.NextStep(serverChallenge)
		if err != nil {
			return nil, fmt.Errorf("SSPI negotiation error at step %d: %w", loop, err)
		}

		reqStr := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\nProxy-Authorization: %s %s\r\n\r\n",
			targetAddr, targetAddr, selectedScheme, clientToken)

		if _, err := conn.Write([]byte(reqStr)); err != nil {
			return nil, fmt.Errorf("failed to send authenticated CONNECT request: %w", err)
		}

		resp, err = http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		if err != nil {
			return nil, fmt.Errorf("failed to read response after SSPI token: %w", err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32768))
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			// Authentication successful! Tunnel is open.
			log.Printf("[SSPI]  Windows SSO authentication succeeded for %s", targetAddr)
			return reader, nil
		}

		if resp.StatusCode != http.StatusProxyAuthRequired {
			return nil, fmt.Errorf("proxy returned status %d after SSPI token: %s", resp.StatusCode, resp.Status)
		}

		if done {
			return nil, fmt.Errorf("SSPI reported complete but proxy still returned 407 (access denied)")
		}

		// Extract server challenge token from Proxy-Authenticate header
		serverChallenge = ""
		for _, h := range resp.Header.Values("Proxy-Authenticate") {
			parts := strings.Fields(h)
			if len(parts) >= 2 && strings.EqualFold(parts[0], selectedScheme) {
				serverChallenge = parts[1]
				break
			}
		}
	}

	return nil, fmt.Errorf("exceeded maximum SSPI negotiation steps")
}
