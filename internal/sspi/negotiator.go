package sspi

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

// ErrSSPIFailedWithBasicAvailable is returned when SSPI negotiation fails but Basic credentials are available.
// The caller should dial a fresh TCP connection and retry with Basic authentication.
var ErrSSPIFailedWithBasicAvailable = errors.New("SSPI negotiation failed, fallback to fresh connection Basic auth")

// AuthenticateProxyTunnel performs the HTTP CONNECT handshake with optional SSPI authentication
// (Negotiate/NTLM/Kerberos) or HTTP Basic authentication on an established TCP connection to an upstream proxy.
// targetAddr is the destination host:port (e.g., "example.com:443" or "93.184.216.34:80").
// proxyURL contains the parsed upstream proxy URL (including hostname, port, and optional credentials in User).
func AuthenticateProxyTunnel(conn net.Conn, targetAddr string, proxyURL *url.URL, timeout time.Duration) (*bufio.Reader, error) {
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		defer func() {
			_ = conn.SetDeadline(time.Time{}) // Reset deadline after handshake
		}()
	}

	reader := bufio.NewReader(conn)

	proxyHost := ""
	var proxyUser *url.Userinfo
	if proxyURL != nil {
		proxyHost = proxyURL.Hostname()
		proxyUser = proxyURL.User
	}

	isWindows := runtime.GOOS == "windows"

	// Step 1: Initial CONNECT request
	// If credentials are provided in proxy URL, send preemptive Basic auth on all platforms (Windows & Linux).
	// This prevents immediate connection termination on proxies that send "Connection: close" with 407.
	authHeader := ""
	if proxyUser != nil {
		username := proxyUser.Username()
		password, _ := proxyUser.Password()
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		authHeader = fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", token)
	}

	initialReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n%s\r\n", targetAddr, targetAddr, authHeader)
	if _, err := conn.Write([]byte(initialReq)); err != nil {
		return nil, fmt.Errorf("failed to send initial CONNECT request: %w", err)
	}

	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil {
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.ContentLength > 0 {
		_, _ = io.CopyN(io.Discard, resp.Body, resp.ContentLength)
	}
	_ = resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// Connection established successfully (either unauthenticated or via preemptive Basic auth)
		return reader, nil
	}

	if resp.StatusCode != http.StatusProxyAuthRequired {
		return nil, fmt.Errorf("proxy returned unexpected status %d: %s", resp.StatusCode, resp.Status)
	}

	// Check if proxy closed connection on 407
	isClosed := resp.Close || strings.EqualFold(resp.Header.Get("Proxy-Connection"), "close") || strings.EqualFold(resp.Header.Get("Connection"), "close")

	// Step 2: Parse Proxy-Authenticate headers
	authHeaders := resp.Header.Values("Proxy-Authenticate")
	hasNegotiate := false
	hasNTLM := false
	hasBasic := false

	for _, h := range authHeaders {
		parts := splitAuthHeader(h)
		for _, part := range parts {
			fields := strings.Fields(strings.TrimSpace(part))
			if len(fields) > 0 {
				scheme := strings.ToLower(fields[0])
				switch scheme {
				case "negotiate":
					hasNegotiate = true
				case "ntlm":
					hasNTLM = true
				case "basic":
					hasBasic = true
				}
			}
		}
	}

	// If proxy closed connection on 407
	if isClosed {
		if hasBasic && proxyUser != nil {
			return nil, ErrSSPIFailedWithBasicAvailable
		}
		return nil, fmt.Errorf("proxy returned 407 (%s) and closed the connection; consider setting \"bypass_sspi\": true in config.json to enable preemptive authentication", resp.Status)
	}

	// Step 3: Authenticate based on OS platform and available schemes

	// A. If on Windows and Negotiate/NTLM is offered, prefer Windows SSPI SSO
	if isWindows && (hasNegotiate || hasNTLM) {
		selectedScheme := "Negotiate"
		hostOnly := proxyHost
		if h, _, err := net.SplitHostPort(proxyHost); err == nil {
			hostOnly = h
		}
		// If proxyHost is an IP address and NTLM is offered, prefer NTLM directly because Kerberos SPN cannot target IP addresses
		if (!hasNegotiate && hasNTLM) || (net.ParseIP(hostOnly) != nil && hasNTLM) {
			selectedScheme = "NTLM"
		}

		log.Printf("[SSPI]  407 Proxy Auth Required -> Negotiating Windows SSO (%s) for %s...", selectedScheme, proxyHost)

		sspiReader, sspiErr := performSSPIHandshake(conn, reader, targetAddr, proxyHost, selectedScheme)
		if sspiErr == nil {
			return sspiReader, nil
		}

		log.Printf("[SSPI]  Windows SSO (%s) failed: %v", selectedScheme, sspiErr)
		// If SSPI failed but Basic is available with credentials, signal caller to retry on a fresh connection
		if hasBasic && proxyUser != nil {
			log.Printf("[SSPI]  Signaling fallback to HTTP Basic authentication via fresh connection...")
			return nil, ErrSSPIFailedWithBasicAvailable
		}
		return nil, fmt.Errorf("SSPI authentication (%s) failed: %w", selectedScheme, sspiErr)
	}

	// B. HTTP Basic Authentication (supported on both Windows and Linux)
	if hasBasic {
		if proxyUser == nil {
			return nil, fmt.Errorf("proxy requires Basic authentication (Proxy-Authenticate: Basic), but no credentials were provided in upstream_proxy URL (use format: http://username:password@proxy:port)")
		}

		log.Printf("[Auth]  407 Proxy Auth Required -> Authenticating via HTTP Basic for user %q...", proxyUser.Username())
		username := proxyUser.Username()
		password, _ := proxyUser.Password()
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

		basicReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\nProxy-Authorization: Basic %s\r\n\r\n",
			targetAddr, targetAddr, token)
		if _, err := conn.Write([]byte(basicReq)); err != nil {
			return nil, fmt.Errorf("failed to send Basic authenticated CONNECT request: %w", err)
		}

		basicResp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		if err != nil {
			return nil, fmt.Errorf("failed to read response after Basic auth: %w", err)
		}
		if basicResp.StatusCode != http.StatusOK && basicResp.ContentLength > 0 {
			_, _ = io.CopyN(io.Discard, basicResp.Body, basicResp.ContentLength)
		}
		_ = basicResp.Body.Close()

		if basicResp.StatusCode == http.StatusOK {
			log.Printf("[Auth]  HTTP Basic authentication succeeded for %s", targetAddr)
			return reader, nil
		}
		return nil, fmt.Errorf("proxy returned status %d after Basic authentication: %s (check username and password)", basicResp.StatusCode, basicResp.Status)
	}

	// C. Linux error message when proxy only offers Windows SSPI (Negotiate/NTLM)
	if !isWindows && (hasNegotiate || hasNTLM) {
		return nil, fmt.Errorf("upstream proxy requires SSPI authentication (Negotiate/NTLM) which is only supported natively on Windows; on Linux, please configure an upstream proxy that supports Basic authentication")
	}

	return nil, fmt.Errorf("proxy requires authentication, but no supported schemes (Negotiate/NTLM/Basic) found in: %v", authHeaders)
}

func performSSPIHandshake(conn net.Conn, reader *bufio.Reader, targetAddr, proxyHost, selectedScheme string) (*bufio.Reader, error) {
	spn := ""
	if selectedScheme == "Negotiate" && proxyHost != "" {
		hostOnly := proxyHost
		if host, _, err := net.SplitHostPort(proxyHost); err == nil {
			hostOnly = host
		}
		// If proxyHost is an IP address, do not set SPN (Active Directory cannot resolve IP addresses as Kerberos SPNs)
		if net.ParseIP(hostOnly) == nil {
			spn = "HTTP/" + hostOnly
		}
	}

	sspiCtx, err := NewSSPIContext(selectedScheme, spn)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSPI context: %w", err)
	}
	defer sspiCtx.Release()

	activeScheme := selectedScheme
	serverChallenge := ""

	for loop := 0; loop < 5; loop++ {
		clientToken, done, err := sspiCtx.NextStep(serverChallenge)
		if err != nil {
			return nil, fmt.Errorf("SSPI negotiation error at step %d: %w", loop, err)
		}

		reqStr := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\nProxy-Authorization: %s %s\r\n\r\n",
			targetAddr, targetAddr, activeScheme, clientToken)

		if _, err := conn.Write([]byte(reqStr)); err != nil {
			return nil, fmt.Errorf("failed to send authenticated CONNECT request: %w", err)
		}

		resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		if err != nil {
			return nil, fmt.Errorf("failed to read response after SSPI token: %w", err)
		}
		if resp.StatusCode != http.StatusOK && resp.ContentLength > 0 {
			_, _ = io.CopyN(io.Discard, resp.Body, resp.ContentLength)
		}
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

		// Extract server challenge token from Proxy-Authenticate header with robust comma/quoting parsing
		actualScheme, chToken, found := ExtractChallengeToken(resp, activeScheme)
		if !found {
			return nil, fmt.Errorf("no challenge token found in Proxy-Authenticate for %s: %v",
				activeScheme, resp.Header.Values("Proxy-Authenticate"))
		}
		activeScheme = actualScheme
		serverChallenge = chToken
	}

	return nil, fmt.Errorf("exceeded maximum SSPI negotiation steps")
}

// ExtractChallengeToken parses Proxy-Authenticate headers and extracts the challenge token
// for the given scheme (or fallback scheme, e.g. NTLM when Negotiate was requested).
// It returns (actualScheme, token, found).
func ExtractChallengeToken(resp *http.Response, selectedScheme string) (string, string, bool) {
	for _, h := range resp.Header.Values("Proxy-Authenticate") {
		parts := splitAuthHeader(h)
		for _, part := range parts {
			fields := strings.Fields(strings.TrimSpace(part))
			if len(fields) >= 2 {
				scheme := fields[0]
				token := strings.TrimRight(fields[1], ",\r\n\t ")
				token = strings.Trim(token, "\"")

				// Match exact scheme
				if strings.EqualFold(scheme, selectedScheme) {
					return scheme, token, true
				}
				// If client selected Negotiate, server might challenge with NTLM directly
				if strings.EqualFold(selectedScheme, "Negotiate") && strings.EqualFold(scheme, "NTLM") {
					return scheme, token, true
				}
			}
		}
	}
	return "", "", false
}

// splitAuthHeader splits a header value by comma while preserving quoted strings and tokens.
func splitAuthHeader(h string) []string {
	var result []string
	var current strings.Builder
	inQuote := false

	for i := 0; i < len(h); i++ {
		c := h[i]
		if c == '"' {
			inQuote = !inQuote
			current.WriteByte(c)
		} else if c == ',' && !inQuote {
			s := strings.TrimSpace(current.String())
			if s != "" {
				result = append(result, s)
			}
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}
	s := strings.TrimSpace(current.String())
	if s != "" {
		result = append(result, s)
	}
	return result
}
