package sspi

import (
	"bufio"
	"encoding/base64"
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
	// On Linux (where Windows SSPI is unavailable), send preemptive Basic auth if credentials are provided in proxy URL.
	authHeader := ""
	if !isWindows && proxyUser != nil {
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
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32768))
	_ = resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// Connection established successfully (either unauthenticated or via preemptive Basic auth)
		return reader, nil
	}

	if resp.StatusCode != http.StatusProxyAuthRequired {
		return nil, fmt.Errorf("proxy returned unexpected status %d: %s", resp.StatusCode, resp.Status)
	}

	// Check if proxy closed connection on 407
	if resp.Close || strings.EqualFold(resp.Header.Get("Proxy-Connection"), "close") || strings.EqualFold(resp.Header.Get("Connection"), "close") {
		return nil, fmt.Errorf("proxy returned 407 (%s) and closed the connection; consider setting \"bypass_sspi\": true in config.json to enable preemptive authentication", resp.Status)
	}

	// Step 2: Parse Proxy-Authenticate headers
	authHeaders := resp.Header.Values("Proxy-Authenticate")
	hasNegotiate := false
	hasNTLM := false
	hasBasic := false

	for _, h := range authHeaders {
		for _, part := range strings.Split(h, ",") {
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

	// Step 3: Authenticate based on OS platform and available schemes

	// A. If on Windows and Negotiate/NTLM is offered, prefer Windows SSPI SSO
	if isWindows && (hasNegotiate || hasNTLM) {
		selectedScheme := "Negotiate"
		if !hasNegotiate && hasNTLM {
			selectedScheme = "NTLM"
		}

		log.Printf("[SSPI]  407 Proxy Auth Required -> Negotiating Windows SSO (%s) for %s...", selectedScheme, proxyHost)

		sspiReader, sspiErr := performSSPIHandshake(conn, reader, targetAddr, proxyHost, selectedScheme, resp)
		if sspiErr == nil {
			return sspiReader, nil
		}

		log.Printf("[SSPI]  Windows SSO (%s) failed: %v", selectedScheme, sspiErr)
		// If SSPI failed but Basic is available with credentials, fall through to try Basic
		if !hasBasic || proxyUser == nil {
			return nil, fmt.Errorf("SSPI authentication (%s) failed: %w", selectedScheme, sspiErr)
		}
		log.Printf("[SSPI]  Falling back to HTTP Basic authentication...")
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
		_, _ = io.Copy(io.Discard, io.LimitReader(basicResp.Body, 32768))
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

func performSSPIHandshake(conn net.Conn, reader *bufio.Reader, targetAddr, proxyHost, selectedScheme string, firstResp *http.Response) (*bufio.Reader, error) {
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

		resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
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
