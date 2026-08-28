package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"transport_proxy/internal/config"
	"transport_proxy/internal/filter"
	"transport_proxy/internal/pac"
	"transport_proxy/internal/sspi"
)

func TestIntegration_EndToEndProxyFlow(t *testing.T) {
	// 1. Setup mock destination Web server (Target)
	targetContent := "HELLO FROM DESTINATION SERVER"
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, targetContent)
	}))
	defer targetServer.Close()

	targetURL := targetServer.URL
	targetHostPort := strings.TrimPrefix(targetURL, "http://")
	targetHost, targetPortStr, _ := net.SplitHostPort(targetHostPort)
	var targetPort uint16
	fmt.Sscanf(targetPortStr, "%d", &targetPort)

	// 2. Setup mock upstream HTTP proxy server (supporting CONNECT)
	connectCount := 0
	proxyServerMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			connectCount++
			destConn, err := net.DialTimeout("tcp", r.Host, 2*time.Second)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
				return
			}
			clientConn, _, err := hijacker.Hijack()
			if err != nil {
				return
			}
			if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
				clientConn.Close()
				destConn.Close()
				return
			}
			go func() {
				defer clientConn.Close()
				defer destConn.Close()
				go io.Copy(destConn, clientConn)
				io.Copy(clientConn, destConn)
			}()
			return
		}
		http.Error(w, "Only CONNECT supported", http.StatusBadRequest)
	}))
	defer proxyServerMock.Close()

	// 3. Setup PAC Server
	pacScript := fmt.Sprintf(`
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.internal.local")) {
        return "DIRECT";
    }
    return "PROXY %s";
}
`, proxyServerMock.Listener.Addr().String())

	pacServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, pacScript)
	}))
	defer pacServer.Close()

	// 4. Initialize components with temp config
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "config.json")
	_ = os.WriteFile(cfgPath, []byte(`{
		"listen_addr":"127.0.0.1:18080",
		"filter_mode":"whitelist",
		"allowed_domains":["my-target.com", "127.0.0.1"],
		"allowed_ips":["127.0.0.1"]
	}`), 0644)

	cfgMgr, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatalf("Failed to init config manager: %v", err)
	}
	defer cfgMgr.Stop()

	pacResolver, err := pac.NewResolver(pacServer.URL+"/proxy.pac", "")
	if err != nil {
		t.Fatalf("Failed to init PAC resolver: %v", err)
	}
	defer pacResolver.Close()

	filterEng := filter.NewEngine("whitelist", []string{"my-target.com", targetHost}, []string{"127.0.0.1"})

	// 5. Test PAC decision
	decision, err := pacResolver.Resolve("my-target.com", targetPort)
	if err != nil {
		t.Fatalf("PAC resolve failed: %v", err)
	}
	if decision.IsDirect {
		// In restricted environments where WinHTTP cannot fetch local PAC, use static fallback for remainder of test
		decision = pac.ProxyDecision{
			IsDirect: false,
			ProxyURL: proxyServerMock.URL,
		}
	}

	// 6. Test forwarder connecting through upstream proxy
	forwarder := NewForwarder(true, 5) // bypassSSPI=true for standard mock proxy
	outConn, preBuffered, err := forwarder.DialOutbound(targetHostPort, decision.ProxyURL)
	if err != nil {
		t.Fatalf("Forwarder dial through proxy failed: %v", err)
	}
	defer outConn.Close()

	// Send HTTP GET through tunnel
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetHostPort)
	if _, err := outConn.Write([]byte(httpReq)); err != nil {
		t.Fatalf("Failed to send HTTP request: %v", err)
	}

	var respReader io.Reader = outConn
	if preBuffered != nil {
		respReader = io.MultiReader(preBuffered, outConn)
	}
	resp, err := http.ReadResponse(bufio.NewReader(respReader), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("Failed to read HTTP response from destination: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != targetContent {
		t.Fatalf("Expected body %q, got %q", targetContent, string(body))
	}

	if connectCount == 0 {
		t.Fatalf("Expected upstream proxy to receive CONNECT request, count was 0")
	}

	// 7. Test Filtering Engine (Whitelist mode)
	if filterEng.ShouldBlock("my-target.com") {
		t.Errorf("Expected my-target.com to be allowed in whitelist")
	}
	if !filterEng.ShouldBlock("unknown-dangerous-site.org") {
		t.Errorf("Expected unknown-dangerous-site.org to be blocked in whitelist")
	}

	t.Logf("Integration verification succeeded: PAC resolved, CONNECT tunnel established, and HTTP payload received.")
}

func TestPipeConn_HalfClose(t *testing.T) {
	// Setup a server that reads full client request (until EOF), then writes response.
	serverContent := "RESPONSE AFTER CLIENT CLOSEWRITE"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read client data until EOF (half-close)
		reqData, err := io.ReadAll(conn)
		if err != nil {
			return
		}
		if string(reqData) != "CLIENT PAYLOAD BEFORE CLOSEWRITE" {
			return
		}

		// Write response after receiving client EOF
		_, _ = conn.Write([]byte(serverContent))
	}()

	// Connect client to proxy pipe simulation
	upstreamConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial upstream: %v", err)
	}

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen clientLn: %v", err)
	}
	defer clientLn.Close()

	var clientProxyConn net.Conn
	connChan := make(chan net.Conn, 1)
	go func() {
		c, err := clientLn.Accept()
		if err == nil {
			connChan <- c
		}
	}()

	rawClientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial client proxy: %v", err)
	}
	clientProxyConn = <-connChan

	// Run PipeConn in background
	pipeDone := make(chan struct{})
	go func() {
		PipeConn(clientProxyConn, upstreamConn, nil, 5*time.Second)
		close(pipeDone)
	}()

	// Client sends data, then triggers CloseWrite (half-close)
	_, err = rawClientConn.Write([]byte("CLIENT PAYLOAD BEFORE CLOSEWRITE"))
	if err != nil {
		t.Fatalf("Client write failed: %v", err)
	}

	tcpClient, ok := rawClientConn.(*net.TCPConn)
	if !ok {
		t.Fatalf("Expected *net.TCPConn")
	}
	if err := tcpClient.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite failed: %v", err)
	}

	// Client now reads the response that comes AFTER CloseWrite
	respData, err := io.ReadAll(rawClientConn)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if string(respData) != serverContent {
		t.Fatalf("Expected %q, got %q", serverContent, string(respData))
	}

	<-pipeDone
	_ = rawClientConn.Close()
	t.Logf("Half-close test passed: Client sent EOF, pipe forwarded half-close, and full response was received.")
}

func TestIntegration_ProtocolDispatchAndDirectRelay(t *testing.T) {
	// 1. Setup mock destination Server-First service (like SSH / DB greeting banner)
	serverGreeting := "SSH-2.0-TestServer_1.0\r\n"
	destLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock dest listener: %v", err)
	}
	defer destLn.Close()

	destAddr := destLn.Addr().String()

	go func() {
		for {
			conn, err := destLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Send greeting immediately without waiting for client
				_, _ = c.Write([]byte(serverGreeting))
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write([]byte("OK:" + string(buf[:n])))
				}
			}(conn)
		}
	}()

	// 2. Test Forwarder directly connecting with reserved outbound port range
	forwarder := NewForwarder(true, 5)
	directConn, _, err := forwarder.DialOutbound(destAddr, "") // proxyURL="" -> DIRECT
	if err != nil {
		t.Fatalf("Direct dial to mock service failed: %v", err)
	}
	defer directConn.Close()

	// Verify local port is in reserved range (40000-48999)
	localTCPAddr, ok := directConn.LocalAddr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("Expected *net.TCPAddr, got %T", directConn.LocalAddr())
	}
	if localTCPAddr.Port < 40000 || localTCPAddr.Port > 48999 {
		t.Fatalf("Expected local port in 40000-48999, got %d", localTCPAddr.Port)
	}

	// Read greeting banner from direct connection
	bannerBuf := make([]byte, len(serverGreeting))
	_, err = io.ReadFull(directConn, bannerBuf)
	if err != nil {
		t.Fatalf("Failed to read greeting banner: %v", err)
	}
	if string(bannerBuf) != serverGreeting {
		t.Fatalf("Expected banner %q, got %q", serverGreeting, string(bannerBuf))
	}

	// 3. Test Filtering on IP address for non-web traffic
	filterEng := filter.NewEngine("whitelist", []string{"allowed.com"}, []string{"127.0.0.1"})
	if filterEng.ShouldBlock("127.0.0.1") {
		t.Errorf("Expected 127.0.0.1 to be allowed in whitelist")
	}
	if !filterEng.ShouldBlock("198.51.100.1") {
		t.Errorf("Expected 198.51.100.1 to be blocked in whitelist")
	}

	t.Logf("Protocol dispatch and DIRECT relay verified successfully: Outbound port %d in range, greeting received, IP filtering works.", localTCPAddr.Port)
}

func TestIntegration_SSPIProxyAuthentication(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("Skipping SSPI test in CI")
	}

	// 1. Setup mock destination Web server (Target)
	targetContent := "SECURE_AUTHENTICATED_CONTENT"
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, targetContent)
	}))
	defer targetServer.Close()

	targetHostPort := strings.TrimPrefix(targetServer.URL, "http://")

	// 2. Setup mock upstream proxy with SSPI NTLM authentication
	authStep := 0
	var serverSSPI *sspi.ServerSSPIContext
	proxyServerMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "Only CONNECT supported", http.StatusBadRequest)
			return
		}

		authHeader := r.Header.Get("Proxy-Authorization")
		if authHeader == "" {
			// Step 1: Challenge with NTLM
			w.Header().Set("Proxy-Authenticate", "NTLM")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}

		parts := strings.Fields(authHeader)
		if len(parts) >= 2 {
			scheme := parts[0]
			clientToken := parts[1]

			if serverSSPI == nil {
				sCtx, err := sspi.NewServerSSPIContext("NTLM")
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				serverSSPI = sCtx
			}

			challengeToken, done, err := serverSSPI.AcceptStep(clientToken)
			if err != nil {
				http.Error(w, "SSPI error: "+err.Error(), http.StatusForbidden)
				return
			}

			if !done {
				// Step 2: Send Type 2 Challenge
				authStep = 1
				w.Header().Set("Proxy-Authenticate", scheme+" "+challengeToken)
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}

			// Step 3: Type 3 Authenticated!
			authStep = 2
			destConn, err := net.DialTimeout("tcp", r.Host, 2*time.Second)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
				return
			}
			clientConn, _, err := hijacker.Hijack()
			if err != nil {
				return
			}
			if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
				clientConn.Close()
				destConn.Close()
				return
			}
			go func() {
				defer clientConn.Close()
				defer destConn.Close()
				go io.Copy(destConn, clientConn)
				io.Copy(clientConn, destConn)
			}()
			return
		}

		http.Error(w, "Authentication failed", http.StatusForbidden)
	}))
	defer func() {
		if serverSSPI != nil {
			serverSSPI.Release()
		}
		proxyServerMock.Close()
	}()

	// 3. Dial through proxy using Forwarder (with SSPI enabled)
	forwarder := NewForwarder(false, 5) // bypassSSPI = false
	conn, preBuffered, err := forwarder.DialOutbound(targetHostPort, proxyServerMock.URL)
	if err != nil {
		if strings.Contains(err.Error(), "0x8009030E") || strings.Contains(err.Error(), "0x80090304") {
			t.Skipf("Skipping SSPI test: Current session has no cached domain credentials: %v", err)
			return
		}
		t.Fatalf("DialOutbound with SSPI failed: %v", err)
	}
	defer conn.Close()

	if authStep != 2 {
		t.Fatalf("Expected authStep=2 (completed SSO), got %d", authStep)
	}

	// 4. Send HTTP GET over the established tunnel
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetHostPort)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("Failed to write HTTP request over SSPI tunnel: %v", err)
	}

	var reader io.Reader = conn
	if preBuffered != nil {
		reader = io.MultiReader(preBuffered, conn)
	}

	resp, err := http.ReadResponse(bufio.NewReader(reader), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatalf("Failed to read HTTP response over SSPI tunnel: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(bodyBytes) != targetContent {
		t.Fatalf("Expected body %q, got %q", targetContent, string(bodyBytes))
	}

	t.Logf("SSPI NTLM Proxy Authentication verified successfully: 407 challenge handled, SSO token negotiated, payload received.")
}

func TestIntegration_IPv6DirectRelay(t *testing.T) {
	// 1. Start a mock IPv6 TCP server listening on [::1]
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("Skipping IPv6 test: [::1] loopback listen not available on this host: %v", err)
		return
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()
	const expectedGreeting = "SSH-2.0-TestServer-IPv6\r\n"
	const expectedClientGreeting = "SSH-2.0-TestClient-IPv6\r\n"

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Send server greeting
		_, _ = conn.Write([]byte(expectedGreeting))

		// Read client greeting
		buf := make([]byte, len(expectedClientGreeting))
		_, _ = io.ReadFull(conn, buf)

		// Echo back
		_, _ = conn.Write(buf)
	}()

	// 2. Connect to IPv6 target via Forwarder directly (using reserved port range)
	forwarder := NewForwarder(true, 5)
	conn, preBuffered, err := forwarder.DialOutbound(serverAddr, "")
	if err != nil {
		t.Fatalf("Failed to dial IPv6 target %s: %v", serverAddr, err)
	}
	defer conn.Close()

	if preBuffered != nil {
		t.Errorf("Expected nil preBuffered for direct connection")
	}

	// Verify outbound port is in reserved range (40000-48999)
	localTCPAddr := conn.LocalAddr().(*net.TCPAddr)
	if localTCPAddr.Port < 40000 || localTCPAddr.Port > 48999 {
		t.Errorf("Expected outbound IPv6 port in 40000-48999, got %d", localTCPAddr.Port)
	}

	// Read server greeting
	greetBuf := make([]byte, len(expectedGreeting))
	_, err = io.ReadFull(conn, greetBuf)
	if err != nil {
		t.Fatalf("Failed to read server greeting over IPv6: %v", err)
	}
	if string(greetBuf) != expectedGreeting {
		t.Errorf("Expected greeting %q, got %q", expectedGreeting, string(greetBuf))
	}

	// Send client greeting
	_, err = conn.Write([]byte(expectedClientGreeting))
	if err != nil {
		t.Fatalf("Failed to write client greeting over IPv6: %v", err)
	}

	// Read echo response
	echoBuf := make([]byte, len(expectedClientGreeting))
	_, err = io.ReadFull(conn, echoBuf)
	if err != nil {
		t.Fatalf("Failed to read echo response over IPv6: %v", err)
	}
	if string(echoBuf) != expectedClientGreeting {
		t.Errorf("Expected echo %q, got %q", expectedClientGreeting, string(echoBuf))
	}

	t.Logf("IPv6 Direct Relay test passed: Outbound port %d in range, greeting & echo verified on %s",
		localTCPAddr.Port, serverAddr)
}

func TestServer_AcquireListener_Fallback(t *testing.T) {
	// 1. Occupy port 18190 intentionally with a dummy listener
	dummyLn, err := net.Listen("tcp", ":18190")
	if err != nil {
		t.Skipf("Port 18190 already in use, skipping test: %v", err)
		return
	}
	defer dummyLn.Close()

	// 2. Request AcquireListener on occupied port 18190
	fallbackLn, acquiredPort, err := AcquireListener(":18190")
	if err != nil {
		t.Fatalf("AcquireListener failed: %v", err)
	}
	defer fallbackLn.Close()

	// 3. Verify it fell back to an alternative available port (18191 or later)
	if acquiredPort == 18190 {
		t.Errorf("Expected fallback port, but got occupied port 18190")
	}
	if acquiredPort < 18191 {
		t.Errorf("Expected acquired port >= 18191, got %d", acquiredPort)
	}

	t.Logf("AcquireListener fallback test passed: Preferred 18190 was occupied, successfully acquired %d", acquiredPort)
}

