package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
	}

	for _, tt := range tests {
		if got := FormatBytes(tt.bytes); got != tt.expected {
			t.Errorf("FormatBytes(%d) = %s, want %s", tt.bytes, got, tt.expected)
		}
	}
}

type dummyConn struct {
	net.Conn
	r *io.PipeReader
	w *bytes.Buffer
}

func (d *dummyConn) Read(b []byte) (n int, err error) {
	return d.r.Read(b)
}

func (d *dummyConn) Write(b []byte) (n int, err error) {
	return d.w.Write(b)
}

func (d *dummyConn) Close() error { return nil }
func (d *dummyConn) SetReadDeadline(t time.Time) error { return nil }
func (d *dummyConn) SetWriteDeadline(t time.Time) error { return nil }
func (d *dummyConn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234} }
func (d *dummyConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5678} }

func TestPipeConnEx_Basic(t *testing.T) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	c1 := &dummyConn{r: r1, w: new(bytes.Buffer)}
	u1 := &dummyConn{r: r2, w: new(bytes.Buffer)}

	go func() {
		w1.Write([]byte("hello upstream"))
		w1.Close()
	}()

	go func() {
		w2.Write([]byte("hello client"))
		w2.Close()
	}()

	upBytes, downBytes := PipeConnEx(c1, u1, nil, nil, 2*time.Second)

	if upBytes != 14 {
		t.Errorf("expected upBytes 14, got %d", upBytes)
	}
	if downBytes != 12 {
		t.Errorf("expected downBytes 12, got %d", downBytes)
	}
	if c1.w.String() != "hello client" {
		t.Errorf("c1 got %s, want hello client", c1.w.String())
	}
	if u1.w.String() != "hello upstream" {
		t.Errorf("u1 got %s, want hello upstream", u1.w.String())
	}
}

func TestPipeConnEx_WithPrebuffer(t *testing.T) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	c1 := &dummyConn{r: r1, w: new(bytes.Buffer)}
	u1 := &dummyConn{r: r2, w: new(bytes.Buffer)}

	clientPre := bytes.NewReader([]byte("pre_client:"))
	upstreamPre := bytes.NewReader([]byte("pre_upstream:"))

	go func() {
		w1.Write([]byte("body"))
		w1.Close()
	}()

	go func() {
		w2.Write([]byte("data"))
		w2.Close()
	}()

	upBytes, downBytes := PipeConnEx(c1, u1, clientPre, upstreamPre, 2*time.Second)

	if upBytes != 15 { // 11 + 4
		t.Errorf("expected upBytes 15, got %d", upBytes)
	}
	if downBytes != 17 { // 13 + 4
		t.Errorf("expected downBytes 17, got %d", downBytes)
	}
	if !strings.HasPrefix(c1.w.String(), "pre_upstream:") {
		t.Errorf("c1 did not receive pre_upstream")
	}
	if !strings.HasPrefix(u1.w.String(), "pre_client:") {
		t.Errorf("u1 did not receive pre_client")
	}
}

func TestPipeConnEx_LargeFileTransfer(t *testing.T) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	c1 := &dummyConn{r: r1, w: new(bytes.Buffer)}
	u1 := &dummyConn{r: r2, w: new(bytes.Buffer)}

	// 10 MB payload
	const payloadSize = 10 * 1024 * 1024
	largePayload := bytes.Repeat([]byte("A"), payloadSize)

	go func() {
		// Client writes 10MB
		w1.Write(largePayload)
		w1.Close()
	}()

	go func() {
		// Upstream writes 10MB
		w2.Write(largePayload)
		w2.Close()
	}()

	upBytes, downBytes := PipeConnEx(c1, u1, nil, nil, 10*time.Second)

	if upBytes != int64(payloadSize) {
		t.Errorf("expected upBytes %d, got %d", payloadSize, upBytes)
	}
	if downBytes != int64(payloadSize) {
		t.Errorf("expected downBytes %d, got %d", payloadSize, downBytes)
	}

	// Verify buffer size (without converting to string to save memory)
	if c1.w.Len() != payloadSize {
		t.Errorf("c1 did not receive full payload, got %d bytes", c1.w.Len())
	}
	if u1.w.Len() != payloadSize {
		t.Errorf("u1 did not receive full payload, got %d bytes", u1.w.Len())
	}
}

func TestForwarder_DialOutbound_BasicAuth_BypassSSPI(t *testing.T) {
	user := "testuser"
	pass := "secret123"
	expectedToken := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			authHeader := r.Header.Get("Proxy-Authorization")
			if authHeader != "Basic "+expectedToken {
				w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}

			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijack not supported", http.StatusInternalServerError)
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			return
		}
		http.Error(w, "bad method", http.StatusBadRequest)
	}))
	defer proxyServer.Close()

	proxyURL := fmt.Sprintf("http://%s:%s@%s", user, pass, strings.TrimPrefix(proxyServer.URL, "http://"))
	fwd := NewForwarder(true, 5) // bypassSSPI = true

	conn, _, err := fwd.DialOutbound("target.example.com:443", proxyURL)
	if err != nil {
		t.Fatalf("DialOutbound with Basic auth (bypassSSPI=true) failed: %v", err)
	}
	if conn == nil {
		t.Fatalf("Expected non-nil connection returned")
	}
	_ = conn.Close()
}

func TestForwarder_DialOutbound_BasicAuth_ChallengeResponse(t *testing.T) {
	user := "corpuser"
	pass := "corppass"
	expectedToken := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			authHeader := r.Header.Get("Proxy-Authorization")
			if authHeader == "" {
				w.Header().Set("Proxy-Authenticate", `Basic realm="CorpProxy"`)
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}

			if authHeader == "Basic "+expectedToken {
				hijacker, ok := w.(http.Hijacker)
				if !ok {
					http.Error(w, "hijack not supported", http.StatusInternalServerError)
					return
				}
				conn, _, err := hijacker.Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				return
			}

			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		http.Error(w, "bad method", http.StatusBadRequest)
	}))
	defer proxyServer.Close()

	proxyURL := fmt.Sprintf("http://%s:%s@%s", user, pass, strings.TrimPrefix(proxyServer.URL, "http://"))
	fwd := NewForwarder(false, 5) // bypassSSPI = false

	conn, _, err := fwd.DialOutbound("target.example.com:443", proxyURL)
	if err != nil {
		t.Fatalf("DialOutbound with Basic auth challenge response failed: %v", err)
	}
	if conn == nil {
		t.Fatalf("Expected non-nil connection returned")
	}
	_ = conn.Close()
}

func TestForwarder_DialOutbound_HTTPSProxy(t *testing.T) {
	// Start an HTTPS proxy mock using httptest.NewTLSServer
	proxyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijack not supported", http.StatusInternalServerError)
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

			// Echo simple handshake test
			buf := make([]byte, 4)
			if _, err := io.ReadFull(conn, buf); err == nil {
				conn.Write(buf)
			}
			return
		}
		http.Error(w, "bad method", http.StatusBadRequest)
	}))
	defer proxyServer.Close()

	fwd := NewForwarder(true, 5)
	// Trust the self-signed cert of proxyServer
	fwd.SetTLSConfig(&tls.Config{
		InsecureSkipVerify: true,
	})

	conn, _, err := fwd.DialOutbound("secured.example.com:443", proxyServer.URL)
	if err != nil {
		t.Fatalf("DialOutbound via HTTPS upstream proxy failed: %v", err)
	}
	if conn == nil {
		t.Fatalf("Expected non-nil connection returned")
	}
	defer conn.Close()

	// Verify data flow over established tunnel
	testPayload := []byte("ping")
	if _, err := conn.Write(testPayload); err != nil {
		t.Fatalf("Write to tunnel failed: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Read from tunnel failed: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("Expected ping, got %s", string(buf))
	}
}

func TestSanitizeProxyURL(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{
			input:    "http://DOMAIN\\user:pass@proxy.corp:8080",
			expected: "http://DOMAIN%5Cuser:pass@proxy.corp:8080",
		},
		{
			input:    "http://CORP\\subdomain\\user:p@ssword@proxy:8080",
			expected: "http://CORP%5Csubdomain%5Cuser:p@ssword@proxy:8080",
		},
		{
			input:    "http://user:pass@proxy.corp:8080",
			expected: "http://user:pass@proxy.corp:8080",
		},
		{
			input:    "http://proxy.corp:8080",
			expected: "http://proxy.corp:8080",
		},
		{
			input:    "",
			expected: "",
		},
	}

	for _, tc := range testCases {
		got := SanitizeProxyURL(tc.input)
		if got != tc.expected {
			t.Errorf("SanitizeProxyURL(%q) = %q; want %q", tc.input, got, tc.expected)
		}
	}
}

func TestForwarder_FreshConnectionBasicRetry(t *testing.T) {
	// Simulate an upstream proxy that sends 407 and closes connection on unauthenticated request,
	// but accepts authenticated CONNECT on fresh connection.
	connectionCount := 0
	expectedUser := "testuser"
	expectedPass := "testpass"
	expectedToken := base64.StdEncoding.EncodeToString([]byte(expectedUser + ":" + expectedPass))

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connectionCount++
		auth := r.Header.Get("Proxy-Authorization")
		if auth != "Basic "+expectedToken {
			// Reject with 407 and close connection
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Corp\"")
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}

		// Accept authenticated CONNECT
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", 500)
			return
		}
		c, _, _ := hijacker.Hijack()
		defer c.Close()
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		buf := make([]byte, 4)
		io.ReadFull(c, buf)
		c.Write(buf)
	}))
	defer proxyServer.Close()

	proxyURL := fmt.Sprintf("http://%s:%s@%s", expectedUser, expectedPass, strings.TrimPrefix(proxyServer.URL, "http://"))
	fwd := NewForwarder(false, 5) // bypassSSPI = false

	conn, _, err := fwd.DialOutbound("target.domain:443", proxyURL)
	if err != nil {
		t.Fatalf("DialOutbound failed: %v", err)
	}
	defer conn.Close()

	// Verify echo over tunnel
	if _, err := conn.Write([]byte("echo")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf) != "echo" {
		t.Errorf("Expected 'echo', got %q", string(buf))
	}
}

type drainTrackingConn struct {
	r            *io.PipeReader
	w            *io.PipeWriter
	closed       bool
	closeWritten bool
	readDeadline time.Time
	mu           sync.Mutex
}

func (d *drainTrackingConn) Read(b []byte) (n int, err error) {
	return d.r.Read(b)
}

func (d *drainTrackingConn) Write(b []byte) (n int, err error) {
	return d.w.Write(b)
}

func (d *drainTrackingConn) Close() error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	_ = d.r.Close()
	_ = d.w.Close()
	return nil
}

func (d *drainTrackingConn) CloseWrite() error {
	d.mu.Lock()
	d.closeWritten = true
	d.mu.Unlock()
	return d.w.Close()
}

func (d *drainTrackingConn) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.readDeadline = t
	d.mu.Unlock()
	return nil
}

func (d *drainTrackingConn) SetDeadline(t time.Time) error      { return nil }
func (d *drainTrackingConn) SetWriteDeadline(t time.Time) error { return nil }
func (d *drainTrackingConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234} }
func (d *drainTrackingConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5678} }

func TestPipeConnEx_HalfCloseSafeDrain(t *testing.T) {
	// Verify that when client sends EOF (half-close), upstream connection (c2) gets a 60s safe drain deadline
	// Client <-> c1
	c1R, clientW := io.Pipe()
	clientR, c1W := io.Pipe()
	c1 := &drainTrackingConn{r: c1R, w: c1W}

	// c2 <-> Upstream Server
	serverR, c2W := io.Pipe()
	c2R, serverW := io.Pipe()
	c2 := &drainTrackingConn{r: c2R, w: c2W}

	done := make(chan struct{})
	go func() {
		// idleTimeout = 0 simulates permanent/interactive connection (e.g. SSH / long-polling)
		PipeConnEx(c1, c2, nil, nil, 0)
		close(done)
	}()

	// 1. Client writes request and closes its write end (half-close)
	_, _ = clientW.Write([]byte("request-payload"))
	_ = clientW.Close()

	// Upstream server reads request
	reqBuf := make([]byte, 15)
	_, _ = io.ReadFull(serverR, reqBuf)
	if string(reqBuf) != "request-payload" {
		t.Errorf("Upstream expected 'request-payload', got %q", string(reqBuf))
	}

	// Wait briefly for PipeConnEx to process client EOF
	time.Sleep(30 * time.Millisecond)

	// Verify that c2 had SetReadDeadline applied with ~60s safe drain timeout
	c2.mu.Lock()
	deadline := c2.readDeadline
	c2.mu.Unlock()

	if deadline.IsZero() {
		t.Errorf("Expected c2 to have a safe drain deadline set after client EOF, got zero time")
	} else {
		remaining := time.Until(deadline)
		if remaining < 50*time.Second || remaining > 70*time.Second {
			t.Errorf("Expected drain deadline ~60s in future, got %v", remaining)
		}
	}

	// 2. Upstream responds with answer and closes
	_, _ = serverW.Write([]byte("response-payload"))
	_ = serverW.Close()

	// Client reads response
	respBuf := make([]byte, 16)
	n, _ := clientR.Read(respBuf)
	if string(respBuf[:n]) != "response-payload" {
		t.Errorf("Client expected 'response-payload', got %q", string(respBuf[:n]))
	}

	select {
	case <-done:
		// Succeeded cleanly without deadlock
	case <-time.After(1 * time.Second):
		t.Fatalf("PipeConnEx deadlocked or hung after half-close completion")
	}
}


