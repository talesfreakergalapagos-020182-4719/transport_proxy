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

