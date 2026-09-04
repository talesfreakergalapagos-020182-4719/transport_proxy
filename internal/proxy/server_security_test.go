package proxy

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type dummyAddr struct {
	addr string
}

func (d dummyAddr) Network() string { return "tcp" }
func (d dummyAddr) String() string  { return d.addr }

func TestProxy_IsAuthorizedLocalClient(t *testing.T) {
	// Loopback clients should always be authorized
	if !isAuthorizedLocalClient(dummyAddr{addr: "127.0.0.1:54321"}) {
		t.Errorf("Expected 127.0.0.1 to be authorized")
	}
	if !isAuthorizedLocalClient(dummyAddr{addr: "[::1]:54321"}) {
		t.Errorf("Expected [::1] to be authorized")
	}

	// External / public IPs must be blocked
	if isAuthorizedLocalClient(dummyAddr{addr: "198.51.100.25:54321"}) {
		t.Errorf("Expected public IP 198.51.100.25 to be rejected")
	}
	if isAuthorizedLocalClient(dummyAddr{addr: "203.0.113.50:80"}) {
		t.Errorf("Expected public IP 203.0.113.50 to be rejected")
	}

	// Malformed address
	if isAuthorizedLocalClient(dummyAddr{addr: "not-an-ip"}) {
		t.Errorf("Expected invalid address to be rejected")
	}
}

func TestProxy_FormatBytes_EdgeCases(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		got := FormatBytes(tt.bytes)
		if got != tt.expected {
			t.Errorf("FormatBytes(%d) = %q, expected %q", tt.bytes, got, tt.expected)
		}
	}
}

func TestProxy_AcquireListener_PortCollisionFallback(t *testing.T) {
	// 1. Bind all-interfaces wildcard port first to guarantee collision with AcquireListener's default hostPrefix
	firstListener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to listen on initial port: %v", err)
	}
	defer firstListener.Close()

	_, portStr, err := net.SplitHostPort(firstListener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort failed: %v", err)
	}
	occupiedPort, _ := strconv.Atoi(portStr)

	// 2. Try AcquireListener on that same occupied port
	// It should detect collision and automatically acquire occupiedPort + 1 (or next available)
	secondListener, acquiredPort, err := AcquireListener("0.0.0.0:" + portStr)
	if err != nil {
		t.Fatalf("AcquireListener failed to find alternative port: %v", err)
	}
	defer secondListener.Close()

	if int(acquiredPort) == occupiedPort {
		t.Errorf("AcquireListener returned occupied port %d, should have fallen back", occupiedPort)
	}

	if acquiredPort == 0 {
		t.Errorf("AcquireListener returned 0 port")
	}
	t.Logf("AcquireListener correctly fell back from %d to %d", occupiedPort, acquiredPort)
}

func TestProxy_PipeConnEx_PreBufferedBothEnds(t *testing.T) {
	// Simulate proxy in the middle:
	// Client End <----> (clientConn) PROXY (upstreamConn) <----> Upstream Server End
	clientEnd, clientConn := net.Pipe()
	defer clientEnd.Close()
	defer clientConn.Close()

	upstreamConn, serverEnd := net.Pipe()
	defer upstreamConn.Close()
	defer serverEnd.Close()

	clientPre := bytes.NewReader([]byte("CLIENT_PRE_DATA;"))
	upstreamPre := bytes.NewReader([]byte("UPSTREAM_PRE_DATA;"))

	var wg sync.WaitGroup
	var clientReceived bytes.Buffer
	var serverReceived bytes.Buffer

	// PipeConnEx relays between clientConn and upstreamConn
	wg.Add(1)
	go func() {
		defer wg.Done()
		PipeConnEx(clientConn, upstreamConn, clientPre, upstreamPre, 2*time.Second)
	}()

	// Simulating client reading from clientEnd
	clientErrChan := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := clientEnd.Read(buf)
		if err != nil && err != io.EOF {
			clientErrChan <- err
			return
		}
		clientReceived.Write(buf[:n])
		_, _ = clientEnd.Write([]byte("CLIENT_STREAM_DATA"))
		_ = clientEnd.Close()
		clientErrChan <- nil
	}()

	// Simulating server reading from serverEnd
	serverErrChan := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := serverEnd.Read(buf)
		if err != nil && err != io.EOF {
			serverErrChan <- err
			return
		}
		serverReceived.Write(buf[:n])
		_, _ = serverEnd.Write([]byte("UPSTREAM_STREAM_DATA"))
		_ = serverEnd.Close()
		serverErrChan <- nil
	}()

	wg.Wait()

	if err := <-clientErrChan; err != nil {
		t.Fatalf("Client reader error: %v", err)
	}
	if err := <-serverErrChan; err != nil {
		t.Fatalf("Server reader error: %v", err)
	}

	// Verify client received the upstream pre-buffered data
	if !strings.Contains(clientReceived.String(), "UPSTREAM_PRE_DATA") {
		t.Errorf("Client did not receive UPSTREAM_PRE_DATA, got: %q", clientReceived.String())
	}

	// Verify server received the client pre-buffered data
	if !strings.Contains(serverReceived.String(), "CLIENT_PRE_DATA") {
		t.Errorf("Server did not receive CLIENT_PRE_DATA, got: %q", serverReceived.String())
	}
}
