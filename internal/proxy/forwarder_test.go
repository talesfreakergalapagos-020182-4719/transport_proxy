package proxy

import (
	"bytes"
	"io"
	"net"
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

	upBytes, downBytes := PipeConnEx(c1, u1, nil, nil, 1*time.Second)

	if upBytes != 14 {
		t.Errorf("expected upBytes 14, got %d", upBytes)
	}
	if downBytes != 12 {
		t.Errorf("expected downBytes 12, got %d", downBytes)
	}
	if c1.w.String() != "hello client" {
		t.Errorf("c1 did not receive hello client")
	}
	if u1.w.String() != "hello upstream" {
		t.Errorf("u1 did not receive hello upstream")
	}
}

func TestPipeConnEx_WithPrebuffer(t *testing.T) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	c1 := &dummyConn{r: r1, w: new(bytes.Buffer)}
	u1 := &dummyConn{r: r2, w: new(bytes.Buffer)}

	go func() {
		w1.Write([]byte("client"))
		w1.Close()
	}()

	go func() {
		w2.Write([]byte("stream"))
		w2.Close()
	}()

	preClient := bytes.NewReader([]byte("pre_"))
	preUpstream := bytes.NewReader([]byte("up_"))

	upBytes, downBytes := PipeConnEx(c1, u1, preClient, preUpstream, 1*time.Second)

	if upBytes != 10 {
		t.Errorf("expected upBytes 10, got %d", upBytes)
	}
	if downBytes != 9 {
		t.Errorf("expected downBytes 9, got %d", downBytes)
	}
	if c1.w.String() != "up_stream" {
		t.Errorf("c1 did not receive up_stream")
	}
	if u1.w.String() != "pre_client" {
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

	// タイムアウトを10秒に設定
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
