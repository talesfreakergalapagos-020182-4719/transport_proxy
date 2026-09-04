package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"transport_proxy/internal/logger"
	"transport_proxy/internal/sspi"
)

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 256*1024)
		return &b
	},
}

// OptimizeTCPConn tunes TCP socket buffer and low-latency flags.
var coarsePipeTime atomic.Int64

func init() {
	coarsePipeTime.Store(time.Now().UnixNano())
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for t := range ticker.C {
			coarsePipeTime.Store(t.UnixNano())
		}
	}()
}

func OptimizeTCPConn(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
		// Note: We intentionally avoid setting fixed small SO_RCVBUF/SO_SNDBUF here so Windows
		// TCP Receive Window Auto-Tuning can scale dynamically up to multiple megabytes on high-speed/high-latency links.
	}
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	} else if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

// Forwarder manages outbound connections either directly or through a proxy.
type Forwarder struct {
	bypassSSPI     bool
	connectTimeout time.Duration
}

// NewForwarder creates a new Forwarder instance.
func NewForwarder(bypassSSPI bool, connectTimeoutSec int) *Forwarder {
	timeout := time.Duration(connectTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	return &Forwarder{
		bypassSSPI:     bypassSSPI,
		connectTimeout: timeout,
	}
}

// DialOutbound connects to the target address either directly (if proxyURL is empty)
// or tunnels through the specified proxyURL with optional SSPI authentication.
func (f *Forwarder) DialOutbound(targetAddr string, proxyURLStr string) (net.Conn, io.Reader, error) {
	if proxyURLStr == "" {
		// Direct outbound connection using reserved outbound port range
		conn, err := f.dialTCP("tcp", targetAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("direct dial to %s failed: %w", targetAddr, err)
		}
		return conn, nil, nil
	}

	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURLStr, err)
	}

	proxyHostPort := proxyURL.Host
	if proxyURL.Port() == "" {
		if proxyURL.Scheme == "https" {
			proxyHostPort = net.JoinHostPort(proxyURL.Hostname(), "443")
		} else {
			proxyHostPort = net.JoinHostPort(proxyURL.Hostname(), "8080")
		}
	}

	proxyConn, err := f.dialTCP("tcp", proxyHostPort)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to proxy %s failed: %w", proxyHostPort, err)
	}

	if f.bypassSSPI {
		// Standard HTTP CONNECT without SSPI auto-negotiation (supports Basic auth if credentials provided)
		authHeader := ""
		if proxyURL.User != nil {
			username := proxyURL.User.Username()
			password, _ := proxyURL.User.Password()
			token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
			authHeader = fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", token)
		}

		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n%s\r\n", targetAddr, targetAddr, authHeader)
		if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
			_ = proxyConn.Close()
			return nil, nil, fmt.Errorf("failed to send CONNECT request: %w", err)
		}

		reader := bufio.NewReader(proxyConn)
		resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		if err != nil {
			_ = proxyConn.Close()
			return nil, nil, fmt.Errorf("failed to read proxy response: %w", err)
		}
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_ = proxyConn.Close()
			return nil, nil, fmt.Errorf("proxy returned non-200 response: %s", resp.Status)
		}

		return proxyConn, reader, nil
	}

	// Automatic authentication (SSPI Windows SSO + Basic auth fallback/native)
	reader, err := sspi.AuthenticateProxyTunnel(proxyConn, targetAddr, proxyURL, f.connectTimeout)
	if err != nil {
		_ = proxyConn.Close()
		return nil, nil, fmt.Errorf("proxy tunnel authentication failed for %s: %w", proxyHostPort, err)
	}

	return proxyConn, reader, nil
}

// PipeStats holds transfer statistics.
type PipeStats struct {
	BytesClientToUpstream atomic.Int64
	BytesUpstreamToClient atomic.Int64
}

// FormatBytes formats byte count to human readable format (e.g. 1.2 KB, 3.4 MB).
func FormatBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(1024), 0
	for n := b / 1024; n >= 1024; n /= 1024 {
		div *= 1024
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// PipeConn copies data bidirectionally between client and upstream connections with half-close support.
func PipeConn(c1 net.Conn, c2 net.Conn, preBuffered io.Reader, idleTimeout time.Duration) (int64, int64) {
	return PipeConnEx(c1, c2, nil, preBuffered, idleTimeout)
}

// PipeConnEx copies data bidirectionally between client and upstream connections, supporting pre-buffered readers on both ends.
func PipeConnEx(c1 net.Conn, c2 net.Conn, clientPreBuffered io.Reader, upstreamPreBuffered io.Reader, idleTimeout time.Duration) (int64, int64) {
	OptimizeTCPConn(c1)
	OptimizeTCPConn(c2)

	var stats PipeStats
	var wg sync.WaitGroup
	wg.Add(2)

	isPermanent := idleTimeout <= 0
	var deadlineRefreshInterval time.Duration
	if isPermanent {
		deadlineRefreshInterval = 0
	} else {
		deadlineRefreshInterval = idleTimeout / 4
		if deadlineRefreshInterval > 30*time.Second {
			deadlineRefreshInterval = 30 * time.Second
		} else if deadlineRefreshInterval < 5*time.Second && idleTimeout > 5*time.Second {
			deadlineRefreshInterval = 5 * time.Second
		}
	}

	c1AddrStr := c1.RemoteAddr().String()
	c2AddrStr := c2.RemoteAddr().String()

	var lastActivity atomic.Int64
	lastActivity.Store(coarsePipeTime.Load())

	// 1. Upstream -> Client (c2 -> c1)
	go func() {
		var localBytes int64
		defer func() {
			if localBytes > 0 {
				stats.BytesUpstreamToClient.Add(localBytes)
			}
			wg.Done()
		}()
		defer func() {
			if r := recover(); r != nil {
				if logger.IsVerbose() { logger.Debugf("[PIPE-DOWN] Panic recovered: %v", r) }
			}
		}()

		var src io.Reader = c2
		if upstreamPreBuffered != nil {
			if br, ok := upstreamPreBuffered.(*bufio.Reader); ok && br != nil {
				src = upstreamPreBuffered
			} else {
				src = io.MultiReader(upstreamPreBuffered, c2)
			}
		}

		bufPtr := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(bufPtr)
		buf := *bufPtr

		if logger.IsVerbose() { logger.Debugf("[PIPE-DOWN] Started: Upstream (%s) -> Client (%s)", c2AddrStr, c1AddrStr) }
		
		var lastDeadline time.Time
		updateDeadline := func(nowNano int64) {
			if !isPermanent {
				now := time.Unix(0, nowNano)
				if now.Sub(lastDeadline) > deadlineRefreshInterval {
					_ = c2.SetReadDeadline(now.Add(idleTimeout))
					lastDeadline = now
				}
			}
		}
	if !isPermanent {
		updateDeadline(coarsePipeTime.Load())
	}

		for {
			nr, er := src.Read(buf)
			if nr > 0 {
				now := coarsePipeTime.Load()
				lastActivity.Store(now)
				if !isPermanent {
					updateDeadline(now)
				}
				nw, ew := c1.Write(buf[0:nr])
				if nw > 0 {
					localBytes += int64(nw)
				}
				if ew != nil {
					if logger.IsVerbose() { logger.Debugf("[PIPE-DOWN] Write to client %s failed: %v", c1AddrStr, ew) }
					_ = c1.Close()
					_ = c2.Close()
					return
				}
				if nr != nw {
					if logger.IsVerbose() { logger.Debugf("[PIPE-DOWN] Short write to client: read=%d, wrote=%d", nr, nw) }
					_ = c1.Close()
					_ = c2.Close()
					return
				}
			}
			if er != nil {
				if logger.IsVerbose() { logger.Debugf("[PIPE-DOWN] Upstream read ended (c2=%s): %v", c2AddrStr, er) }
				if netErr, ok := er.(net.Error); ok && netErr.Timeout() {
					elapsed := time.Duration(time.Now().UnixNano() - lastActivity.Load())
					if elapsed < idleTimeout {
						updateDeadline(time.Now().UnixNano())
						continue
					}
					closeWrite(c1)
				} else if er == io.EOF {
					closeWrite(c1)
				} else {
					_ = c1.Close()
					_ = c2.Close()
				}
				return
			}
		}
	}()

	// 2. Client -> Upstream (c1 -> c2)
	go func() {
		var localBytes int64
		defer func() {
			if localBytes > 0 {
				stats.BytesClientToUpstream.Add(localBytes)
			}
			wg.Done()
		}()
		defer func() {
			if r := recover(); r != nil {
				if logger.IsVerbose() { logger.Debugf("[PIPE-UP] Panic recovered: %v", r) }
			}
		}()

		var clientSrc io.Reader = c1
		if clientPreBuffered != nil {
			if br, ok := clientPreBuffered.(*bufio.Reader); ok && br != nil {
				clientSrc = clientPreBuffered
			} else {
				clientSrc = io.MultiReader(clientPreBuffered, c1)
			}
		}

		bufPtr := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(bufPtr)
		buf := *bufPtr

		if logger.IsVerbose() { logger.Debugf("[PIPE-UP] Started: Client (%s) -> Upstream (%s)", c1AddrStr, c2AddrStr) }
		
		var lastDeadline time.Time
		updateDeadline := func(nowNano int64) {
			if !isPermanent {
				now := time.Unix(0, nowNano)
				if now.Sub(lastDeadline) > deadlineRefreshInterval {
					_ = c1.SetReadDeadline(now.Add(idleTimeout))
					lastDeadline = now
				}
			}
		}
		if !isPermanent {
			updateDeadline(coarsePipeTime.Load())
		}

		for {
			nr, er := clientSrc.Read(buf)
			if nr > 0 {
				now := coarsePipeTime.Load()
				lastActivity.Store(now)
				if !isPermanent {
					updateDeadline(now)
				}
				nw, ew := c2.Write(buf[0:nr])
				if nw > 0 {
					localBytes += int64(nw)
				}
				if ew != nil {
					if logger.IsVerbose() { logger.Debugf("[PIPE-UP] Write to upstream %s failed: %v", c2AddrStr, ew) }
					_ = c1.Close()
					_ = c2.Close()
					return
				}
				if nr != nw {
					if logger.IsVerbose() { logger.Debugf("[PIPE-UP] Short write to upstream: read=%d, wrote=%d", nr, nw) }
					_ = c1.Close()
					_ = c2.Close()
					return
				}
			}
			if er != nil {
				if logger.IsVerbose() { logger.Debugf("[PIPE-UP] Client read ended (c1=%s): %v", c1AddrStr, er) }
				if netErr, ok := er.(net.Error); ok && netErr.Timeout() {
					elapsed := time.Duration(time.Now().UnixNano() - lastActivity.Load())
					if elapsed < idleTimeout {
						updateDeadline(time.Now().UnixNano())
						continue
					}
					closeWrite(c2)
				} else if er == io.EOF {
					closeWrite(c2)
				} else {
					_ = c1.Close()
					_ = c2.Close()
				}
				return
			}
		}
	}()

	wg.Wait()
	_ = c1.Close()
	_ = c2.Close()
	if logger.IsVerbose() {
		logger.Debugf("[PIPE] PipeConn finished for Client: %s <-> Upstream: %s (Client->Up: %d B, Up->Client: %d B)",
			c1AddrStr, c2AddrStr, stats.BytesClientToUpstream.Load(), stats.BytesUpstreamToClient.Load())
	}

	return stats.BytesClientToUpstream.Load(), stats.BytesUpstreamToClient.Load()
}
