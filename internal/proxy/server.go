package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"transport_proxy/internal/config"
	"transport_proxy/internal/filter"
	"transport_proxy/internal/interceptor"
	"transport_proxy/internal/logger"
	"transport_proxy/internal/pac"
)

// Server represents the transparent TCP proxy server.
type Server struct {
	listener    net.Listener
	cfgMgr      *config.Manager
	filterEng   *filter.Engine
	redirector  *interceptor.Redirector
	pacResolver *pac.Resolver
	activeConns sync.WaitGroup
	mu          sync.Mutex
	closed      bool
}

// NewServer creates a new transparent proxy server.
func NewServer(cfgMgr *config.Manager, filterEng *filter.Engine, redirector *interceptor.Redirector, pacResolver *pac.Resolver) *Server {
	return &Server{
		cfgMgr:      cfgMgr,
		filterEng:   filterEng,
		redirector:  redirector,
		pacResolver: pacResolver,
	}
}

// AcquireListener attempts to bind to preferredAddr (e.g. ":18080").
// If the preferred port is occupied by another process, it identifies the occupying process,
// issues a warning, and automatically searches for an available fallback port (18081, 18082, ...).
func AcquireListener(preferredAddr string) (net.Listener, uint16, error) {
	listenHost, portStr, err := net.SplitHostPort(preferredAddr)
	if err != nil {
		listenHost = ""
		portStr = "18080"
	}
	preferredPort := 18080
	if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
		preferredPort = p
	}

	hostPrefix := ":"
	if listenHost != "" && listenHost != "127.0.0.1" && listenHost != "0.0.0.0" && listenHost != "localhost" {
		hostPrefix = listenHost + ":"
	}

	// 1. Try preferred port first
	firstAddr := fmt.Sprintf("%s%d", hostPrefix, preferredPort)
	listener, err := net.Listen("tcp", firstAddr)
	if err == nil {
		return listener, uint16(preferredPort), nil
	}

	// Preferred port is in use: find who is using it
	procInfo, _ := interceptor.FindProcessUsingPort(uint16(preferredPort))
	if procInfo != nil {
		log.Printf("================================================================================")
		log.Printf("[WARNING] Preferred proxy listen port %d is already in use by process '%s' (PID %d)!",
			preferredPort, procInfo.ProcessName, procInfo.PID)
		if procInfo.ProcessPath != "" {
			log.Printf("[WARNING] Process Path: %s", procInfo.ProcessPath)
		}
		log.Printf("[WARNING] Automatically searching for an alternative available port...")
		log.Printf("================================================================================")
	} else {
		log.Printf("[WARNING] Preferred proxy listen port %d is already in use (%v). Searching for alternative port...",
			preferredPort, err)
	}

	// 2. Search fallback ports (e.g. 18081 to 18180)
	const maxFallbackAttempts = 100
	for offset := 1; offset <= maxFallbackAttempts; offset++ {
		candidatePort := preferredPort + offset
		if candidatePort > 65535 {
			candidatePort = 18000 + offset
		}
		// Avoid proxy outbound reserved port range (40000-48999)
		if candidatePort >= int(config.OutboundPortMin) && candidatePort <= int(config.OutboundPortMax) {
			continue
		}

		candidateAddr := fmt.Sprintf("%s%d", hostPrefix, candidatePort)
		ln, err := net.Listen("tcp", candidateAddr)
		if err == nil {
			log.Printf("[ProxyServer] Successfully switched to alternative listen port %d (Dual-Stack IPv4/IPv6).", candidatePort)
			return ln, uint16(candidatePort), nil
		}
	}

	return nil, 0, fmt.Errorf("failed to find an available listen port after %d attempts (starting from %d): %w",
		maxFallbackAttempts, preferredPort, err)
}

// StartWithListener begins accepting connections on an already-bound listener.
func (s *Server) StartWithListener(ctx context.Context, listener net.Listener) error {
	s.listener = listener
	log.Printf("[ProxyServer] Transparent proxy listening on %s (Dual-Stack IPv4/IPv6)", listener.Addr().String())

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[ProxyServer] CRITICAL: Recovered from panic in accept loop: %v", r)
			}
		}()

		for {
			conn, err := s.listener.Accept()
			if err != nil {
				s.mu.Lock()
				isClosed := s.closed
				s.mu.Unlock()
				if isClosed {
					return
				}
				log.Printf("[ProxyServer] Accept error: %v", err)
				time.Sleep(5 * time.Millisecond)
				continue
			}

			s.activeConns.Add(1)
			go func(c net.Conn) {
				defer s.activeConns.Done()
				s.handleClient(ctx, c)
			}(conn)
		}
	}()

	return nil
}

// Start begins listening on the configured local address (with automatic port fallback) and accepting connections.
func (s *Server) Start(ctx context.Context) error {
	cfg := s.cfgMgr.Get()
	listener, _, err := AcquireListener(cfg.ListenAddr)
	if err != nil {
		return err
	}
	return s.StartWithListener(ctx, listener)
}

// handleClient processes a transparently intercepted client connection.
func (s *Server) handleClient(ctx context.Context, clientConn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[ProxyServer] Recovered from panic in client connection handler: %v", r)
		}
	}()

	defer func() {
		_ = clientConn.Close()
	}()

	cfg := s.cfgMgr.Get()
	connectTimeout := time.Duration(cfg.ConnectTimeoutSec) * time.Second
	idleTimeout := time.Duration(cfg.IdleTimeoutSec) * time.Second

	OptimizeTCPConn(clientConn)

	// 1. Resolve original destination from NAT table
	origIP, origPort, found := s.redirector.LookupOriginalDestination(clientConn.RemoteAddr())
	if !found {
		// Connection arrived without NAT tracking (e.g. direct curl to local proxy port)
		log.Printf("[ProxyServer] Unknown original destination for %s (no NAT session)", clientConn.RemoteAddr())
		return
	}
	logger.Debugf("[DEBUG] Connection accepted: Client %s -> Original Target %s", clientConn.RemoteAddr(), net.JoinHostPort(origIP.String(), strconv.Itoa(int(origPort))))

	targetAddr := net.JoinHostPort(origIP.String(), strconv.Itoa(int(origPort)))

	forwarder := NewForwarder(cfg.BypassSSPI, cfg.ConnectTimeoutSec)

	// Asynchronous Speculative Pre-Dialing:
	// Concurrently start dialing targetAddr in the background while inspecting initial client payload (peek).
	// This overlaps TCP 3-way handshake time with client ClientHello wait time, drastically reducing connection latency.
	type preDialResult struct {
		conn        net.Conn
		preBuffered io.Reader
		err         error
	}
	preDialChan := make(chan preDialResult, 1)
	preDialCtx, cancelPreDial := context.WithCancel(ctx)
	defer cancelPreDial()

	go func() {
		conn, preBuf, dialErr := forwarder.DialOutbound(targetAddr, "")
		select {
		case preDialChan <- preDialResult{conn: conn, preBuffered: preBuf, err: dialErr}:
		case <-preDialCtx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()

	var initialData []byte
	var isWeb bool
	var protoType string
	var targetDomain string

	if isServerFirstPort(origPort) {
		// Server-first protocol: Client waits for server banner, so skip peek to eliminate 100ms connection delay
		isWeb = false
		protoType = "RAW_TCP"
		targetDomain = ""
	} else {
		// 2. Read initial data chunk with fast peek timeout (50ms) to detect TLS SNI or HTTP Host.
		// For client-first protocols (HTTP/TLS), client sends data immediately (<1ms).
		peekTimeout := 50 * time.Millisecond
		_ = clientConn.SetReadDeadline(time.Now().Add(peekTimeout))
		peekBuf := make([]byte, 4096)
		n, readErr := clientConn.Read(peekBuf)
		_ = clientConn.SetReadDeadline(time.Time{})

		if readErr != nil && n == 0 {
			if netErr, ok := readErr.(net.Error); !ok || !netErr.Timeout() {
				// Client disconnected immediately (e.g. EOF or RST) without sending data
				logger.Debugf("[ProxyServer] Client %s disconnected early before sending data: %v", clientConn.RemoteAddr(), readErr)
				return
			}
		}

		if n > 0 {
			initialData = peekBuf[:n]
		}

		// L7 Protocol Signature Inspection (inspect headers without full payload decryption)
		isWeb, protoType, targetDomain = interceptor.IsHTTPOrHTTPS(initialData)
		logger.Debugf("[DEBUG] Payload inspection: Protocol=%s, SNI/Host=%q (Read %d bytes)", protoType, targetDomain, len(initialData))
	}

	startTime := time.Now()

	// 3. Evaluate filtering rules (Whitelist / Blacklist) - ALWAYS active for all protocols & destinations
	targetHostToCheck := targetDomain
	if targetHostToCheck == "" {
		targetHostToCheck = origIP.String()
	}

	targetDisplay := targetAddr
	if targetDomain != "" {
		targetDisplay = net.JoinHostPort(targetDomain, strconv.Itoa(int(origPort)))
	}

	if s.filterEng.ShouldBlock(targetHostToCheck) {
		log.Printf("[BLOCK] %-7s | Client: %-21s | Target: %-30s -> Blocked by policy",
			protoType, clientConn.RemoteAddr(), targetDisplay)
		return // Dropping connection sends FIN/RST to client (pre-dialed connection cleaned up by cancelPreDial)
	}

	// If domain was identified, prefer domain:port for upstream CONNECT
	dialTarget := targetAddr
	if targetDomain != "" {
		hostOnly := targetDomain
		if h, _, err := net.SplitHostPort(targetDomain); err == nil {
			hostOnly = h
		}
		dialTarget = net.JoinHostPort(hostOnly, strconv.Itoa(int(origPort)))
	}

	// 4. Resolve proxy decision via PAC / static configuration
	decision, err := s.pacResolver.Resolve(targetHostToCheck, origPort)
	if err != nil {
		log.Printf("[ProxyServer] Routing resolution error for %s: %v", targetHostToCheck, err)
		decision = pac.ProxyDecision{IsDirect: true}
	}

	// Dynamic Protocol Dispatch:
	// - Web traffic (HTTP / HTTPS) with upstream proxy configured -> PROXY (CONNECT / HTTP forward)
	// - Non-Web traffic (SSH, RDP, DB, custom TCP) or no upstream proxy -> DIRECT (transparent relay)
	proxyToUse := ""
	targetToDial := targetAddr
	if isWeb && !decision.IsDirect && decision.ProxyURL != "" {
		proxyToUse = decision.ProxyURL
		targetToDial = dialTarget
		log.Printf("[ALLOW] %-7s | Client: %-21s | Target: %-30s -> PROXY (%s)",
			protoType, clientConn.RemoteAddr(), targetDisplay, proxyToUse)
	} else {
		proxyToUse = ""
		targetToDial = targetAddr
		log.Printf("[ALLOW] %-7s | Client: %-21s | Target: %-30s -> DIRECT",
			protoType, clientConn.RemoteAddr(), targetDisplay)
	}

	// 5. Connect to upstream: Reuse pre-dialed DIRECT connection or dial configured upstream proxy
	var outConn net.Conn
	var preBuffered io.Reader

	if proxyToUse == "" {
		// DIRECT connection: obtain result from asynchronous pre-dial
		res := <-preDialChan
		if res.err != nil {
			log.Printf("[ERROR] Outbound direct dial failed for %s: %v", targetToDial, res.err)
			return
		}
		outConn = res.conn
		preBuffered = res.preBuffered
	} else {
		// PROXY connection: cancel direct pre-dial and connect to upstream proxy
		cancelPreDial()
		logger.Debugf("[DEBUG] Dialing upstream proxy %s for target %s...", proxyToUse, targetToDial)
		var dialErr error
		outConn, preBuffered, dialErr = forwarder.DialOutbound(targetToDial, proxyToUse)
		if dialErr != nil {
			log.Printf("[ERROR] Outbound proxy dial failed for %s (Proxy: %q): %v", targetToDial, proxyToUse, dialErr)
			return
		}
	}

	logger.Debugf("[DEBUG] Upstream connection established successfully (Local: %s -> Remote: %s)", outConn.LocalAddr(), outConn.RemoteAddr())
	defer func() {
		_ = outConn.Close()
	}()

	// 6. Forward the initial payload that was read for SNI/Host inspection
	if len(initialData) > 0 {
		_ = outConn.SetWriteDeadline(time.Now().Add(connectTimeout))
		if _, err := outConn.Write(initialData); err != nil {
			log.Printf("[ERROR] Failed to write initial payload to %s: %v", targetToDial, err)
			return
		}
		_ = outConn.SetWriteDeadline(time.Time{})
		logger.Debugf("[DEBUG] Initial payload (%d bytes) sent to upstream %s", len(initialData), targetToDial)
	}

	// 7. Bidirectional forwarding pipe
	logger.Debugf("[DEBUG] Starting bidirectional data relay...")
	bytesClientToUp, bytesUpToClient := PipeConn(clientConn, outConn, preBuffered, idleTimeout)
	duration := time.Since(startTime).Round(time.Millisecond)
	totalSent := bytesClientToUp + int64(len(initialData))

	log.Printf("[CLOSE] Client: %-21s | Target: %-30s | Sent: %-8s | Recv: %-8s | Duration: %v",
		clientConn.RemoteAddr(), targetDisplay,
		FormatBytes(totalSent), FormatBytes(bytesUpToClient),
		duration)
}

// Close gracefully stops the proxy server and waits for active connections to finish.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}

	// Wait with timeout for active connections
	done := make(chan struct{})
	go func() {
		s.activeConns.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		log.Printf("[ProxyServer] Timeout waiting for active connections to drain")
	}

	return err
}

// isServerFirstPort returns true for well-known server-first TCP services where the server
// sends a greeting banner before the client sends any data. For these protocols, waiting for
// client data (peek) would introduce an unneeded 100ms connection delay.
func isServerFirstPort(port uint16) bool {
	switch port {
	case 21, // FTP
		22,    // SSH
		23,    // Telnet
		25,    // SMTP
		110,   // POP3
		143,   // IMAP
		587,   // Submission
		993,   // IMAPS
		995,   // POP3S
		1433,  // MSSQL
		1521,  // Oracle
		3306,  // MySQL / MariaDB
		3389,  // RDP
		5432,  // PostgreSQL
		5900,  // VNC
		6379,  // Redis
		27017: // MongoDB
		return true
	default:
		return false
	}
}
