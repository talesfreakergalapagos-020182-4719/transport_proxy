package proxy

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
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
	var origIP net.IP
	var origPort uint16
	var found bool
	if s.redirector != nil {
		origIP, origPort, found = s.redirector.LookupOriginalDestination(clientConn.RemoteAddr())
	}
	if !found {
		// Connection arrived without NAT tracking (explicit forward proxy connection, e.g. curl -x http://127.0.0.1:18080)
		s.handleExplicitProxyClient(ctx, clientConn)
		return
	}
	logger.Debugf("[DEBUG] Connection accepted: Client %s -> Original Target %s", clientConn.RemoteAddr(), net.JoinHostPort(origIP.String(), strconv.Itoa(int(origPort))))

	targetAddr := net.JoinHostPort(origIP.String(), strconv.Itoa(int(origPort)))

	forwarder := NewForwarder(cfg.BypassSSPI, cfg.ConnectTimeoutSec)

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
		return // Dropping connection sends FIN/RST to client
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

	// 5. Connect to upstream (DIRECT or configured upstream PROXY)
	logger.Debugf("[DEBUG] Dialing upstream for target %s (Proxy: %q)...", targetToDial, proxyToUse)
	outConn, preBuffered, dialErr := forwarder.DialOutbound(targetToDial, proxyToUse)
	if dialErr != nil {
		log.Printf("[ERROR] Outbound dial failed for %s (Proxy: %q): %v", targetToDial, proxyToUse, dialErr)
		return
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
	// 7. Bidirectional forwarding pipe
	logger.Debugf("[DEBUG] Starting bidirectional data relay...")
	// Determine appropriate idle timeout:
	// For interactive protocols (RDP, SSH, VNC, DB, TeamViewer, AnyDesk, Cloud VDI) or if explicitly disabled (cfg.IdleTimeoutSec <= 0),
	// disable the read deadline (idleTimeout = 0) and rely on OS TCP Keep-Alive (30s) so idle sessions never drop!
	connIdleTimeout := idleTimeout
	if cfg.IdleTimeoutSec <= 0 || isInteractiveService(protoType, origPort, targetDomain) {
		connIdleTimeout = 0
	}
	bytesClientToUp, bytesUpToClient := PipeConn(clientConn, outConn, preBuffered, connIdleTimeout)
	duration := time.Since(startTime).Round(time.Millisecond)
	totalSent := bytesClientToUp + int64(len(initialData))

	log.Printf("[CLOSE] Client: %-21s | Target: %-30s | Sent: %-8s | Recv: %-8s | Duration: %v",
		clientConn.RemoteAddr(), targetDisplay,
		FormatBytes(totalSent), FormatBytes(bytesUpToClient),
		duration)
}

var (
	localSubnetsCache   []*net.IPNet
	localIPsCache       []net.IP
	localSubnetCacheMut sync.RWMutex
	lastCacheUpdate     time.Time
)

func updateLocalInterfaceCache() {
	localSubnetCacheMut.Lock()
	defer localSubnetCacheMut.Unlock()

	if time.Since(lastCacheUpdate) < 30*time.Second && (len(localIPsCache) > 0 || len(localSubnetsCache) > 0) {
		return
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}

	var ips []net.IP
	var subnets []*net.IPNet

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		isVirtualWSL := strings.Contains(strings.ToLower(iface.Name), "wsl") ||
			strings.Contains(strings.ToLower(iface.Name), "hyper-v") ||
			strings.Contains(strings.ToLower(iface.Name), "vethernet")

		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok {
				ips = append(ips, ipNet.IP)
				if isVirtualWSL {
					subnets = append(subnets, ipNet)
				}
			}
		}
	}

	localIPsCache = ips
	localSubnetsCache = subnets
	lastCacheUpdate = time.Now()
}

// isAuthorizedLocalClient checks if the client connection originates from the local host or WSL.
func isAuthorizedLocalClient(remoteAddr net.Addr) bool {
	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		host = remoteAddr.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	// 1. Loopback addresses (127.0.0.1, ::1) -> Localhost and WSL Mirrored mode (0 alloc, <1ns)
	if ip.IsLoopback() {
		return true
	}

	// 2. Check cached local network interfaces
	updateLocalInterfaceCache()

	localSubnetCacheMut.RLock()
	defer localSubnetCacheMut.RUnlock()

	for _, localIP := range localIPsCache {
		if localIP.Equal(ip) {
			return true
		}
	}
	for _, subnet := range localSubnetsCache {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// handleExplicitProxyClient handles explicit HTTP and HTTPS CONNECT proxy requests (e.g. from WSL via http_proxy).
func (s *Server) handleExplicitProxyClient(ctx context.Context, clientConn net.Conn) {
	// Security Check: Only allow explicit proxy connections originating from local host or WSL
	if !isAuthorizedLocalClient(clientConn.RemoteAddr()) {
		log.Printf("[BLOCK] EXPLICIT PROXY | Client: %-21s -> Blocked: unauthorized external client (only localhost/WSL allowed)",
			clientConn.RemoteAddr())
		_, _ = clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nAccess denied: proxy is restricted to local host and WSL\n"))
		return
	}

	cfg := s.cfgMgr.Get()
	connectTimeout := time.Duration(cfg.ConnectTimeoutSec) * time.Second
	idleTimeout := time.Duration(cfg.IdleTimeoutSec) * time.Second

	// Set initial read deadline for HTTP request header
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	clientReader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(clientReader)
	_ = clientConn.SetReadDeadline(time.Time{})

	if err != nil {
		logger.Debugf("[ProxyServer] Direct connection from %s failed to parse as HTTP request: %v", clientConn.RemoteAddr(), err)
		return
	}

	startTime := time.Now()
	forwarder := NewForwarder(cfg.BypassSSPI, cfg.ConnectTimeoutSec)

	if req.Method == http.MethodConnect {
		// ----------------------------------------------------
		// Explicit HTTPS Proxy Tunnel (CONNECT host:port HTTP/1.1)
		// ----------------------------------------------------
		target := req.RequestURI
		if target == "" {
			target = req.Host
		}

		targetHost, portStr, err := net.SplitHostPort(target)
		var targetPort uint16 = 443
		if err != nil {
			targetHost = target
		} else {
			if p, pErr := strconv.Atoi(portStr); pErr == nil && p > 0 && p <= 65535 {
				targetPort = uint16(p)
			}
		}
		targetDisplay := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

		// 1. Policy check (Whitelist / Blacklist)
		if s.filterEng.ShouldBlock(targetHost) {
			log.Printf("[BLOCK] HTTPS (EXPLICIT) | Client: %-21s | Target: %-30s -> Blocked by policy",
				clientConn.RemoteAddr(), targetDisplay)
			_, _ = clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBlocked by policy\n"))
			return
		}

		// 2. Resolve proxy decision via PAC / static configuration
		decision, err := s.pacResolver.Resolve(targetHost, targetPort)
		if err != nil {
			logger.Debugf("[ProxyServer] Routing resolution error for %s: %v", targetHost, err)
			decision = pac.ProxyDecision{IsDirect: true}
		}

		proxyToUse := ""
		if !decision.IsDirect && decision.ProxyURL != "" {
			proxyToUse = decision.ProxyURL
			log.Printf("[ALLOW] HTTPS (EXPLICIT) | Client: %-21s | Target: %-30s -> PROXY (%s)",
				clientConn.RemoteAddr(), targetDisplay, proxyToUse)
		} else {
			log.Printf("[ALLOW] HTTPS (EXPLICIT) | Client: %-21s | Target: %-30s -> DIRECT",
				clientConn.RemoteAddr(), targetDisplay)
		}

		// 3. Dial upstream
		outConn, preBufferedUpstream, dialErr := forwarder.DialOutbound(targetDisplay, proxyToUse)
		if dialErr != nil {
			log.Printf("[ERROR] Outbound dial failed for explicit target %s (Proxy: %q): %v", targetDisplay, proxyToUse, dialErr)
			_, _ = clientConn.Write([]byte(fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nDial failed: %v\n", dialErr)))
			return
		}
		defer func() {
			_ = outConn.Close()
		}()

		// 4. Send 200 Connection Established to client
		_, writeErr := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if writeErr != nil {
			logger.Debugf("[ProxyServer] Failed to send 200 Connection Established to %s: %v", clientConn.RemoteAddr(), writeErr)
			return
		}

		// 5. Bidirectional forwarding pipe
		connIdleTimeout := idleTimeout
		if cfg.IdleTimeoutSec <= 0 || isInteractiveService("HTTPS", targetPort, targetHost) {
			connIdleTimeout = 0
		}
		bytesClientToUp, bytesUpToClient := PipeConnEx(clientConn, outConn, clientReader, preBufferedUpstream, connIdleTimeout)
		duration := time.Since(startTime).Round(time.Millisecond)

		log.Printf("[CLOSE] Client: %-21s | Target: %-30s | Sent: %-8s | Recv: %-8s | Duration: %v",
			clientConn.RemoteAddr(), targetDisplay,
			FormatBytes(bytesClientToUp), FormatBytes(bytesUpToClient),
			duration)
		return
	}

	// ----------------------------------------------------
	// Explicit HTTP Forward Proxy (GET/POST/etc http://host/path HTTP/1.1)
	// ----------------------------------------------------
	targetHost := req.URL.Hostname()
	if targetHost == "" {
		targetHost = req.Host
		if h, _, err := net.SplitHostPort(targetHost); err == nil {
			targetHost = h
		}
	}
	portStr := req.URL.Port()
	var targetPort uint16 = 80
	if portStr != "" {
		if p, pErr := strconv.Atoi(portStr); pErr == nil && p > 0 && p <= 65535 {
			targetPort = uint16(p)
		}
	}
	targetDisplay := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	// 1. Policy check
	if s.filterEng.ShouldBlock(targetHost) {
		log.Printf("[BLOCK] HTTP (EXPLICIT)  | Client: %-21s | Target: %-30s -> Blocked by policy",
			clientConn.RemoteAddr(), targetDisplay)
		_, _ = clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBlocked by policy\n"))
		return
	}

	// 2. Resolve proxy decision
	decision, err := s.pacResolver.Resolve(targetHost, targetPort)
	if err != nil {
		decision = pac.ProxyDecision{IsDirect: true}
	}

	proxyToUse := ""
	if !decision.IsDirect && decision.ProxyURL != "" {
		proxyToUse = decision.ProxyURL
		log.Printf("[ALLOW] HTTP (EXPLICIT)  | Client: %-21s | Target: %-30s -> PROXY (%s)",
			clientConn.RemoteAddr(), targetDisplay, proxyToUse)
	} else {
		log.Printf("[ALLOW] HTTP (EXPLICIT)  | Client: %-21s | Target: %-30s -> DIRECT",
			clientConn.RemoteAddr(), targetDisplay)
	}

	// 3. Dial upstream
	outConn, preBufferedUpstream, dialErr := forwarder.DialOutbound(targetDisplay, proxyToUse)
	if dialErr != nil {
		log.Printf("[ERROR] Outbound dial failed for explicit target %s (Proxy: %q): %v", targetDisplay, proxyToUse, dialErr)
		_, _ = clientConn.Write([]byte(fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nDial failed: %v\n", dialErr)))
		return
	}
	defer func() {
		_ = outConn.Close()
	}()

	// 4. Forward the initial HTTP request to upstream
	if proxyToUse == "" {
		req.RequestURI = ""
		req.Header.Del("Proxy-Connection")
	}
	_ = outConn.SetWriteDeadline(time.Now().Add(connectTimeout))
	if err := req.Write(outConn); err != nil {
		log.Printf("[ERROR] Failed to write HTTP request to upstream %s: %v", targetDisplay, err)
		return
	}
	_ = outConn.SetWriteDeadline(time.Time{})

	// 5. Pipe remaining connection
	connIdleTimeout := idleTimeout
	if cfg.IdleTimeoutSec <= 0 {
		connIdleTimeout = 0
	}
	bytesClientToUp, bytesUpToClient := PipeConnEx(clientConn, outConn, clientReader, preBufferedUpstream, connIdleTimeout)
	duration := time.Since(startTime).Round(time.Millisecond)

	log.Printf("[CLOSE] Client: %-21s | Target: %-30s | Sent: %-8s | Recv: %-8s | Duration: %v",
		clientConn.RemoteAddr(), targetDisplay,
		FormatBytes(bytesClientToUp), FormatBytes(bytesUpToClient),
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

// isInteractiveService returns true for remote desktop, terminal, database, or streaming protocols
// where connections are long-lived and long idle periods (without user input) are expected.
func isInteractiveService(protoType string, port uint16, domain string) bool {
	// 1. Signature-detected interactive protocols (regardless of port number)
	switch protoType {
	case "RDP", "SSH", "VNC":
		return true
	}

	// 2. Well-known interactive / remote administration / database ports
	switch port {
	case 22,   // SSH
		23,    // Telnet
		3389,  // Microsoft RDP
		5900,  // VNC
		5901,  // VNC display 1
		5938,  // TeamViewer
		7070,  // AnyDesk
		1433,  // MSSQL
		1521,  // Oracle DB
		3306,  // MySQL / MariaDB
		5432,  // PostgreSQL
		6379,  // Redis
		27017: // MongoDB
		return true
	}

	// 3. Cloud Remote Desktop / VDI / Streaming domains
	if domain != "" {
		lower := strings.ToLower(domain)
		if strings.Contains(lower, "remotedesktop") ||
			strings.Contains(lower, "wvd.microsoft.com") ||
			strings.Contains(lower, "anydesk.com") ||
			strings.Contains(lower, "teamviewer.com") ||
			strings.Contains(lower, "splashtop.com") ||
			strings.Contains(lower, "logmein.com") {
			return true
		}
	}

	return false
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
