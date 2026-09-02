//go:build windows

package interceptor

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"transport_proxy/internal/logger"
)

type dryRunSessionInfo struct {
	Domain   string
	LastSeen atomic.Int64
}

type dnsTask struct {
	clientAddr net.Addr
	targetIP   net.IP
	srcPort    uint16
	dstPort    uint16
	isIPv6     bool
	payload    []byte
	rawPacket  []byte
	origAddr   WinDivertAddress
}

// Redirector handles WinDivert packet interception, bi-directional NAT, session tracking, and dry-run auditing.
type Redirector struct {
	dll            *WinDivertDLL
	handle         syscall.Handle // Layer 0: WINDIVERT_LAYER_NETWORK (Host outbound/inbound)
	filterStr      string
	localProxyPort uint16
	localProxyIP   net.IP
	pid            int
	sessions       sync.Map // map[SessionKey]*SessionInfo
	dryRunSessions sync.Map // map[SessionKey]*dryRunSessionInfo for deduplicating dry-run audit logs
	dryRun         bool
	filterEng      FilterEvaluator
	routingEng     RoutingEvaluator
	dnsEng         DNSEvaluator
	coarseNano     atomic.Int64
	dnsQueue       chan dnsTask
	mu             sync.Mutex
	closed         bool
}

// NewRedirector initializes a new Redirector with given settings.
func NewRedirector(localListenAddr string, customFilter string) (*Redirector, error) {
	dll, err := LoadWinDivertDLL()
	if err != nil {
		return nil, err
	}

	host, portStr, err := net.SplitHostPort(localListenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address %s: %w", localListenAddr, err)
	}

	var port uint16
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("invalid listen port in %s", localListenAddr)
	}

	var ip net.IP
	if host != "" && host != "0.0.0.0" && host != "::" {
		ip = net.ParseIP(host)
	}

	pid := os.Getpid()

	// Bi-directional NAT filter:
	// 1. Forward: Outbound TCP to target ports (excluding loopback)
	// 2. Reverse: Outbound TCP from local proxy port back to clients (to rewrite source IP/port)
	// 3. QUIC Drop: Outbound UDP to port 443 (dropped to force browsers to fallback to TCP/TLS)
	var filterStr string
	if customFilter != "" {
		filterStr = customFilter
	} else {
		filterStr = fmt.Sprintf("((outbound and tcp and !loopback) or (outbound and tcp and tcp.SrcPort == %d) or (outbound and udp and udp.DstPort == 443 and !loopback))", port)
	}

	r := &Redirector{
		dll:            dll,
		handle:         syscall.InvalidHandle,
		filterStr:      filterStr,
		localProxyPort: port,
		localProxyIP:   ip,
		pid:            pid,
		dnsQueue:       make(chan dnsTask, 2048),
	}
	r.coarseNano.Store(time.Now().UnixNano())
	return r, nil
}

// SetDryRun configures dry-run audit mode without intercepting traffic.
func (r *Redirector) SetDryRun(dryRun bool, forwardCond string, filterEng FilterEvaluator, routingEng RoutingEvaluator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dryRun = dryRun
	r.filterEng = filterEng
	r.routingEng = routingEng

	if dryRun {
		if forwardCond != "" {
			r.filterStr = forwardCond
		} else {
			r.filterStr = "outbound and tcp and !loopback"
		}
	}
}

// SetDNSEngine configures the DNS-to-DoH evaluation engine.
func (r *Redirector) SetDNSEngine(dnsEng DNSEvaluator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dnsEng = dnsEng
}

// SetDNSServers configures custom upstream DNS servers.
func (r *Redirector) SetDNSServers(dnsServers []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(dnsServers) > 0 {
		// Custom DNS is configured: allow direct bypass by disabling DNS interception
		r.dnsEng = nil
	}
}

// Start opens the WinDivert handle and starts packet processing and session GC loops.
func (r *Redirector) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return fmt.Errorf("redirector already closed")
	}

	var flags uint64
	if r.dryRun {
		flags = WINDIVERT_FLAG_SNIFF
		log.Printf("[Redirector] Dry-Run Mode ENABLED: Passively sniffing outbound traffic without interception.")
	}

	handle, err := r.dll.Open(r.filterStr, WINDIVERT_LAYER_NETWORK, 0, flags)
	if err != nil {
		return fmt.Errorf("failed to open WinDivert handle (Layer 0): %w", err)
	}
	r.handle = handle

	// Optimize kernel packet queue for high-throughput and spike resilience
	_ = r.dll.SetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 16384)
	_ = r.dll.SetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 8000)
	_ = r.dll.SetParam(handle, WINDIVERT_PARAM_QUEUE_SIZE, 64*1024*1024)

	log.Printf("[Redirector] WinDivert Network Layer (Layer 0) started with filter: %s", r.filterStr)

	// Start coarse timestamp background ticker (20ms interval) to avoid per-packet time.Now syscalls
	r.coarseNano.Store(time.Now().UnixNano())
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-ticker.C:
				r.coarseNano.Store(t.UnixNano())
			}
		}
	}()

	// Start DNS worker pool to handle intercepted DNS queries concurrently without unbounded goroutines
	const numDNSWorkers = 16
	for w := 0; w < numDNSWorkers; w++ {
		go r.dnsWorker(ctx)
	}

	// Start multi-worker packet processing loops for high throughput
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	} else if numWorkers > 8 {
		numWorkers = 8
	}
	for i := 0; i < numWorkers; i++ {
		go r.packetLoop(ctx, i)
	}

	// Start NAT session table garbage collection loop
	go r.sessionGCLoop(ctx)

	return nil
}

// dnsWorker consumes DNS tasks from the bounded queue.
func (r *Redirector) dnsWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-r.dnsQueue:
			if !ok {
				return
			}
			r.processDNSTask(ctx, task)
		}
	}
}

// processDNSTask processes an intercepted DNS query packet asynchronously.
func (r *Redirector) processDNSTask(ctx context.Context, task dnsTask) {
	defer func() {
		if rec := recover(); rec != nil {
			logger.Debugf("[DNS] Recovered from panic in DNS task processor: %v", rec)
		}
	}()

	if r.dnsEng == nil {
		return
	}

	respData, passthrough := r.dnsEng.ProcessDNSQuery(ctx, task.clientAddr, task.targetIP, task.payload)
	if passthrough {
		sendAddr := task.origAddr
		_, _ = r.dll.Send(r.handle, task.rawPacket, &sendAddr)
		return
	}

	if len(respData) > 0 {
		var respPkt []byte
		if task.isIPv6 {
			respPkt = BuildIPv6UDPPacket(task.targetIP, task.clientAddr.(*net.UDPAddr).IP, task.dstPort, task.srcPort, respData)
		} else {
			respPkt = BuildIPv4UDPPacket(task.targetIP, task.clientAddr.(*net.UDPAddr).IP, task.dstPort, task.srcPort, respData)
		}

		if respPkt != nil {
			injectAddr := task.origAddr
			injectAddr.SetOutbound(false) // Inbound to client
			injectAddr.Flags |= WINDIVERT_ADDRESS_FLAG_IMPOSTOR
			injectAddr.Flags &^= WINDIVERT_ADDRESS_FLAG_LOOPBACK
			_ = r.dll.CalcChecksums(respPkt, &injectAddr, 0)
			_, _ = r.dll.Send(r.handle, respPkt, &injectAddr)
		}
	}
}

// LookupOriginalDestination retrieves the original destination IP and port for a client connection.
func (r *Redirector) LookupOriginalDestination(clientAddr net.Addr) (net.IP, uint16, bool) {
	tcpAddr, ok := clientAddr.(*net.TCPAddr)
	if !ok {
		return nil, 0, false
	}

	key := MakeSessionKeyFromNetIP(tcpAddr.IP, uint16(tcpAddr.Port))
	val, exists := r.sessions.Load(key)
	if !exists {
		return nil, 0, false
	}

	info := val.(*SessionInfo)
	info.LastSeen.Store(time.Now().UnixNano())
	return info.OriginalDstIP, info.OriginalDstPort, true
}

// LookupOriginalDestinationConn retrieves the original destination IP and port given a net.Conn.
func (r *Redirector) LookupOriginalDestinationConn(conn net.Conn) (net.IP, uint16, bool) {
	if conn == nil {
		return nil, 0, false
	}
	return r.LookupOriginalDestination(conn.RemoteAddr())
}

// DeleteSession explicitly removes a session once connection is terminated.
func (r *Redirector) DeleteSession(clientAddr net.Addr) {
	if tcpAddr, ok := clientAddr.(*net.TCPAddr); ok {
		key := MakeSessionKeyFromNetIP(tcpAddr.IP, uint16(tcpAddr.Port))
		r.sessions.Delete(key)
	}
}

// packetLoop continuously receives, rewrites (Forward & Reverse NAT), and reinjects packets.
func (r *Redirector) packetLoop(ctx context.Context, workerID int) {
	// Pin worker goroutine to a dedicated OS thread for zero context-switch overhead on WinDivert syscalls
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for {
		var stopped bool
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[Redirector] CRITICAL: Recovered from panic in packetLoop worker %d: %v", workerID, rec)
					time.Sleep(1 * time.Second)
				}
			}()

			packetBuf := make([]byte, 65535)
			var addr WinDivertAddress

			for {
				select {
				case <-ctx.Done():
					stopped = true
					return
				default:
				}

				n, err := r.dll.Recv(r.handle, packetBuf, &addr)
				if err != nil {
					r.mu.Lock()
					isClosed := r.closed
					r.mu.Unlock()
					if isClosed {
						stopped = true
						return
					}
					runtime.Gosched()
					time.Sleep(10 * time.Millisecond) // Prevent busy loop on continuous error
					continue
				}

				if n <= 0 || n > len(packetBuf) {
					continue
				}

				rawPacket := packetBuf[:n]

				// Process based on IP version in the header
				if len(rawPacket) > 0 {
					version := rawPacket[0] >> 4
					if version == 4 {
						proto, srcIP, dstIP, ihl, err := ParseIPv4Fast(rawPacket)
					if err == nil && proto == IPPROTO_TCP {
						srcPort, dstPort, tcpFlags, dataOffset, err := ParseTCPFast(rawPacket, ihl)
						if err == nil {
							if r.dryRun {
								clientKey := MakeSessionKeyIPv4(srcIP, srcPort)
								payloadOffset := ihl + dataOffset
								var payload []byte
								if len(rawPacket) > payloadOffset {
									payload = rawPacket[payloadOffset:]
								}
								r.handleDryRunTCP(clientKey, net.IPv4(dstIP[0], dstIP[1], dstIP[2], dstIP[3]), dstPort, payload)
								continue
							}

							nowNano := r.coarseNano.Load()

							// DIAGNOSTIC: Detect self-interception of proxy's own outbound connections
							if srcPort >= 40000 && srcPort <= 48999 {
								logger.Debugf("[TRAP]  SELF-INTERCEPTION DETECTED! SrcPort=%d is in proxy outbound range! %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d (pktLen=%d, IfIdx=%d, Flags=0x%x, Loopback=%v)",
									srcPort, srcIP[0], srcIP[1], srcIP[2], srcIP[3], srcPort,
									dstIP[0], dstIP[1], dstIP[2], dstIP[3], dstPort,
									len(rawPacket), addr.IfIdx, addr.Flags, addr.IsLoopback())
								// DO NOT process - just reinject as-is to prevent loop
								_, _ = r.dll.Send(r.handle, rawPacket, &addr)
								continue
							}

							if srcPort == r.localProxyPort {
								// ----------------------------------------------------
								// REVERSE NAT: Response packet from Local Proxy to Client
								// Rewrite SrcIP:SrcPort back to OriginalDstIP:OriginalDstPort
								// ----------------------------------------------------
								clientKey := MakeSessionKeyIPv4(dstIP, dstPort)
								if val, exists := r.sessions.Load(clientKey); exists {
									info := val.(*SessionInfo)
									info.LastSeen.Store(nowNano) // Keep alive during active traffic

									logger.Debugf("[RNAT]  Reverse NAT: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d (pktLen=%d, IfIdx=%d, Flags=0x%x, Loopback=%v) -> Rewrite Src to %s:%d",
										srcIP[0], srcIP[1], srcIP[2], srcIP[3], srcPort,
										dstIP[0], dstIP[1], dstIP[2], dstIP[3], dstPort,
										len(rawPacket), addr.IfIdx, addr.Flags, addr.IsLoopback(),
										info.OriginalDstIP, info.OriginalDstPort)

									_ = RewriteIPv4TCP(rawPacket, info.OriginalDstIP, nil, info.OriginalDstPort, 0)
									addr.SetOutbound(false)                                  // Inbound to client TCP stack
									addr.Flags &^= WINDIVERT_ADDRESS_FLAG_LOOPBACK           // Clear loopback flag (injecting on physical adapter)
									addr.IfIdx = info.IfIdx                                  // Restore original physical interface
									addr.SubIfIdx = info.SubIfIdx                            // Restore original sub-interface
									addr.Flags |= WINDIVERT_ADDRESS_FLAG_IMPOSTOR            // Mark as injected packet
									_ = r.dll.CalcChecksums(rawPacket, &addr, 0)

									// Handle LSO packets that exceed physical MTU (1500)
									fragments := FragmentIPv4(rawPacket, 1500)
									for i, frag := range fragments {
										sentLen, sendErr := r.dll.Send(r.handle, frag, &addr)
										if sendErr != nil {
											logger.Debugf("[RNAT]  Send failed: frag %d/%d (len=%d): %v", i+1, len(fragments), len(frag), sendErr)
										} else {
											logger.Debugf("[RNAT]  Sent frag %d/%d (len=%d, sentLen=%d, IfIdx=%d, Flags=0x%x)",
												i+1, len(fragments), len(frag), sentLen, addr.IfIdx, addr.Flags)
										}
									}
									continue // Skip standard Send at bottom
								} else {
									logger.Debugf("[RNAT]  No session found for clientKey=%d.%d.%d.%d:%d (SrcPort=%d matched proxy port)",
										dstIP[0], dstIP[1], dstIP[2], dstIP[3], dstPort, srcPort)
								}
							} else {
								// ----------------------------------------------------
								// FORWARD NAT: Request packet from Client to Remote Target
								// Save Original Destination & rewrite Dst to Local Proxy
								// ----------------------------------------------------
								clientKey := MakeSessionKeyIPv4(srcIP, srcPort)
								dstNetIP := net.IPv4(dstIP[0], dstIP[1], dstIP[2], dstIP[3])

								var info *SessionInfo
								if val, exists := r.sessions.Load(clientKey); exists {
									existing := val.(*SessionInfo)
									// If this is a new SYN packet or destination has changed, overwrite the session
									if (tcpFlags&TCP_SYN != 0 && tcpFlags&TCP_ACK == 0) ||
										!existing.OriginalDstIP.Equal(dstNetIP) ||
										existing.OriginalDstPort != dstPort {
										info = &SessionInfo{
											OriginalDstIP:   dstNetIP,
											OriginalDstPort: dstPort,
											IfIdx:           addr.IfIdx,
											SubIfIdx:        addr.SubIfIdx,
											CreatedAt:       time.Now(),
										}
										info.LastSeen.Store(nowNano)
										r.sessions.Store(clientKey, info)
										logger.Debugf("[NAT]   New/Updated Session (SYN/Rebound): %d.%d.%d.%d:%d -> %s:%d | IfIdx=%d, SubIfIdx=%d, Flags=0x%x",
											srcIP[0], srcIP[1], srcIP[2], srcIP[3], srcPort, dstNetIP, dstPort, addr.IfIdx, addr.SubIfIdx, addr.Flags)
									} else {
										info = existing
										info.LastSeen.Store(nowNano) // Keep alive during active traffic
										if addr.IfIdx != 0 {
											info.IfIdx = addr.IfIdx
											info.SubIfIdx = addr.SubIfIdx
										}
									}
								} else {
									now := time.Now()
									info = &SessionInfo{
										OriginalDstIP:   dstNetIP,
										OriginalDstPort: dstPort,
										IfIdx:           addr.IfIdx,
										SubIfIdx:        addr.SubIfIdx,
										CreatedAt:       now,
									}
									info.LastSeen.Store(nowNano)
									r.sessions.Store(clientKey, info)
									logger.Debugf("[NAT]   Intercepted: %d.%d.%d.%d:%d -> %s:%d | IfIdx=%d, SubIfIdx=%d, Flags=0x%x",
										srcIP[0], srcIP[1], srcIP[2], srcIP[3], srcPort, dstNetIP, dstPort, addr.IfIdx, addr.SubIfIdx, addr.Flags)
								}

								// Rewrite destination to local adapter IP and proxy listener port.
								targetIP := r.localProxyIP
								if targetIP == nil {
									targetIP = net.IPv4(srcIP[0], srcIP[1], srcIP[2], srcIP[3])
								}
								_ = RewriteIPv4TCP(rawPacket, nil, targetIP, 0, r.localProxyPort)
								addr.SetOutbound(false) // Inbound to local proxy listener
								addr.Flags |= WINDIVERT_ADDRESS_FLAG_IMPOSTOR
								_ = r.dll.CalcChecksums(rawPacket, &addr, 0)
								_, sendErr := r.dll.Send(r.handle, rawPacket, &addr)
								if sendErr != nil {
									logger.Debugf("[NAT] Forward NAT send failed: %v", sendErr)
								}
								continue
							}
						}
					} else if proto == IPPROTO_UDP {
						srcPort, dstPort, _, dataOffset, err := ParseUDPFast(rawPacket, ihl)
						if err == nil {
							if dstPort == 443 {
								// UDP 443 (HTTP/3 QUIC) Interception: Drop to force TCP fallback
								if !r.dryRun {
									continue
								}
							} else if dstPort == 53 && r.dnsEng != nil && !r.dryRun {
								// UDP 53 DNS Interception & Worker Pool Queue
								clientAddr := &net.UDPAddr{
									IP:   net.IPv4(srcIP[0], srcIP[1], srcIP[2], srcIP[3]),
									Port: int(srcPort),
								}
								targetIP := net.IPv4(dstIP[0], dstIP[1], dstIP[2], dstIP[3])

								rawCopy := append([]byte(nil), rawPacket...)
								payloadCopy := rawCopy[dataOffset:]

								task := dnsTask{
									clientAddr: clientAddr,
									targetIP:   targetIP,
									srcPort:    srcPort,
									dstPort:    dstPort,
									isIPv6:     false,
									payload:    payloadCopy,
									rawPacket:  rawCopy,
									origAddr:   addr,
								}

								select {
								case r.dnsQueue <- task:
								default:
									// Spillage / fallback worker on queue saturation
									go r.processDNSTask(ctx, task)
								}

								continue // Handled asynchronously
							}
						}
					}
				} else if version == 6 {
					// ----------------------------------------------------
					// IPv6 Packet Processing (Zero-Alloc Fast Path)
					// ----------------------------------------------------
					nextHdr, srcIP6, dstIP6, _, ihl, err := ParseIPv6Fast(rawPacket)
					if err == nil && nextHdr == IPPROTO_TCP {
						srcPort, dstPort, tcpFlags, dataOffset, err := ParseTCPFast(rawPacket, ihl)
						if err == nil {
							if r.dryRun {
								clientKey := MakeSessionKeyIPv6(srcIP6, srcPort)
								payloadOffset := ihl + dataOffset
								var payload []byte
								if len(rawPacket) > payloadOffset {
									payload = rawPacket[payloadOffset:]
								}
								r.handleDryRunTCP(clientKey, net.IP(dstIP6[:]), dstPort, payload)
								continue
							}

							nowNano := r.coarseNano.Load()

							// DIAGNOSTIC: Detect self-interception of proxy's own outbound connections
							if srcPort >= 40000 && srcPort <= 48999 {
								logger.Debugf("[TRAP-v6] SELF-INTERCEPTION DETECTED! SrcPort=%d is in proxy outbound range! [%s]:%d -> [%s]:%d (pktLen=%d, IfIdx=%d, Flags=0x%x, Loopback=%v)",
									srcPort, net.IP(srcIP6[:]), srcPort, net.IP(dstIP6[:]), dstPort,
									len(rawPacket), addr.IfIdx, addr.Flags, addr.IsLoopback())
								// DO NOT process - just reinject as-is to prevent loop
								_, _ = r.dll.Send(r.handle, rawPacket, &addr)
								continue
							}

							if srcPort == r.localProxyPort {
								// ----------------------------------------------------
								// REVERSE NAT (IPv6): Response packet from Local Proxy to Client
								// Rewrite SrcIP:SrcPort back to OriginalDstIP:OriginalDstPort
								// ----------------------------------------------------
								clientKey := MakeSessionKeyIPv6(dstIP6, dstPort)
								if val, exists := r.sessions.Load(clientKey); exists {
									info := val.(*SessionInfo)
									info.LastSeen.Store(nowNano)

									logger.Debugf("[RNAT-v6] Reverse NAT: [%s]:%d -> [%s]:%d -> Rewrite Src to [%s]:%d",
										net.IP(srcIP6[:]), srcPort, net.IP(dstIP6[:]), dstPort,
										info.OriginalDstIP, info.OriginalDstPort)

									_ = RewriteIPv6TCP(rawPacket, info.OriginalDstIP, nil, info.OriginalDstPort, 0)
									addr.SetOutbound(false)                                  // Inbound to client TCP stack
									addr.Flags &^= WINDIVERT_ADDRESS_FLAG_LOOPBACK           // Clear loopback flag
									addr.IfIdx = info.IfIdx                                  // Restore original physical interface
									addr.SubIfIdx = info.SubIfIdx                            // Restore original sub-interface
									addr.Flags |= WINDIVERT_ADDRESS_FLAG_IMPOSTOR            // Mark as injected packet
									_ = r.dll.CalcChecksums(rawPacket, &addr, 0)

									if len(rawPacket) > 1280 {
										sentLen, sendErr := r.dll.Send(r.handle, rawPacket, &addr)
										if sendErr != nil {
											fragments := FragmentIPv6TCP(rawPacket, 1280)
											for i, frag := range fragments {
												sLen, sErr := r.dll.Send(r.handle, frag, &addr)
												if sErr != nil {
													logger.Debugf("[RNAT-v6] Send failed: frag %d/%d (len=%d): %v", i+1, len(fragments), len(frag), sErr)
												} else {
													logger.Debugf("[RNAT-v6] Sent frag %d/%d (len=%d, sentLen=%d, IfIdx=%d)", i+1, len(fragments), len(frag), sLen, addr.IfIdx)
												}
											}
										} else {
											logger.Debugf("[RNAT-v6] Sent len=%d, sentLen=%d, IfIdx=%d", len(rawPacket), sentLen, addr.IfIdx)
										}
									} else {
										sentLen, sendErr := r.dll.Send(r.handle, rawPacket, &addr)
										if sendErr != nil {
											logger.Debugf("[RNAT-v6] Send failed (len=%d): %v", len(rawPacket), sendErr)
										} else {
											logger.Debugf("[RNAT-v6] Sent len=%d, sentLen=%d, IfIdx=%d", len(rawPacket), sentLen, addr.IfIdx)
										}
									}
									continue
								} else {
									logger.Debugf("[RNAT-v6] No session found for clientKey=[%s]:%d", net.IP(dstIP6[:]), dstPort)
								}
							} else {
								// ----------------------------------------------------
								// FORWARD NAT (IPv6): Request packet from Client to Remote Target
								// Save Original Destination & rewrite Dst to Local Proxy
								// ----------------------------------------------------
								clientKey := MakeSessionKeyIPv6(srcIP6, srcPort)
								dstNetIP := append(net.IP(nil), dstIP6[:]...)

								var info *SessionInfo
								if val, exists := r.sessions.Load(clientKey); exists {
									existing := val.(*SessionInfo)
									if (tcpFlags&TCP_SYN != 0 && tcpFlags&TCP_ACK == 0) ||
										!existing.OriginalDstIP.Equal(dstNetIP) ||
										existing.OriginalDstPort != dstPort {
										info = &SessionInfo{
											OriginalDstIP:   dstNetIP,
											OriginalDstPort: dstPort,
											IfIdx:           addr.IfIdx,
											SubIfIdx:        addr.SubIfIdx,
											CreatedAt:       time.Now(),
										}
										info.LastSeen.Store(nowNano)
										r.sessions.Store(clientKey, info)
										logger.Debugf("[NAT-v6]  New/Updated Session: [%s]:%d -> [%s]:%d | IfIdx=%d, Flags=0x%x",
											net.IP(srcIP6[:]), srcPort, dstNetIP, dstPort, addr.IfIdx, addr.Flags)
									} else {
										info = existing
										info.LastSeen.Store(nowNano)
										if addr.IfIdx != 0 {
											info.IfIdx = addr.IfIdx
											info.SubIfIdx = addr.SubIfIdx
										}
									}
								} else {
									now := time.Now()
									info = &SessionInfo{
										OriginalDstIP:   dstNetIP,
										OriginalDstPort: dstPort,
										IfIdx:           addr.IfIdx,
										SubIfIdx:        addr.SubIfIdx,
										CreatedAt:       now,
									}
									info.LastSeen.Store(nowNano)
									r.sessions.Store(clientKey, info)
									logger.Debugf("[NAT-v6]  Intercepted: [%s]:%d -> [%s]:%d | IfIdx=%d, Flags=0x%x",
										net.IP(srcIP6[:]), srcPort, dstNetIP, dstPort, addr.IfIdx, addr.Flags)
								}

								// Rewrite destination to client's local IPv6 address and proxy listener port.
								targetIP := r.localProxyIP
								if targetIP == nil || targetIP.To4() != nil {
									targetIP = net.IP(srcIP6[:])
								}
								_ = RewriteIPv6TCP(rawPacket, nil, targetIP, 0, r.localProxyPort)
								addr.SetOutbound(false) // Inbound to local proxy listener
								addr.Flags |= WINDIVERT_ADDRESS_FLAG_IMPOSTOR
								_ = r.dll.CalcChecksums(rawPacket, &addr, 0)
								_, sendErr := r.dll.Send(r.handle, rawPacket, &addr)
								if sendErr != nil {
									logger.Debugf("[NAT-v6] Forward NAT send failed: %v", sendErr)
								}
								continue
							}
						}
					} else if nextHdr == IPPROTO_UDP {
						srcPort, dstPort, _, dataOffset, err := ParseUDPFast(rawPacket, ihl)
						if err == nil {
							if dstPort == 443 {
								// IPv6 UDP 443 QUIC: drop to force TCP
								if !r.dryRun {
									continue
								}
							} else if dstPort == 53 && r.dnsEng != nil && !r.dryRun {
								// IPv6 UDP 53 DNS Interception
								clientAddr := &net.UDPAddr{
									IP:   net.IP(srcIP6[:]),
									Port: int(srcPort),
								}
								targetIP := net.IP(dstIP6[:])

								rawCopy := append([]byte(nil), rawPacket...)
								payloadCopy := rawCopy[dataOffset:]
								origAddr := addr

								task := dnsTask{
									clientAddr: clientAddr,
									targetIP:   targetIP,
									srcPort:    srcPort,
									dstPort:    dstPort,
									isIPv6:     true,
									payload:    payloadCopy,
									rawPacket:  rawCopy,
									origAddr:   origAddr,
								}

								select {
								case r.dnsQueue <- task:
								default:
									go r.processDNSTask(ctx, task)
								}

								continue // Handled asynchronously
							}
						}
					}
				}
				}

				// Reinject unmodified passthrough packet into network stack
				_, sendErr := r.dll.Send(r.handle, rawPacket, &addr)
				if sendErr != nil {
					logger.Debugf("[NAT-SEND] Reinjection failed (len=%d, IfIdx=%d, Flags=0x%x, Outbound=%v): %v",
						len(rawPacket), addr.IfIdx, addr.Flags, addr.IsOutbound(), sendErr)
				}
			}
		}()

		if stopped {
			return
		}
	}
}

// sessionGCLoop purges stale NAT session table entries to prevent memory leaks.
func (r *Redirector) sessionGCLoop(ctx context.Context) {
	for {
		var stopped bool
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[Redirector] Recovered from panic in sessionGCLoop: %v", rec)
					time.Sleep(1 * time.Second)
				}
			}()

			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()

			// Safe TTL of 24 hours for established sessions (active sessions have LastSeen updated per packet,
			// and idle interactive sessions like RDP/SSH are kept alive via TCP Keep-Alive).
			const sessionTTL = 24 * time.Hour

			for {
				select {
				case <-ctx.Done():
					stopped = true
					return
				case <-ticker.C:
					now := time.Now()
					r.sessions.Range(func(k, v any) bool {
						info := v.(*SessionInfo)
						lastSeenTime := time.Unix(0, info.LastSeen.Load())
						if now.Sub(lastSeenTime) > sessionTTL {
							r.sessions.Delete(k)
						}
						return true
					})
					if r.dryRun {
						r.dryRunSessions.Range(func(k, v any) bool {
							info := v.(*dryRunSessionInfo)
							lastSeenTime := time.Unix(0, info.LastSeen.Load())
							if now.Sub(lastSeenTime) > sessionTTL {
								r.dryRunSessions.Delete(k)
							}
							return true
						})
					}
				}
			}
		}()

		if stopped {
			return
		}
	}
}

// Close closes the Network Layer WinDivert handle and frees all resources.
func (r *Redirector) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	var lastErr error
	if r.handle != syscall.InvalidHandle {
		log.Printf("[Redirector] Closing WinDivert Network Layer handle and restoring network state...")
		if err := r.dll.Close(r.handle); err != nil {
			lastErr = err
		}
		r.handle = syscall.InvalidHandle
	}

	return lastErr
}

// handleDryRunTCP inspects and logs an outbound TCP packet for dry-run monitoring.
func (r *Redirector) handleDryRunTCP(clientKey SessionKey, dstIP net.IP, dstPort uint16, payload []byte) {
	isWeb, protoType, targetDomain := IsHTTPOrHTTPS(payload)

	loggedVal, exists := r.dryRunSessions.Load(clientKey)
	prevLoggedDomain := ""
	if exists {
		info := loggedVal.(*dryRunSessionInfo)
		prevLoggedDomain = info.Domain
		info.LastSeen.Store(time.Now().UnixNano())
	}

	shouldLog := false
	if targetDomain != "" {
		if prevLoggedDomain != targetDomain {
			shouldLog = true
			info := &dryRunSessionInfo{Domain: targetDomain}
			info.LastSeen.Store(time.Now().UnixNano())
			r.dryRunSessions.Store(clientKey, info)
		}
	} else if !exists {
		// Log IP connection for non-web or initial TCP sync
		shouldLog = true
		info := &dryRunSessionInfo{Domain: ""}
		info.LastSeen.Store(time.Now().UnixNano())
		r.dryRunSessions.Store(clientKey, info)
	}

	if !shouldLog {
		return
	}

	targetHostToCheck := targetDomain
	if targetHostToCheck == "" {
		targetHostToCheck = dstIP.String()
	}

	shouldBlock := false
	if r.filterEng != nil {
		shouldBlock = r.filterEng.ShouldBlock(targetHostToCheck)
	}

	var targetAddrStr string
	if dstIP.To4() != nil {
		targetAddrStr = fmt.Sprintf("%s:%d", dstIP.String(), dstPort)
	} else {
		targetAddrStr = fmt.Sprintf("[%s]:%d", dstIP.String(), dstPort)
	}

	targetDisplay := targetAddrStr
	if targetDomain != "" {
		targetDisplay = fmt.Sprintf("%s:%d", targetDomain, dstPort)
	}

	clientDisplay := clientKey.DisplayString()

	if shouldBlock {
		log.Printf("[DRY-RUN] %-7s | WOULD BLOCK | Client: %-21s | Target: %-30s -> Blocked by policy",
			protoType, clientDisplay, targetDisplay)
	} else {
		upstreamInfo := "DIRECT"
		// Only Web traffic (HTTP/HTTPS) routes through upstream proxy, matching live server behavior
		if isWeb && r.routingEng != nil {
			isDirect, proxyURL, err := r.routingEng.ResolveRouting(targetHostToCheck, dstPort)
			if err == nil && !isDirect && proxyURL != "" {
				upstreamInfo = fmt.Sprintf("PROXY (%s)", proxyURL)
			}
		}
		log.Printf("[DRY-RUN] %-7s | WOULD ALLOW | Client: %-21s | Target: %-30s -> Upstream: %s",
			protoType, clientDisplay, targetDisplay, upstreamInfo)
	}
}
