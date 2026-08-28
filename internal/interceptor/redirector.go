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

// SessionKey uniquely identifies a client TCP session by source IP and port.
// Designed with zero-allocation in mind (fixed-size byte array value type).
type SessionKey struct {
	IP   [16]byte // Holds 4-byte IPv4 (in first 4 bytes) or 16-byte IPv6
	Port uint16
	IsV6 bool
}

// MakeSessionKeyIPv4 creates a zero-alloc SessionKey from raw 4-byte IPv4.
func MakeSessionKeyIPv4(ip [4]byte, port uint16) SessionKey {
	var k SessionKey
	copy(k.IP[:4], ip[:])
	k.Port = port
	return k
}

// MakeSessionKeyFromNetIP creates a SessionKey from a standard net.IP.
func MakeSessionKeyFromNetIP(ip net.IP, port uint16) SessionKey {
	var k SessionKey
	if ip4 := ip.To4(); ip4 != nil {
		copy(k.IP[:4], ip4)
	} else {
		copy(k.IP[:], ip)
		k.IsV6 = true
	}
	k.Port = port
	return k
}

// DisplayString returns formatted IP:Port string for logging.
func (k SessionKey) DisplayString() string {
	if k.IsV6 {
		return fmt.Sprintf("[%s]:%d", net.IP(k.IP[:]).String(), k.Port)
	}
	return fmt.Sprintf("%d.%d.%d.%d:%d", k.IP[0], k.IP[1], k.IP[2], k.IP[3], k.Port)
}

// SessionInfo stores original destination information for redirected connections.
type SessionInfo struct {
	OriginalDstIP   net.IP
	OriginalDstPort uint16
	IfIdx           uint32 // Original physical network interface index
	SubIfIdx        uint32 // Original sub-interface index
	CreatedAt       time.Time
	LastSeen        atomic.Int64
}

type dryRunSessionInfo struct {
	Domain   string
	LastSeen atomic.Int64
}

// FilterEvaluator checks if a host or IP should be blocked.
type FilterEvaluator interface {
	ShouldBlock(hostOrIP string) bool
}

// RoutingEvaluator resolves upstream proxy routing decisions.
type RoutingEvaluator interface {
	ResolveRouting(targetHost string, targetPort uint16) (isDirect bool, proxyURL string, err error)
}

// DNSEvaluator processes intercepted UDP DNS query packets.
type DNSEvaluator interface {
	ProcessDNSQuery(ctx context.Context, clientAddr net.Addr, dstIP net.IP, payload []byte) (respData []byte, passthrough bool)
}

// Redirector handles WinDivert packet interception, bi-directional NAT, session tracking, and dry-run auditing.
type Redirector struct {
	dll            *WinDivertDLL
	handle         syscall.Handle
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

	return &Redirector{
		dll:            dll,
		handle:         syscall.InvalidHandle,
		filterStr:      filterStr,
		localProxyPort: port,
		localProxyIP:   ip,
		pid:            pid,
	}, nil
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
		return fmt.Errorf("failed to open WinDivert handle: %w", err)
	}
	r.handle = handle

	// Optimize kernel packet queue for high-throughput and spike resilience
	_ = r.dll.SetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 8192)
	_ = r.dll.SetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2000)
	_ = r.dll.SetParam(handle, WINDIVERT_PARAM_QUEUE_SIZE, 32*1024*1024)

	log.Printf("[Redirector] WinDivert started with filter: %s", r.filterStr)

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

				rawPacket := packetBuf[:n]

				// Process IPv4 TCP packets
				if !addr.IsIPv6() {
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

							nowNano := time.Now().UnixNano()

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
								// When localProxyIP is not explicitly set (listening on 0.0.0.0), rewriting DstIP to srcIP (client's local IP)
								// guarantees Windows TCP stack recognizes it as a local destination and delivers it to 0.0.0.0:18080.
								targetIP := r.localProxyIP
								if targetIP == nil {
									targetIP = net.IPv4(srcIP[0], srcIP[1], srcIP[2], srcIP[3])
								}
								_ = RewriteIPv4TCP(rawPacket, nil, targetIP, 0, r.localProxyPort)
								addr.SetOutbound(false) // Inbound to local proxy listener
								addr.Flags |= WINDIVERT_ADDRESS_FLAG_IMPOSTOR
								_ = r.dll.CalcChecksums(rawPacket, &addr, 0)
							}
						}
					} else if proto == IPPROTO_UDP {
						srcPort, dstPort, _, dataOffset, err := ParseUDPFast(rawPacket, ihl)
						if err == nil {
							if dstPort == 443 {
								// ----------------------------------------------------
								// UDP 443 (HTTP/3 QUIC) Interception:
								// Browsers attempt QUIC via UDP 443, bypassing TCP proxy.
								// In normal mode, drop UDP 443 to force browsers to fallback to TCP/TLS (HTTP/2 / HTTP/1.1).
								// ----------------------------------------------------
								if !r.dryRun {
									continue // Silently DROP UDP 443 packet (do not reinject)
								}
							} else if dstPort == 53 && r.dnsEng != nil && !r.dryRun {
								// ----------------------------------------------------
								// UDP 53 DNS Interception & DoH Dynamic Upgrade
								// ----------------------------------------------------
								payload := rawPacket[dataOffset:]
								clientAddr := &net.UDPAddr{
									IP:   net.IPv4(srcIP[0], srcIP[1], srcIP[2], srcIP[3]),
									Port: int(srcPort),
								}
								targetIP := net.IPv4(dstIP[0], dstIP[1], dstIP[2], dstIP[3])

								rawCopy := append([]byte(nil), rawPacket...)
								payloadCopy := append([]byte(nil), payload...)
								origAddr := addr

								go func(cAddr net.Addr, tIP net.IP, sPort, dPort uint16, pld, rPkt []byte, oAddr WinDivertAddress) {
									defer func() {
										if rec := recover(); rec != nil {
											logger.Debugf("[DNS] Recovered from panic in DNS handler: %v", rec)
										}
									}()

									respData, passthrough := r.dnsEng.ProcessDNSQuery(ctx, cAddr, tIP, pld)
									if passthrough {
										// Passthrough: send original query packet as-is to remote DNS server
										sendAddr := oAddr
										_, _ = r.dll.Send(r.handle, rPkt, &sendAddr)
										return
									}
									if len(respData) > 0 {
										// Build response UDP packet: Src = targetIP:53, Dst = clientIP:srcPort
										respPkt := BuildIPv4UDPPacket(tIP, cAddr.(*net.UDPAddr).IP, dPort, sPort, respData)
										if respPkt != nil {
											injectAddr := oAddr
											injectAddr.SetOutbound(false) // Inbound to client
											injectAddr.Flags |= WINDIVERT_ADDRESS_FLAG_IMPOSTOR
											injectAddr.Flags &^= WINDIVERT_ADDRESS_FLAG_LOOPBACK
											_ = r.dll.CalcChecksums(respPkt, &injectAddr, 0)
											_, _ = r.dll.Send(r.handle, respPkt, &injectAddr)
										}
									}
								}(clientAddr, targetIP, srcPort, dstPort, payloadCopy, rawCopy, origAddr)

								continue // Handled asynchronously
							}
						}
					}
				} else if addr.IsIPv6() {
					// ----------------------------------------------------
					// IPv6 Packet Processing (TCP NAT & QUIC Interception)
					// ----------------------------------------------------
					ip6Hdr, ihl, err := ParseIPv6Header(rawPacket)
					if err == nil && ip6Hdr.NextHeader == IPPROTO_TCP {
						srcPort, dstPort, tcpFlags, dataOffset, err := ParseTCPFast(rawPacket, ihl)
						if err == nil {
							if r.dryRun {
								clientKey := MakeSessionKeyFromNetIP(ip6Hdr.SrcIP, srcPort)
								payloadOffset := ihl + dataOffset
								var payload []byte
								if len(rawPacket) > payloadOffset {
									payload = rawPacket[payloadOffset:]
								}
								r.handleDryRunTCP(clientKey, ip6Hdr.DstIP, dstPort, payload)
								continue
							}

							nowNano := time.Now().UnixNano()

							// DIAGNOSTIC: Detect self-interception of proxy's own outbound connections
							if srcPort >= 40000 && srcPort <= 48999 {
								logger.Debugf("[TRAP-v6] SELF-INTERCEPTION DETECTED! SrcPort=%d is in proxy outbound range! [%s]:%d -> [%s]:%d (pktLen=%d, IfIdx=%d, Flags=0x%x, Loopback=%v)",
									srcPort, ip6Hdr.SrcIP, srcPort, ip6Hdr.DstIP, dstPort,
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
								clientKey := MakeSessionKeyFromNetIP(ip6Hdr.DstIP, dstPort)
								if val, exists := r.sessions.Load(clientKey); exists {
									info := val.(*SessionInfo)
									info.LastSeen.Store(nowNano)

									logger.Debugf("[RNAT-v6] Reverse NAT: [%s]:%d -> [%s]:%d -> Rewrite Src to [%s]:%d",
										ip6Hdr.SrcIP, srcPort, ip6Hdr.DstIP, dstPort,
										info.OriginalDstIP, info.OriginalDstPort)

									_ = RewriteIPv6TCP(rawPacket, info.OriginalDstIP, nil, info.OriginalDstPort, 0)
									addr.SetOutbound(false)                                  // Inbound to client TCP stack
									addr.Flags &^= WINDIVERT_ADDRESS_FLAG_LOOPBACK           // Clear loopback flag
									addr.IfIdx = info.IfIdx                                  // Restore original physical interface
									addr.SubIfIdx = info.SubIfIdx                            // Restore original sub-interface
									addr.Flags |= WINDIVERT_ADDRESS_FLAG_IMPOSTOR            // Mark as injected packet
									_ = r.dll.CalcChecksums(rawPacket, &addr, 0)

									sentLen, sendErr := r.dll.Send(r.handle, rawPacket, &addr)
									if sendErr != nil {
										logger.Debugf("[RNAT-v6] Send failed (len=%d): %v", len(rawPacket), sendErr)
									} else {
										logger.Debugf("[RNAT-v6] Sent len=%d, sentLen=%d, IfIdx=%d", len(rawPacket), sentLen, addr.IfIdx)
									}
									continue
								} else {
									logger.Debugf("[RNAT-v6] No session found for clientKey=[%s]:%d", ip6Hdr.DstIP, dstPort)
								}
							} else {
								// ----------------------------------------------------
								// FORWARD NAT (IPv6): Request packet from Client to Remote Target
								// Save Original Destination & rewrite Dst to Local Proxy
								// ----------------------------------------------------
								clientKey := MakeSessionKeyFromNetIP(ip6Hdr.SrcIP, srcPort)

								var info *SessionInfo
								if val, exists := r.sessions.Load(clientKey); exists {
									existing := val.(*SessionInfo)
									if (tcpFlags&TCP_SYN != 0 && tcpFlags&TCP_ACK == 0) ||
										!existing.OriginalDstIP.Equal(ip6Hdr.DstIP) ||
										existing.OriginalDstPort != dstPort {
										info = &SessionInfo{
											OriginalDstIP:   append(net.IP(nil), ip6Hdr.DstIP...),
											OriginalDstPort: dstPort,
											IfIdx:           addr.IfIdx,
											SubIfIdx:        addr.SubIfIdx,
											CreatedAt:       time.Now(),
										}
										info.LastSeen.Store(nowNano)
										r.sessions.Store(clientKey, info)
										logger.Debugf("[NAT-v6]  New/Updated Session: [%s]:%d -> [%s]:%d | IfIdx=%d, Flags=0x%x",
											ip6Hdr.SrcIP, srcPort, ip6Hdr.DstIP, dstPort, addr.IfIdx, addr.Flags)
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
										OriginalDstIP:   append(net.IP(nil), ip6Hdr.DstIP...),
										OriginalDstPort: dstPort,
										IfIdx:           addr.IfIdx,
										SubIfIdx:        addr.SubIfIdx,
										CreatedAt:       now,
									}
									info.LastSeen.Store(nowNano)
									r.sessions.Store(clientKey, info)
									logger.Debugf("[NAT-v6]  Intercepted: [%s]:%d -> [%s]:%d | IfIdx=%d, Flags=0x%x",
										ip6Hdr.SrcIP, srcPort, ip6Hdr.DstIP, dstPort, addr.IfIdx, addr.Flags)
								}

								// Rewrite destination to client's local IPv6 address and proxy listener port.
								targetIP := r.localProxyIP
								if targetIP == nil || targetIP.To4() != nil {
									targetIP = ip6Hdr.SrcIP
								}
								_ = RewriteIPv6TCP(rawPacket, nil, targetIP, 0, r.localProxyPort)
								addr.SetOutbound(false) // Inbound to local proxy listener
								addr.Flags |= WINDIVERT_ADDRESS_FLAG_IMPOSTOR
								_ = r.dll.CalcChecksums(rawPacket, &addr, 0)
							}
						}
					} else if ip6Hdr != nil && ip6Hdr.NextHeader == IPPROTO_UDP {
						srcPort, dstPort, _, dataOffset, err := ParseUDPFast(rawPacket, ihl)
						if err == nil {
							if dstPort == 443 {
								// ----------------------------------------------------
								// IPv6 UDP 443 (HTTP/3 QUIC) Interception:
								// Drop UDP 443 to force browsers to fallback to TCP/TLS.
								// ----------------------------------------------------
								if !r.dryRun {
									continue // Silently drop IPv6 QUIC packet
								}
							} else if dstPort == 53 && r.dnsEng != nil && !r.dryRun {
								// ----------------------------------------------------
								// IPv6 UDP 53 DNS Interception & DoH Dynamic Upgrade
								// ----------------------------------------------------
								payload := rawPacket[dataOffset:]
								clientAddr := &net.UDPAddr{
									IP:   ip6Hdr.SrcIP,
									Port: int(srcPort),
								}
								targetIP := ip6Hdr.DstIP

								rawCopy := append([]byte(nil), rawPacket...)
								payloadCopy := append([]byte(nil), payload...)
								origAddr := addr

								go func(cAddr net.Addr, tIP net.IP, sPort, dPort uint16, pld, rPkt []byte, oAddr WinDivertAddress) {
									defer func() {
										if rec := recover(); rec != nil {
											logger.Debugf("[DNS-v6] Recovered from panic in DNS handler: %v", rec)
										}
									}()

									respData, passthrough := r.dnsEng.ProcessDNSQuery(ctx, cAddr, tIP, pld)
									if passthrough {
										sendAddr := oAddr
										_, _ = r.dll.Send(r.handle, rPkt, &sendAddr)
										return
									}
									if len(respData) > 0 {
										respPkt := BuildIPv6UDPPacket(tIP, cAddr.(*net.UDPAddr).IP, dPort, sPort, respData)
										if respPkt != nil {
											injectAddr := oAddr
											injectAddr.SetOutbound(false)
											injectAddr.Flags |= WINDIVERT_ADDRESS_FLAG_IMPOSTOR
											injectAddr.Flags &^= WINDIVERT_ADDRESS_FLAG_LOOPBACK
											_ = r.dll.CalcChecksums(respPkt, &injectAddr, 0)
											_, _ = r.dll.Send(r.handle, respPkt, &injectAddr)
										}
									}
								}(clientAddr, targetIP, srcPort, dstPort, payloadCopy, rawCopy, origAddr)

								continue // Handled asynchronously
							}
						}
					}
				}

				// Reinject packet into network stack
				_, sendErr := r.dll.Send(r.handle, rawPacket, &addr)
				if sendErr != nil {
					log.Printf("[NAT-SEND] Reinjection failed (len=%d, IfIdx=%d, Flags=0x%x, Outbound=%v): %v",
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

			// Safe TTL of 3 minutes for inactive sessions (active sessions have LastSeen updated per packet)
			const sessionTTL = 3 * time.Minute

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

// Close closes the WinDivert handle and frees all resources.
func (r *Redirector) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	if r.handle != syscall.InvalidHandle {
		log.Printf("[Redirector] Closing WinDivert handle and restoring network state...")
		err := r.dll.Close(r.handle)
		r.handle = syscall.InvalidHandle
		return err
	}

	return nil
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
