//go:build linux

package interceptor

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	SO_ORIGINAL_DST      = 80
	IP6T_SO_ORIGINAL_DST = 80
	SOL_IPV6             = 41
	iptablesChainName    = "TPROXY_RULES"
)

// Redirector handles Linux iptables packet redirection, SO_ORIGINAL_DST resolution, and local DNS interception.
type Redirector struct {
	localProxyPort  uint16
	localDNSUDPPort uint16
	filterStr       string
	dryRun          bool
	filterEng       FilterEvaluator
	routingEng      RoutingEvaluator
	dnsEng          DNSEvaluator
	dnsServers      []string
	dnsUDPConn      *net.UDPConn
	dnsUDPConn2     *net.UDPConn
	uid             int
	rulesApplied    bool
	mu              sync.Mutex
	closed          bool
}

// NewRedirector initializes a new Linux Redirector.
func NewRedirector(localListenAddr string, customFilter string) (*Redirector, error) {
	_, portStr, err := net.SplitHostPort(localListenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid listen address %s: %w", localListenAddr, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid listen port in %s", localListenAddr)
	}

	dnsPort := port + 100
	if dnsPort > 65535 {
		dnsPort = 18053
	}

	return &Redirector{
		localProxyPort:  uint16(port),
		localDNSUDPPort: uint16(dnsPort),
		filterStr:       customFilter,
		uid:             os.Geteuid(),
	}, nil
}

// SetDryRun configures dry-run mode.
func (r *Redirector) SetDryRun(dryRun bool, forwardCond string, filterEng FilterEvaluator, routingEng RoutingEvaluator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dryRun = dryRun
	r.filterEng = filterEng
	r.routingEng = routingEng
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
	r.dnsServers = dnsServers
}

// Start applies iptables redirection rules and starts local DNS interceptor.
func (r *Redirector) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return fmt.Errorf("redirector already closed")
	}

	if r.dryRun {
		log.Printf("[Redirector] Linux Dry-Run Mode ACTIVE: Passive monitoring without iptables redirection.")
		return nil
	}

	// 1. Start local UDP listener for default Cloudflare DoH interception when no custom DNS is configured
	if len(r.dnsServers) == 0 && r.dnsEng != nil {
		// Listener 1: For host queries (OUTPUT chain), bound to 127.0.0.1:port
		dnsAddr1, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", r.localDNSUDPPort))
		if err != nil {
			return fmt.Errorf("failed to resolve local DNS UDP address 1: %w", err)
		}
		conn1, err := net.ListenUDP("udp", dnsAddr1)
		if err != nil {
			return fmt.Errorf("failed to listen on local DNS UDP port %d: %w", r.localDNSUDPPort, err)
		}
		if err := setupUDPSocketOptions(conn1); err != nil {
			log.Printf("[Redirector] Warning: Failed to set UDP socket options: %v", err)
		}
		r.dnsUDPConn = conn1
		go r.dnsListenerLoop(ctx, conn1)

		// Listener 2: For Docker/forwarded queries (PREROUTING chain), bound to 0.0.0.0:port+1
		dnsAddr2, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", r.localDNSUDPPort+1))
		if err != nil {
			return fmt.Errorf("failed to resolve local DNS UDP address 2: %w", err)
		}
		conn2, err := net.ListenUDP("udp", dnsAddr2)
		if err != nil {
			return fmt.Errorf("failed to listen on local DNS UDP port %d: %w", r.localDNSUDPPort+1, err)
		}
		if err := setupUDPSocketOptions(conn2); err != nil {
			log.Printf("[Redirector] Warning: Failed to set UDP socket options: %v", err)
		}
		r.dnsUDPConn2 = conn2
		go r.dnsListenerLoop(ctx, conn2)

		log.Printf("[Redirector] DNS UDP Interceptor listening on 127.0.0.1:%d (Host) and :%d (Docker)", r.localDNSUDPPort, r.localDNSUDPPort+1)
	}

	// 2. Apply iptables redirection rules
	if err := r.applyIPTablesRules(); err != nil {
		if r.dnsUDPConn != nil {
			_ = r.dnsUDPConn.Close()
		}
		if r.dnsUDPConn2 != nil {
			_ = r.dnsUDPConn2.Close()
		}
		return fmt.Errorf("failed to configure iptables rules: %w", err)
	}
	r.rulesApplied = true

	if len(r.dnsServers) > 0 {
		log.Printf("[Redirector] Linux iptables REDIRECT rules active: TCP -> :%d (Custom DNS direct bypass: %v)",
			r.localProxyPort, r.dnsServers)
	} else {
		log.Printf("[Redirector] Linux iptables REDIRECT rules active: TCP -> :%d, DNS -> :%d (Cloudflare Security DoH)",
			r.localProxyPort, r.localDNSUDPPort)
	}

	return nil
}

// Close removes iptables redirection rules and releases DNS UDP listeners.
func (r *Redirector) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	if r.dnsUDPConn != nil {
		_ = r.dnsUDPConn.Close()
	}
	if r.dnsUDPConn2 != nil {
		_ = r.dnsUDPConn2.Close()
	}

	if r.rulesApplied {
		_ = r.removeIPTablesRules()
		r.rulesApplied = false
		log.Printf("[Redirector] Linux iptables rules cleaned up. Normal network routing restored.")
	}

	return nil
}

// LookupOriginalDestination is a fallback for RemoteAddr (SO_ORIGINAL_DST requires the net.Conn descriptor).
func (r *Redirector) LookupOriginalDestination(clientAddr net.Addr) (net.IP, uint16, bool) {
	return nil, 0, false
}

// LookupOriginalDestinationConn queries Linux kernel SO_ORIGINAL_DST on the client TCP socket.
func (r *Redirector) LookupOriginalDestinationConn(conn net.Conn) (net.IP, uint16, bool) {
	if conn == nil {
		return nil, 0, false
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, 0, false
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return nil, 0, false
	}

	var origIP net.IP
	var origPort uint16
	var sysErr error

	err = rawConn.Control(func(fd uintptr) {
		// Try IPv4 SO_ORIGINAL_DST
		var raw [16]byte
		var size uint32 = 16
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.SOL_IP),
			uintptr(SO_ORIGINAL_DST),
			uintptr(unsafe.Pointer(&raw[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno == 0 {
			origPort = binary.BigEndian.Uint16(raw[2:4])
			origIP = net.IPv4(raw[4], raw[5], raw[6], raw[7])
			return
		}

		// Try IPv6 IP6T_SO_ORIGINAL_DST
		var raw6 [28]byte
		var size6 uint32 = 28
		_, _, errno6 := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(SOL_IPV6),
			uintptr(IP6T_SO_ORIGINAL_DST),
			uintptr(unsafe.Pointer(&raw6[0])),
			uintptr(unsafe.Pointer(&size6)),
			0,
		)
		if errno6 == 0 {
			origPort = binary.BigEndian.Uint16(raw6[2:4])
			ipBytes := make([]byte, 16)
			copy(ipBytes, raw6[8:24])
			origIP = net.IP(ipBytes)
			return
		}

		sysErr = errno
	})

	if err != nil || sysErr != nil || origIP == nil || origPort == 0 {
		return nil, 0, false
	}

	return origIP, origPort, true
}

// DeleteSession is a no-op on Linux as the kernel manages NAT state.
func (r *Redirector) DeleteSession(clientAddr net.Addr) {
}

func setupUDPSocketOptions(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	return rawConn.Control(func(fd uintptr) {
		// IPv4 IP_RECVORIGDSTADDR (SOL_IP = 0, IP_RECVORIGDSTADDR = 20)
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, 20, 1)
		// IPv6 IPV6_RECVORIGDSTADDR (SOL_IPV6 = 41, IPV6_RECVORIGDSTADDR = 74)
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, 74, 1)
	})
}

func extractOrigDstIP(oob []byte) net.IP {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == 20 { // IP_RECVORIGDSTADDR
			if len(msg.Data) >= 8 {
				return net.IPv4(msg.Data[4], msg.Data[5], msg.Data[6], msg.Data[7])
			}
		}
		if msg.Header.Level == syscall.SOL_IPV6 && msg.Header.Type == 74 { // IPV6_RECVORIGDSTADDR
			if len(msg.Data) >= 24 {
				ip := make(net.IP, 16)
				copy(ip, msg.Data[8:24])
				return ip
			}
		}
	}
	return nil
}

func (r *Redirector) dnsListenerLoop(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, 4096)
	oob := make([]byte, 2048)

	// Default target: Cloudflare Security DNS
	defaultTargetIP := net.IPv4(1, 1, 1, 2)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, _, _, clientAddr, err := r.dnsUDPConn.ReadMsgUDP(buf, oob)
		if err != nil {
			r.mu.Lock()
			isClosed := r.closed
			r.mu.Unlock()
			if isClosed {
				return
			}
			continue
		}

		queryData := make([]byte, n)
		copy(queryData, buf[:n])

		go func(cAddr net.Addr, qData []byte) {
			if r.dnsEng == nil {
				return
			}
			respData, passthrough := r.dnsEng.ProcessDNSQuery(ctx, cAddr, defaultTargetIP, qData)
			if passthrough {
				respData = r.forwardUDPQuery(ctx, defaultTargetIP, 53, qData)
			}
			if len(respData) > 0 {
				_, _ = conn.WriteTo(respData, cAddr)
			}
		}(clientAddr, queryData)
	}
}

// forwardUDPQuery relays a DNS query to the target using a marked socket to bypass iptables.
func (r *Redirector) forwardUDPQuery(ctx context.Context, dstIP net.IP, port int, data []byte) []byte {
	targetAddr := &net.UDPAddr{IP: dstIP, Port: port}
	
	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// SO_MARK = 36 on Linux
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 36, 0xff)
			})
		},
	}
	
	conn, err := dialer.DialContext(ctx, "udp", targetAddr.String())
	if err != nil {
		log.Printf("[DNS] UDP Passthrough failed to dial %s: %v", targetAddr, err)
		return nil
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(data); err != nil {
		return nil
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

// applyIPTablesRules creates dedicated chain and sets up transparent redirection for both IPv4 and IPv6.
func (r *Redirector) applyIPTablesRules() error {
	// First clean any stale rules from a previous unclean run
	_ = r.removeIPTablesRules()

	proxyPortStr := strconv.Itoa(int(r.localProxyPort))
	dnsPortStr := strconv.Itoa(int(r.localDNSUDPPort))

	isCustomDNS := len(r.dnsServers) > 0

	// -------------------------------------------------------------
	// 1. Configure IPv4 iptables
	// -------------------------------------------------------------
	if err := execCmd("iptables", "-t", "nat", "-N", iptablesChainName); err != nil {
		return fmt.Errorf("failed to create iptables chain %s: %w", iptablesChainName, err)
	}

	// Bypass proxy's own outbound connections by SO_MARK (0xff) to prevent self-interception loops
	if err := execCmd("iptables", "-t", "nat", "-A", iptablesChainName, "-m", "mark", "--mark", "0xff", "-j", "RETURN"); err != nil {
		uidStr := strconv.Itoa(r.uid)
		_ = execCmd("iptables", "-t", "nat", "-A", iptablesChainName, "-m", "owner", "--uid-owner", uidStr, "-j", "RETURN")
	}

	// Bypass all loopback traffic (127.0.0.0/8) including local DNS (e.g. systemd-resolved 127.0.0.53)
	_ = execCmd("iptables", "-t", "nat", "-A", iptablesChainName, "-d", "127.0.0.0/8", "-j", "RETURN")

	// If custom DNS servers are specified, directly bypass them (allow direct plaintext UDP 53 communication)
	if isCustomDNS {
		for _, s := range r.dnsServers {
			ip := net.ParseIP(strings.TrimSpace(s))
			if ip != nil && ip.To4() != nil {
				_ = execCmd("iptables", "-t", "nat", "-A", iptablesChainName, "-d", ip.String(), "-p", "udp", "--dport", "53", "-j", "RETURN")
			}
		}
	} else if r.dnsEng != nil {
		// Default mode: Redirect outbound UDP 53 DNS to local DoH converter
		_ = execCmd("iptables", "-t", "nat", "-A", iptablesChainName, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dnsPortStr)
	}

	// Redirect outbound TCP to local proxy port
	if err := execCmd("iptables", "-t", "nat", "-A", iptablesChainName, "-p", "tcp", "-j", "REDIRECT", "--to-ports", proxyPortStr); err != nil {
		return fmt.Errorf("failed to add TCP redirect rule: %w", err)
	}

	// Link to OUTPUT chain (intercepts outbound traffic initiated from this host)
	if err := execCmd("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", iptablesChainName); err != nil {
		return fmt.Errorf("failed to hook into OUTPUT chain: %w", err)
	}

	// Link to PREROUTING chain (intercepts forwarded traffic, e.g., from Docker containers)
	_ = execCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-j", iptablesChainName)

	if !isCustomDNS && r.dnsEng != nil {
		dnsPort2Str := strconv.Itoa(int(r.localDNSUDPPort + 1))
		_ = execCmd("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
		_ = execCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dnsPort2Str)
	}

	// -------------------------------------------------------------
	// 2. Configure IPv6 ip6tables (Dual-Stack IPv4/IPv6 support)
	// -------------------------------------------------------------
	if err := execCmd("ip6tables", "-t", "nat", "-N", iptablesChainName); err == nil {
		if err := execCmd("ip6tables", "-t", "nat", "-A", iptablesChainName, "-m", "mark", "--mark", "0xff", "-j", "RETURN"); err != nil {
			uidStr := strconv.Itoa(r.uid)
			_ = execCmd("ip6tables", "-t", "nat", "-A", iptablesChainName, "-m", "owner", "--uid-owner", uidStr, "-j", "RETURN")
		}

		// Bypass IPv6 loopback (::1/128)
		_ = execCmd("ip6tables", "-t", "nat", "-A", iptablesChainName, "-d", "::1/128", "-j", "RETURN")

		if isCustomDNS {
			for _, s := range r.dnsServers {
				ip := net.ParseIP(strings.TrimSpace(s))
				if ip != nil && ip.To4() == nil {
					_ = execCmd("ip6tables", "-t", "nat", "-A", iptablesChainName, "-d", ip.String(), "-p", "udp", "--dport", "53", "-j", "RETURN")
				}
			}
		} else if r.dnsEng != nil {
			_ = execCmd("ip6tables", "-t", "nat", "-A", iptablesChainName, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dnsPortStr)
		}

		_ = execCmd("ip6tables", "-t", "nat", "-A", iptablesChainName, "-p", "tcp", "-j", "REDIRECT", "--to-ports", proxyPortStr)

		_ = execCmd("ip6tables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", iptablesChainName)
		_ = execCmd("ip6tables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-j", iptablesChainName)

		if !isCustomDNS && r.dnsEng != nil {
			dnsPort2Str := strconv.Itoa(int(r.localDNSUDPPort + 1))
			_ = execCmd("ip6tables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
			_ = execCmd("ip6tables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dnsPort2Str)
		}
	}

	return nil
}

// removeIPTablesRules tears down both IPv4 and IPv6 iptables chains cleanly.
func (r *Redirector) removeIPTablesRules() error {
	// IPv4 Unlink and flush
	_ = execCmd("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", iptablesChainName)
	_ = execCmd("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
	_ = execCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-j", iptablesChainName)
	_ = execCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
	_ = execCmd("iptables", "-t", "nat", "-F", iptablesChainName)
	_ = execCmd("iptables", "-t", "nat", "-X", iptablesChainName)

	// IPv6 Unlink and flush
	_ = execCmd("ip6tables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", iptablesChainName)
	_ = execCmd("ip6tables", "-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
	_ = execCmd("ip6tables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-j", iptablesChainName)
	_ = execCmd("ip6tables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
	_ = execCmd("ip6tables", "-t", "nat", "-F", iptablesChainName)
	_ = execCmd("ip6tables", "-t", "nat", "-X", iptablesChainName)

	return nil
}

// CleanupIPTables can be invoked from CLI (--cleanup) or crash handler.
func CleanupIPTables() error {
	// IPv4 cleanup
	_ = execCmd("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", iptablesChainName)
	_ = execCmd("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
	_ = execCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-j", iptablesChainName)
	_ = execCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
	_ = execCmd("iptables", "-t", "nat", "-F", iptablesChainName)
	_ = execCmd("iptables", "-t", "nat", "-X", iptablesChainName)

	// IPv6 cleanup
	_ = execCmd("ip6tables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", iptablesChainName)
	_ = execCmd("ip6tables", "-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
	_ = execCmd("ip6tables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-j", iptablesChainName)
	_ = execCmd("ip6tables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
	_ = execCmd("ip6tables", "-t", "nat", "-F", iptablesChainName)
	_ = execCmd("ip6tables", "-t", "nat", "-X", iptablesChainName)
	return nil
}

func execCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
