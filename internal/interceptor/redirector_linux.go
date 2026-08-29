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
	localProxyPort uint16
	localDNSUDPPort uint16
	filterStr      string
	dryRun         bool
	filterEng      FilterEvaluator
	routingEng     RoutingEvaluator
	dnsEng         DNSEvaluator
	dnsUDPConn     *net.UDPConn
	uid            int
	rulesApplied   bool
	mu             sync.Mutex
	closed         bool
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

	// 1. Start local UDP listener for DNS interception if DNS engine is attached
	if r.dnsEng != nil {
		dnsAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", r.localDNSUDPPort))
		if err != nil {
			return fmt.Errorf("failed to resolve local DNS UDP address: %w", err)
		}
		conn, err := net.ListenUDP("udp", dnsAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on local DNS UDP port %d: %w", r.localDNSUDPPort, err)
		}
		
		if err := setupUDPSocketOptions(conn); err != nil {
			log.Printf("[Redirector] Warning: Failed to set UDP original destination socket options: %v", err)
		}

		r.dnsUDPConn = conn
		go r.dnsListenerLoop(ctx)
		log.Printf("[Redirector] DNS UDP Interceptor listening on 127.0.0.1:%d", r.localDNSUDPPort)
	}

	// 2. Apply iptables redirection rules
	if err := r.applyIPTablesRules(); err != nil {
		if r.dnsUDPConn != nil {
			_ = r.dnsUDPConn.Close()
		}
		return fmt.Errorf("failed to configure iptables rules: %w", err)
	}
	r.rulesApplied = true

	log.Printf("[Redirector] Linux iptables REDIRECT rules active: TCP -> :%d, DNS -> :%d (SO_MARK 0xff bypassed)",
		r.localProxyPort, r.localDNSUDPPort)

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

func (r *Redirector) dnsListenerLoop(ctx context.Context) {
	buf := make([]byte, 4096)
	oob := make([]byte, 2048)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, oobn, _, clientAddr, err := r.dnsUDPConn.ReadMsgUDP(buf, oob)
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

		origIP := extractOrigDstIP(oob[:oobn])
		if origIP == nil {
			// Fallback to local loopback if original destination extraction fails
			origIP = net.IPv4(127, 0, 0, 1)
		}

		go func(cAddr net.Addr, qData []byte, dstIP net.IP) {
			if r.dnsEng == nil {
				return
			}
			respData, passthrough := r.dnsEng.ProcessDNSQuery(ctx, cAddr, dstIP, qData)
			if !passthrough && len(respData) > 0 {
				_, _ = r.dnsUDPConn.WriteTo(respData, cAddr)
			}
		}(clientAddr, queryData, origIP)
	}
}

// applyIPTablesRules creates dedicated chain and sets up transparent redirection for both IPv4 and IPv6.
func (r *Redirector) applyIPTablesRules() error {
	// First clean any stale rules from a previous unclean run
	_ = r.removeIPTablesRules()

	proxyPortStr := strconv.Itoa(int(r.localProxyPort))
	dnsPortStr := strconv.Itoa(int(r.localDNSUDPPort))

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

	// Redirect outbound UDP 53 DNS to local DNS UDP listener if enabled (Do this BEFORE loopback bypass to catch 127.0.0.42/53 etc)
	if r.dnsEng != nil {
		_ = execCmd("iptables", "-t", "nat", "-A", iptablesChainName, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dnsPortStr)
	}

	// Bypass loopback traffic (for TCP and other non-DNS traffic)
	_ = execCmd("iptables", "-t", "nat", "-A", iptablesChainName, "-d", "127.0.0.0/8", "-j", "RETURN")

	// Redirect outbound TCP to local proxy port
	if err := execCmd("iptables", "-t", "nat", "-A", iptablesChainName, "-p", "tcp", "-j", "REDIRECT", "--to-ports", proxyPortStr); err != nil {
		return fmt.Errorf("failed to add TCP redirect rule: %w", err)
	}

	// Link to OUTPUT and PREROUTING chains (handles local processes and routed traffic)
	if err := execCmd("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", iptablesChainName); err != nil {
		return fmt.Errorf("failed to hook into OUTPUT chain: %w", err)
	}
	_ = execCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-j", iptablesChainName)

	if r.dnsEng != nil {
		_ = execCmd("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
		_ = execCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
	}

	// -------------------------------------------------------------
	// 2. Configure IPv6 ip6tables (Dual-Stack IPv4/IPv6 support)
	// -------------------------------------------------------------
	if err := execCmd("ip6tables", "-t", "nat", "-N", iptablesChainName); err == nil {
		if err := execCmd("ip6tables", "-t", "nat", "-A", iptablesChainName, "-m", "mark", "--mark", "0xff", "-j", "RETURN"); err != nil {
			uidStr := strconv.Itoa(r.uid)
			_ = execCmd("ip6tables", "-t", "nat", "-A", iptablesChainName, "-m", "owner", "--uid-owner", uidStr, "-j", "RETURN")
		}

		if r.dnsEng != nil {
			_ = execCmd("ip6tables", "-t", "nat", "-A", iptablesChainName, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", dnsPortStr)
		}

		_ = execCmd("ip6tables", "-t", "nat", "-A", iptablesChainName, "-d", "::1/128", "-j", "RETURN")
		_ = execCmd("ip6tables", "-t", "nat", "-A", iptablesChainName, "-p", "tcp", "-j", "REDIRECT", "--to-ports", proxyPortStr)

		_ = execCmd("ip6tables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", iptablesChainName)
		_ = execCmd("ip6tables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-j", iptablesChainName)

		if r.dnsEng != nil {
			_ = execCmd("ip6tables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
			_ = execCmd("ip6tables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "53", "-j", iptablesChainName)
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
