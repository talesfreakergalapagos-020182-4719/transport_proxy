//go:build windows

package proxy

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"

	"transport_proxy/internal/config"
)

var outboundPortCounter atomic.Uint32

// isPortBindError checks if the error is caused by a local port binding conflict (WSAEADDRINUSE / WSAEACCES / bind failure).
func isPortBindError(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		// Windows: WSAEACCES (10013), WSAEADDRINUSE (10048)
		if errno == 10013 || errno == 10048 {
			return true
		}
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "bind:") || strings.Contains(errStr, "address already in use") || strings.Contains(errStr, "access is denied")
}

// dialTCP connects to the given network address using a local port bound
// to the reserved range to prevent WinDivert self-interception loop.
func (f *Forwarder) dialTCP(network, address string) (net.Conn, error) {
	const (
		maxAttempts = 50
	)
	rangeSize := config.OutboundPortMax - config.OutboundPortMin + 1

	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		port := int(config.OutboundPortMin) + int(outboundPortCounter.Add(1)%uint32(rangeSize))
		dialer := &net.Dialer{
			Timeout:   f.connectTimeout,
			LocalAddr: &net.TCPAddr{Port: port},
			Control: func(network, address string, c syscall.RawConn) error {
				var sockErr error
				err := c.Control(func(fd uintptr) {
					sockErr = setReuseAddr(fd)
				})
				if err != nil {
					return err
				}
				return sockErr
			},
		}

		conn, err := dialer.Dial(network, address)
		if err == nil {
			OptimizeTCPConn(conn)
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.SetLinger(0) // Prevent TIME_WAIT port exhaustion on reserved outbound range
			}
			return conn, nil
		}
		lastErr = err

		// If the error is not a local port binding collision (e.g. target actively refused, timed out, host unreachable),
		// retrying different local ports will never succeed. Return immediately to avoid wasting 50 SYN attempts.
		if !isPortBindError(err) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("dial to %s failed (after %d port-range attempts: %w)", address, maxAttempts, lastErr)
}

