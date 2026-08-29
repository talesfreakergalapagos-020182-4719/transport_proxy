//go:build windows

package proxy

import (
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
)

var outboundPortCounter atomic.Uint32

// dialTCP connects to the given network address using a local port bound
// to the reserved range (40000-48999) to prevent WinDivert self-interception loop.
func (f *Forwarder) dialTCP(network, address string) (net.Conn, error) {
	const (
		portMin     = 40000
		portMax     = 48999
		rangeSize   = portMax - portMin + 1
		maxAttempts = 50
	)

	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		port := portMin + int(outboundPortCounter.Add(1)%rangeSize)
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
	}

	return nil, fmt.Errorf("dial to %s failed (after %d port-range attempts: %v)", address, maxAttempts, lastErr)
}
