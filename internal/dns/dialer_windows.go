//go:build windows

package dns

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"
	"transport_proxy/internal/config"
)

var dohOutboundPortCounter atomic.Uint32

func createDoHDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		const (
			portMin     = config.OutboundPortMin
			portMax     = config.OutboundPortMax
			rangeSize   = portMax - portMin + 1
			maxAttempts = 50
		)

		var lastErr error
		for i := 0; i < maxAttempts; i++ {
			port := portMin + uint16(dohOutboundPortCounter.Add(1)%uint32(rangeSize))
			netDialer := &net.Dialer{
				Timeout:   timeout,
				LocalAddr: &net.TCPAddr{Port: int(port)},
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

			conn, err := netDialer.DialContext(ctx, network, addr)
			if err == nil {
				if tc, ok := conn.(*net.TCPConn); ok {
					_ = tc.SetNoDelay(true)
					_ = tc.SetKeepAlive(true)
					_ = tc.SetKeepAlivePeriod(30 * time.Second)
				}
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("doh dialer: all port attempts failed: %w", lastErr)
	}
}
