//go:build linux

package proxy

import (
	"net"
	"syscall"
)

// dialTCP connects to the given network address.
// On Linux, SO_MARK (0xff) is set on the socket via setReuseAddr to bypass iptables rules.
// LocalAddr is left nil so the OS kernel instantly assigns an ephemeral port, eliminating port contention.
func (f *Forwarder) dialTCP(network, address string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: f.connectTimeout,
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
	if err != nil {
		return nil, err
	}
	OptimizeTCPConn(conn)
	return conn, nil
}
