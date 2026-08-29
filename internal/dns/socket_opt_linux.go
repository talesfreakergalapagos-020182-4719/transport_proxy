//go:build linux

package dns

import "syscall"

const (
	SO_MARK    = 36
	TProxyMark = 0xff
)

func setReuseAddr(fd uintptr) error {
	// Mark socket so iptables OUTPUT rule bypasses this DoH client's outbound connections
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_MARK, TProxyMark)
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
