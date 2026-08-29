//go:build linux

package interceptor

import (
	"context"
	"time"
)

// PortGuard for Linux is a no-op stub since Linux iptables uses --uid-owner to prevent proxy self-loops cleanly.
type PortGuard struct {
	portMin uint16
	portMax uint16
}

// NewPortGuard initializes a Linux PortGuard stub.
func NewPortGuard(portMin, portMax uint16) *PortGuard {
	return &PortGuard{
		portMin: portMin,
		portMax: portMax,
	}
}

// Start on Linux is a no-op.
func (pg *PortGuard) Start(ctx context.Context, scanInterval time.Duration) {
}

// Stop on Linux is a no-op.
func (pg *PortGuard) Stop() {
}
