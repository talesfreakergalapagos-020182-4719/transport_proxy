//go:build linux

package interceptor

import (
	"context"
	"testing"
)

func TestLinuxRedirector_Lifecycle(t *testing.T) {
	r, err := NewRedirector("127.0.0.1:18080", "")
	if err != nil {
		t.Fatalf("NewRedirector failed: %v", err)
	}

	// In dry-run mode, Start/Close should succeed without modifying iptables
	r.SetDryRun(true, "", nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start in dry-run mode failed: %v", err)
	}

	if err := r.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestLinuxRedirector_LookupOriginalDestinationConn_Nil(t *testing.T) {
	r, err := NewRedirector("127.0.0.1:18080", "")
	if err != nil {
		t.Fatalf("NewRedirector failed: %v", err)
	}

	ip, port, found := r.LookupOriginalDestinationConn(nil)
	if found || ip != nil || port != 0 {
		t.Errorf("Expected not found on nil conn, got ip=%v, port=%d, found=%v", ip, port, found)
	}
}
