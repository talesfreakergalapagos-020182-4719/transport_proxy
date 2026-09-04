//go:build windows

package interceptor

import (
	"context"
	"net"
	"testing"
)

type dummyDNSEvaluator struct{}

func (d *dummyDNSEvaluator) ProcessDNSQuery(ctx context.Context, clientAddr net.Addr, dstIP net.IP, payload []byte) (respData []byte, passthrough bool) {
	return nil, true
}

func TestRedirector_SetDNSServers_Toggle(t *testing.T) {
	r := &Redirector{}
	mockEng := &dummyDNSEvaluator{}

	// 1. Initially set DNS engine
	r.SetDNSEngine(mockEng)
	if r.dnsEng != mockEng {
		t.Fatalf("Expected dnsEng to be set initially")
	}

	// 2. Setting custom DNS servers should disable interception (dnsEng becomes nil)
	r.SetDNSServers([]string{"10.0.0.1", "10.0.0.2"})
	if r.dnsEng != nil {
		t.Errorf("Expected dnsEng to be nil when custom DNS is configured")
	}

	// 3. Resetting custom DNS servers to empty should restore the original DNS engine
	r.SetDNSServers([]string{})
	if r.dnsEng != mockEng {
		t.Errorf("Expected dnsEng to be restored to original engine when dns_servers is empty")
	}

	// 4. Resetting with nil slice should also restore
	r.SetDNSServers([]string{"8.8.8.8"})
	if r.dnsEng != nil {
		t.Errorf("Expected dnsEng to be nil again")
	}
	r.SetDNSServers(nil)
	if r.dnsEng != mockEng {
		t.Errorf("Expected dnsEng to be restored when nil slice passed")
	}
}
