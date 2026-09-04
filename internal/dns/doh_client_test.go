package dns

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type mockTransport struct {
	rt     http.RoundTripper
	mockURL string
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = m.mockURL
	return m.rt.RoundTrip(req)
}

func TestDoHClient_QueryDoH_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST method, got %s", r.Method)
		}
		dummyResp := []byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
		w.WriteHeader(http.StatusOK)
		w.Write(dummyResp)
	}))
	defer ts.Close()

	client := NewDoHClient(5*time.Second, nil)
	client.client.Transport = &mockTransport{
		rt:      http.DefaultTransport,
		mockURL: ts.Listener.Addr().String(),
	}

	ctx := context.Background()
	dstIP := net.ParseIP("1.1.1.1")
	query := []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01}
	
	resp, err := client.QueryDoH(ctx, dstIP, query)
	if err != nil {
		t.Fatalf("QueryDoH failed: %v", err)
	}
	if len(resp) < 12 {
		t.Errorf("unexpected response length: %d", len(resp))
	}
}

func TestBuildDoHURL(t *testing.T) {
	ipv4 := net.ParseIP("1.1.1.1")
	if url := BuildDoHURL(ipv4); url != "https://1.1.1.1/dns-query" {
		t.Errorf("unexpected IPv4 DoH URL: %s", url)
	}

	ipv6 := net.ParseIP("2606:4700:4700::1111")
	if url := BuildDoHURL(ipv6); url != "https://[2606:4700:4700::1111]/dns-query" {
		t.Errorf("unexpected IPv6 DoH URL: %s", url)
	}
}

func TestDoHClient_QueryDoH_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer ts.Close()

	client := NewDoHClient(2*time.Second, nil)
	client.client.Transport = &mockTransport{
		rt:      http.DefaultTransport,
		mockURL: ts.Listener.Addr().String(),
	}

	ctx := context.Background()
	dstIP := net.ParseIP("1.1.1.1")
	query := []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01}

	_, err := client.QueryDoH(ctx, dstIP, query)
	if err == nil {
		t.Errorf("Expected error for HTTP 500 response, got nil")
	}

	// Test SetTimeout
	client.SetTimeout(10 * time.Second)
	if client.timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", client.timeout)
	}
}

func TestProbeManager_MarkStatus(t *testing.T) {
	dohClient := NewDoHClient(2*time.Second, nil)
	pm := NewProbeManager(dohClient, 5*time.Minute)

	testIP := net.ParseIP("9.9.9.9")

	// Initially unknown
	if status := pm.GetStatus(testIP); status != StatusUnknown {
		t.Errorf("Expected StatusUnknown initially, got %v", status)
	}

	// Mark supported
	pm.MarkStatus(testIP, StatusSupported)
	if status := pm.GetStatus(testIP); status != StatusSupported {
		t.Errorf("Expected StatusSupported, got %v", status)
	}

	ctx := context.Background()
	if !pm.CheckOrProbe(ctx, testIP) {
		t.Errorf("Expected CheckOrProbe to return true for StatusSupported")
	}

	// Mark unsupported
	pm.MarkStatus(testIP, StatusUnsupported)
	if status := pm.GetStatus(testIP); status != StatusUnsupported {
		t.Errorf("Expected StatusUnsupported, got %v", status)
	}
	if pm.CheckOrProbe(ctx, testIP) {
		t.Errorf("Expected CheckOrProbe to return false for StatusUnsupported")
	}
}
