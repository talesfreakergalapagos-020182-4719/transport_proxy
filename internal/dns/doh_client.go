package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"transport_proxy/internal/logger"
	"transport_proxy/internal/pac"
)

// ProxyDecisionResolver resolves upstream proxy URL if configured.
type ProxyDecisionResolver interface {
	Resolve(targetHost string, targetPort uint16) (pac.ProxyDecision, error)
}

// DoHClient performs DNS-over-HTTPS (RFC 8484) queries using standard IP-certificate TLS validation.
type DoHClient struct {
	client     *http.Client
	timeout    time.Duration
}

// NewDoHClient initializes a new DoH client with connection pooling and loop-preventing dialer.
func NewDoHClient(timeout time.Duration, pacResolver ProxyDecisionResolver) *DoHClient {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	dialer := createDoHDialContext(timeout)

	tr := &http.Transport{
		DialContext: dialer,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // Enforce strict TLS certificate verification against target IP SAN
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	if pacResolver != nil {
		tr.Proxy = func(req *http.Request) (*url.URL, error) {
			host := req.URL.Hostname()
			port := uint16(443)
			decision, err := pacResolver.Resolve(host, port)
			if err != nil || decision.IsDirect || decision.ProxyURL == "" {
				return nil, nil // Direct
			}
			return url.Parse(decision.ProxyURL)
		}
	}

	return &DoHClient{
		client: &http.Client{
			Transport: tr,
			Timeout:   timeout,
		},
		timeout: timeout,
	}
}

// BuildDoHURL constructs the standard DoH endpoint URL for a given IP address.
func BuildDoHURL(ip net.IP) string {
	if ip.To4() != nil {
		return fmt.Sprintf("https://%s/dns-query", ip.String())
	}
	return fmt.Sprintf("https://[%s]/dns-query", ip.String())
}

// QueryDoH sends a raw DNS wire format query to https://<dstIP>/dns-query via HTTP POST.
// Returns the raw DNS response bytes from the DoH server.
func (c *DoHClient) QueryDoH(ctx context.Context, dstIP net.IP, queryWire []byte) ([]byte, error) {
	dohURL := BuildDoHURL(dstIP)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(queryWire))
	if err != nil {
		return nil, fmt.Errorf("failed to create DoH request for %s: %w", dohURL, err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	startTime := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH query to %s failed: %w", dohURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("DoH server %s returned HTTP status %d: %s", dohURL, resp.StatusCode, string(bodySnippet))
	}

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response from %s: %w", dohURL, err)
	}

	if len(respBytes) < 12 {
		return nil, fmt.Errorf("DoH response from %s too short (%d bytes)", dohURL, len(respBytes))
	}

	logger.Debugf("[DoH] Query to %s completed in %v (Response %d bytes)", dohURL, time.Since(startTime).Round(time.Millisecond), len(respBytes))
	return respBytes, nil
}
