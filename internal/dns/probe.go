package dns

import (
	"context"
	"net"
	"sync"
	"time"

	"transport_proxy/internal/logger"
)

// DoHSupportStatus represents the cached DoH capability status of a DNS server IP.
type DoHSupportStatus uint8

const (
	StatusUnknown DoHSupportStatus = iota
	StatusSupported
	StatusUnsupported
)

type probeEntry struct {
	status   DoHSupportStatus
	expireAt time.Time
}

// ProbeManager caches and dynamically tests DNS server IPs for DoH support.
type ProbeManager struct {
	cache       sync.Map // map[string]*probeEntry
	probeMu     sync.Map // map[string]*sync.Mutex for coalescing concurrent probes to same IP
	cacheTTL    time.Duration
	dohClient      *DoHClient
}

// NewProbeManager creates a new DoH ProbeManager.
func NewProbeManager(dohClient *DoHClient, cacheTTL time.Duration) *ProbeManager {
	if cacheTTL <= 0 {
		cacheTTL = 1 * time.Hour
	}

	pm := &ProbeManager{
		cacheTTL:       cacheTTL,
		dohClient:      dohClient,
	}

	return pm
}

// GetStatus returns the cached DoH status for an IP without performing a network probe.
func (pm *ProbeManager) GetStatus(ip net.IP) DoHSupportStatus {

	key := ip.String()
	val, ok := pm.cache.Load(key)
	if !ok {
		return StatusUnknown
	}

	entry := val.(*probeEntry)
	if time.Now().After(entry.expireAt) {
		pm.cache.Delete(key)
		return StatusUnknown
	}

	return entry.status
}

// CheckOrProbe checks cached status or sends a test DoH probe query to determine support.
func (pm *ProbeManager) CheckOrProbe(ctx context.Context, ip net.IP) bool {

	status := pm.GetStatus(ip)
	if status == StatusSupported {
		return true
	}
	if status == StatusUnsupported {
		return false
	}

	// Coalesce concurrent probes to the same IP
	ipStr := ip.String()
	muVal, _ := pm.probeMu.LoadOrStore(ipStr, &sync.Mutex{})
	mu := muVal.(*sync.Mutex)
	mu.Lock()
	defer func() {
		mu.Unlock()
	}()

	// Double-check cache after acquiring lock
	status = pm.GetStatus(ip)
	if status != StatusUnknown {
		return status == StatusSupported
	}

	// Perform probe with standard test query (A record for cloudflare.com)
	testQuery := []byte{
		0x00, 0x01, // ID = 1
		0x01, 0x00, // Standard Query, Recursion Desired
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
		0x0a, 'c', 'l', 'o', 'u', 'd', 'f', 'l', 'a', 'r', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // QTYPE = A
		0x00, 0x01, // QCLASS = IN
	}

	probeCtx, cancel := context.WithTimeout(ctx, pm.dohClient.timeout)
	defer cancel()

	resp, err := pm.dohClient.QueryDoH(probeCtx, ip, testQuery)
	now := time.Now()

	if err == nil && len(resp) >= 12 {
		logger.Infof("[DoH-Probe] DNS Server %s verified SUPPORTED for DoH (IP SAN TLS Certificate OK)", ipStr)
		pm.cache.Store(ipStr, &probeEntry{
			status:   StatusSupported,
			expireAt: now.Add(pm.cacheTTL),
		})
		return true
	}

	logger.Debugf("[DoH-Probe] DNS Server %s is NOT DoH-capable (%v) -> Will use standard UDP 53 passthrough", ipStr, err)
	pm.cache.Store(ipStr, &probeEntry{
		status:   StatusUnsupported,
		expireAt: now.Add(pm.cacheTTL),
	})
	return false
}

// MarkStatus manually sets the DoH status for an IP.
func (pm *ProbeManager) MarkStatus(ip net.IP, status DoHSupportStatus) {
	pm.cache.Store(ip.String(), &probeEntry{
		status:   status,
		expireAt: time.Now().Add(pm.cacheTTL),
	})
}
