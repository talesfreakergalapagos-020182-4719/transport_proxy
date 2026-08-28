package dns

import (
	"context"
	"log"
	"net"
	"time"

	"transport_proxy/internal/config"
	"transport_proxy/internal/logger"
)

// FilterEvaluator checks if a host or domain should be blocked.
type FilterEvaluator interface {
	ShouldBlock(hostOrIP string) bool
}

// Engine orchestrates DNS interception, policy filtering, dynamic DoH probing, caching, and fallback.
type Engine struct {
	cfgMgr     *config.Manager
	filterEng  FilterEvaluator
	dohClient  *DoHClient
	probeMgr   *ProbeManager
	cache      *Cache
	pacResolve ProxyDecisionResolver
}

// NewEngine creates and initializes the DNS interception engine.
func NewEngine(cfgMgr *config.Manager, filterEng FilterEvaluator, pacResolver ProxyDecisionResolver) *Engine {
	cfg := cfgMgr.Get()
	dohTimeout := time.Duration(cfg.DohTimeoutSec) * time.Second
	if dohTimeout <= 0 {
		dohTimeout = 3 * time.Second
	}

	dohClient := NewDoHClient(dohTimeout, pacResolver)
	probeMgr := NewProbeManager(dohClient, 1*time.Hour)

	var cache *Cache
	if cfg.DNSCacheEnabled {
		ttl := time.Duration(cfg.DNSCacheTTLSec) * time.Second
		cache = NewCache(ttl)
	}

	eng := &Engine{
		cfgMgr:     cfgMgr,
		filterEng:  filterEng,
		dohClient:  dohClient,
		probeMgr:   probeMgr,
		cache:      cache,
		pacResolve: pacResolver,
	}

	return eng
}

// ProcessDNSQuery processes an intercepted DNS query packet.
// Returns:
//   - respData: DNS response wire bytes to inject to client if resolved by DoH/Cache/Block.
//   - passthrough: true if query should be passed through to original DNS server via normal UDP 53.
func (e *Engine) ProcessDNSQuery(ctx context.Context, clientAddr net.Addr, dstIP net.IP, payload []byte) (respData []byte, passthrough bool) {
	cfg := e.cfgMgr.Get()
	if !cfg.DohEnabled {
		return nil, true // Pass through when DoH is disabled
	}

	// 1. Parse raw query to extract question domain
	msg, err := ParseQuery(payload)
	if err != nil || len(msg.Questions) == 0 {
		// Unparseable DNS payload - pass through safely
		return nil, true
	}

	q := msg.Questions[0]
	qname := q.Name
	qtype := q.Type
	typeStr := TypeToString(qtype)
	targetDisplay := net.JoinHostPort(dstIP.String(), "53")

	// 2. Policy Filtering Evaluation (Whitelist / Blacklist)
	if e.filterEng != nil && e.filterEng.ShouldBlock(qname) {
		log.Printf("[BLOCK] DNS     | Client: %-21s | Target: %-30s | Query: %s (%s) -> Blocked by policy",
			clientAddr.String(), targetDisplay, qname, typeStr)
		resp := BuildErrorResponse(payload, RCodeNXDomain)
		return resp, false
	}

	// 3. Private / Local DNS IP Check (Immediate Passthrough without probing)
	if e.probeMgr.IsPrivateIP(dstIP) {
		logger.Debugf("[DNS]   Private/Local DNS IP %s -> Passing through without DoH", targetDisplay)
		return nil, true
	}

	// 4. DNS Answer Cache Check (0ms resolution)
	if e.cache != nil && cfg.DNSCacheEnabled {
		if cachedResp, hit := e.cache.Get(dstIP, qname, qtype, msg.Header.ID); hit {
			logger.Debugf("[DNS]   CACHE HIT | Client: %s | Target: %s | Query: %s (%s)",
				clientAddr.String(), targetDisplay, qname, typeStr)
			return cachedResp, false
		}
	}

	// 5. Dynamic DoH Capability Check (or Active Probe on first encounter)
	isDoHCapable := e.probeMgr.CheckOrProbe(ctx, dstIP)
	if !isDoHCapable {
		return nil, true // Passthrough to normal UDP 53
	}

	// 6. Execute DoH Query (HTTPS POST application/dns-message)
	startTime := time.Now()
	dohResp, dohErr := e.dohClient.QueryDoH(ctx, dstIP, payload)
	duration := time.Since(startTime).Round(time.Millisecond)

	if dohErr != nil {
		logger.Debugf("[DNS]   DoH query to %s failed: %v", BuildDoHURL(dstIP), dohErr)
		if cfg.FallbackToUDP {
			logger.Debugf("[DNS]   Falling back to standard UDP 53 for %s", targetDisplay)
			return nil, true
		}
		// ServFail response if fallback disabled
		return BuildErrorResponse(payload, RCodeServFail), false
	}

	// Match client transaction ID
	if len(dohResp) >= 2 {
		dohResp[0] = payload[0]
		dohResp[1] = payload[1]
	}

	// Store in cache
	if e.cache != nil && cfg.DNSCacheEnabled {
		e.cache.Set(dstIP, qname, qtype, dohResp)
	}

	log.Printf("[ALLOW] DNS-DoH | Client: %-21s | Target: %-30s | Query: %-25s (%s) -> DoH (%v)",
		clientAddr.String(), targetDisplay, qname, typeStr, duration)

	return dohResp, false
}
