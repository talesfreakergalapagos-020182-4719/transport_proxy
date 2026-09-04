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
	coalesce   *CoalesceGroup
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
		coalesce:   NewCoalesceGroup(),
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

	// Sanitize target IP: Loopback, unspecified, or private IPs cannot be public DoH servers.
	// When custom DNS is not configured, safely fallback to Cloudflare Security DoH.
	targetIP := dstIP
	if targetIP == nil || targetIP.IsLoopback() || targetIP.IsUnspecified() || (targetIP.IsPrivate() && !cfg.IsCustomDNS()) {
		if targetIP != nil && targetIP.To4() == nil && len(targetIP) == net.IPv6len {
			targetIP = net.ParseIP("2606:4700:4700::1112")
		} else {
			targetIP = net.IPv4(1, 1, 1, 2)
		}
	}
	targetDisplay := net.JoinHostPort(targetIP.String(), "53")

	// 2. Policy Filtering Evaluation (Whitelist / Blacklist)
	if e.filterEng != nil && e.filterEng.ShouldBlock(qname) {
		log.Printf("[BLOCK] DNS     | Client: %-21s | Target: %-30s | Query: %s (%s) -> Blocked by policy",
			clientAddr.String(), targetDisplay, qname, typeStr)
		resp := BuildErrorResponse(payload, RCodeNXDomain)
		return resp, false
	}

	// 3. DNS Answer Cache Check (0ms resolution)
	if e.cache != nil && cfg.DNSCacheEnabled {
		if cachedResp, hit := e.cache.Get(targetIP, qname, qtype, msg.Header.ID); hit {
			logger.Debugf("[DNS]   CACHE HIT | Client: %s | Target: %s | Query: %s (%s)",
				clientAddr.String(), targetDisplay, qname, typeStr)
			return cachedResp, false
		}
	}

	// 5. Dynamic DoH Capability Check (or Active Probe on first encounter)
	isDoHCapable := e.probeMgr.CheckOrProbe(ctx, targetIP)
	if !isDoHCapable {
		return nil, true // Passthrough to normal UDP 53
	}

	// 6. Execute DoH Query with Query Coalescing (Singleflight) to deduplicate simultaneous bursts
	startTime := time.Now()
	dohResp, shared, dohErr := e.coalesce.Do(targetIP, qname, qtype, func() ([]byte, error) {
		return e.dohClient.QueryDoH(ctx, targetIP, payload)
	})
	duration := time.Since(startTime).Round(time.Millisecond)

	if dohErr != nil {
		logger.Debugf("[DNS]   DoH query to %s failed: %v", BuildDoHURL(targetIP), dohErr)
		if cfg.FallbackToUDP {
			logger.Debugf("[DNS]   Falling back to standard UDP 53 for %s", targetDisplay)
			return nil, true
		}
		// ServFail response if fallback disabled
		return BuildErrorResponse(payload, RCodeServFail), false
	}

	// Store original clean dohResp in cache before ID modification
	if !shared && e.cache != nil && cfg.DNSCacheEnabled {
		e.cache.Set(targetIP, qname, qtype, dohResp)
	}

	// Return defensive copy matching client transaction ID to prevent race condition across coalesced callers
	clientResp := append([]byte(nil), dohResp...)
	if len(clientResp) >= 2 {
		clientResp[0] = payload[0]
		clientResp[1] = payload[1]
	}

	tag := "DoH"
	if shared {
		tag = "DoH-Coalesced"
	}
	log.Printf("[ALLOW] DNS-DoH | Client: %-21s | Target: %-30s | Query: %-25s (%s) -> %s (%v)",
		clientAddr.String(), targetDisplay, qname, typeStr, tag, duration)

	return clientResp, false
}

// UpdateConfig dynamically updates DoH client timeouts and cache parameters on config reload.
func (e *Engine) UpdateConfig(newCfg *config.Config) {
	if newCfg == nil {
		return
	}

	dohTimeout := time.Duration(newCfg.DohTimeoutSec) * time.Second
	if dohTimeout <= 0 {
		dohTimeout = 3 * time.Second
	}
	if e.dohClient != nil {
		e.dohClient.SetTimeout(dohTimeout)
	}

	if e.cache != nil {
		if !newCfg.DNSCacheEnabled {
			e.cache.Purge()
		} else {
			ttl := time.Duration(newCfg.DNSCacheTTLSec) * time.Second
			e.cache.SetMaxTTL(ttl)
		}
	} else if newCfg.DNSCacheEnabled {
		ttl := time.Duration(newCfg.DNSCacheTTLSec) * time.Second
		e.cache = NewCache(ttl)
	}
}

