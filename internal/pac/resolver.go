package pac

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ProxyDecision represents the routing decision for a destination.
type ProxyDecision struct {
	IsDirect bool   // True if traffic should bypass proxy and connect directly
	ProxyURL string // Resolved upstream proxy URL, e.g. "http://proxy.corp.local:8080"
}

type cachedEntry struct {
	decision  ProxyDecision
	expiresAt time.Time
}

// Resolver resolves proxy routing decisions for target destinations using PAC or static config.
type Resolver struct {
	pacURL      string
	staticProxy string
	isPACMode   bool
	session     *WinHTTPSession
	mu          sync.RWMutex
	cache       sync.Map // map[string]*cachedEntry (lock-free concurrent cache)
	stopChan    chan struct{}
}

const (
	maxCacheEntries = 2000             // Maximum cache entries to prevent memory growth
	cacheTTL        = 10 * time.Minute // TTL for PAC evaluation cache
)

// NewResolver initializes a new proxy routing resolver.
func NewResolver(pacURL string, staticProxy string) (*Resolver, error) {
	r := &Resolver{
		pacURL:      strings.TrimSpace(pacURL),
		staticProxy: strings.TrimSpace(staticProxy),
		stopChan:    make(chan struct{}),
	}

	// Auto-detect if staticProxy is actually a PAC URL
	if r.pacURL == "" && r.staticProxy != "" {
		lower := strings.ToLower(r.staticProxy)
		if strings.HasSuffix(lower, ".pac") || strings.HasSuffix(lower, ".dat") || strings.HasPrefix(lower, "pac+") {
			r.pacURL = strings.TrimPrefix(r.staticProxy, "pac+")
			r.staticProxy = ""
		}
	}

	// If no explicit PAC/proxy configured in config.json, auto-detect Windows OS proxy settings
	if r.pacURL == "" && r.staticProxy == "" {
		r.applyOSProxyConfig()
	} else if r.pacURL != "" {
		r.isPACMode = true
	}

	if r.isPACMode {
		session, err := NewWinHTTPSession("tproxy-pac/1.0")
		if err != nil {
			return nil, fmt.Errorf("failed to initialize WinHTTP session for PAC: %w", err)
		}
		r.session = session
		if r.pacURL != "" {
			log.Printf("[PAC] Initialized PAC resolver with URL: %s", r.pacURL)
		} else {
			log.Printf("[PAC] Initialized WinHTTP WPAD auto-detect mode")
		}
	} else if r.staticProxy != "" {
		log.Printf("[Proxy] Initialized static upstream proxy: %s", r.staticProxy)
	} else {
		log.Printf("[Proxy] Initialized direct outbound mode (no proxy/PAC configured)")
	}

	go r.cacheCleanupLoop()

	return r, nil
}

// applyOSProxyConfig attempts to detect proxy / PAC settings from Windows Internet Options.
func (r *Resolver) applyOSProxyConfig() {
	ieCfg, err := GetIEProxyConfigForCurrentUser()
	if err != nil {
		return
	}

	if ieCfg.AutoConfigURL != "" {
		r.pacURL = ieCfg.AutoConfigURL
		r.isPACMode = true
		log.Printf("[PAC] Auto-detected Windows PAC script: %s", r.pacURL)
	} else if ieCfg.Proxy != "" {
		r.staticProxy = ieCfg.Proxy
		r.isPACMode = false
		log.Printf("[Proxy] Auto-detected Windows Proxy: %s", r.staticProxy)
	} else if ieCfg.AutoDetect {
		log.Printf("[PAC] Auto-detecting WPAD PAC script via DHCP/DNS...")
		wpadURL, err := DetectAutoProxyConfigURL()
		if err == nil && wpadURL != "" {
			r.pacURL = wpadURL
			r.isPACMode = true
			log.Printf("[PAC] Auto-detected WPAD PAC script: %s", r.pacURL)
		} else {
			r.isPACMode = false
			r.pacURL = ""
			log.Printf("[PAC] WPAD auto-detection: No WPAD PAC script found on local network. Defaulting to DIRECT mode.")
		}
	}
}

// UpdateConfig updates the PAC and static proxy configuration dynamically.
func (r *Resolver) UpdateConfig(pacURL string, staticProxy string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pacURL = strings.TrimSpace(pacURL)
	staticProxy = strings.TrimSpace(staticProxy)

	if pacURL == "" && staticProxy != "" {
		lower := strings.ToLower(staticProxy)
		if strings.HasSuffix(lower, ".pac") || strings.HasSuffix(lower, ".dat") || strings.HasPrefix(lower, "pac+") {
			pacURL = strings.TrimPrefix(staticProxy, "pac+")
			staticProxy = ""
		}
	}

	r.pacURL = pacURL
	r.staticProxy = staticProxy
	r.isPACMode = false

	if r.pacURL == "" && r.staticProxy == "" {
		r.applyOSProxyConfig()
	} else if r.pacURL != "" {
		r.isPACMode = true
	}

	r.cache.Range(func(key, value any) bool {
		r.cache.Delete(key)
		return true
	})

	if r.isPACMode {
		if r.session == nil {
			session, err := NewWinHTTPSession("tproxy-pac/1.0")
			if err == nil {
				r.session = session
			}
		}
		if r.pacURL != "" {
			log.Printf("[PAC] Updated PAC URL to: %s", r.pacURL)
		} else {
			log.Printf("[PAC] Updated to WinHTTP WPAD auto-detect mode")
		}
	} else {
		if r.session != nil {
			r.session.Close()
			r.session = nil
		}
		if r.staticProxy != "" {
			log.Printf("[Proxy] Updated to static proxy: %s", r.staticProxy)
		} else {
			log.Printf("[Proxy] Updated to Direct mode (no proxy/PAC configured)")
		}
	}
}

// Resolve returns the ProxyDecision for a given destination host and port.
func (r *Resolver) Resolve(targetHost string, targetPort uint16) (ProxyDecision, error) {
	r.mu.RLock()
	isPAC := r.isPACMode
	pacURL := r.pacURL
	staticProxy := r.staticProxy
	session := r.session
	r.mu.RUnlock()

	if !isPAC {
		if staticProxy == "" {
			return ProxyDecision{IsDirect: true}, nil
		}
		return ProxyDecision{IsDirect: false, ProxyURL: normalizeProxyURL(staticProxy)}, nil
	}

	if session == nil {
		if staticProxy != "" {
			return ProxyDecision{IsDirect: false, ProxyURL: normalizeProxyURL(staticProxy)}, nil
		}
		return ProxyDecision{IsDirect: true}, nil
	}

	// Construct target URL for PAC evaluation
	scheme := "https"
	if targetPort == 80 {
		scheme = "http"
	}
	hostOnly := targetHost
	if h, _, err := net.SplitHostPort(targetHost); err == nil {
		hostOnly = h
	}
	targetURL := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(hostOnly, fmt.Sprintf("%d", targetPort)))

	// Check lock-free cache
	now := time.Now()
	if val, found := r.cache.Load(targetURL); found {
		entry := val.(*cachedEntry)
		if now.Before(entry.expiresAt) {
			return entry.decision, nil
		}
	}

	isDirect, rawProxyList, err := session.GetProxyForURL(targetURL, pacURL)
	if err != nil {
		log.Printf("[PAC] Evaluation error for %s: %v. Falling back to direct/static.", targetURL, err)
		fallbackDecision := ProxyDecision{IsDirect: true}
		if staticProxy != "" {
			fallbackDecision = ProxyDecision{IsDirect: false, ProxyURL: normalizeProxyURL(staticProxy)}
		}
		r.cache.Store(targetURL, &cachedEntry{
			decision:  fallbackDecision,
			expiresAt: now.Add(1 * time.Minute),
		})
		return fallbackDecision, nil
	}

	decision := ProxyDecision{}
	if isDirect || rawProxyList == "" {
		decision.IsDirect = true
	} else {
		firstProxy := parseFirstProxy(rawProxyList)
		if firstProxy == "" || strings.EqualFold(firstProxy, "DIRECT") {
			decision.IsDirect = true
		} else {
			decision.IsDirect = false
			decision.ProxyURL = normalizeProxyURL(firstProxy)
		}
	}

	// Store in cache
	r.cache.Store(targetURL, &cachedEntry{
		decision:  decision,
		expiresAt: now.Add(cacheTTL),
	})

	return decision, nil
}

// ResolveRouting implements the interceptor.RoutingEvaluator interface.
func (r *Resolver) ResolveRouting(targetHost string, targetPort uint16) (bool, string, error) {
	d, err := r.Resolve(targetHost, targetPort)
	return d.IsDirect, d.ProxyURL, err
}

func (r *Resolver) cacheCleanupLoop() {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[PAC] Recovered from panic in cacheCleanupLoop: %v", rec)
		}
	}()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopChan:
			return
		case <-ticker.C:
			now := time.Now()
			r.cache.Range(func(k, v any) bool {
				entry := v.(*cachedEntry)
				if now.After(entry.expiresAt) {
					r.cache.Delete(k)
				}
				return true
			})
		}
	}
}

// Close closes the resolver and releases WinHTTP resources.
func (r *Resolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-r.stopChan:
	default:
		close(r.stopChan)
	}

	if r.session != nil {
		r.session.Close()
		r.session = nil
	}
}

func parseFirstProxy(proxyList string) string {
	parts := strings.Split(proxyList, ";")
	if len(parts) == 0 {
		return ""
	}
	first := strings.TrimSpace(parts[0])
	fields := strings.Fields(first)
	if len(fields) == 2 {
		return fields[1]
	}
	if len(fields) == 1 {
		return fields[0]
	}
	return first
}

func normalizeProxyURL(p string) string {
	p = strings.TrimSpace(p)
	if !strings.Contains(p, "://") {
		return "http://" + p
	}
	u, err := url.Parse(p)
	if err != nil {
		return "http://" + p
	}
	return u.String()
}
