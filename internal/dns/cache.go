package dns

import (
	"encoding/binary"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const maxDNSCacheEntries = 10000

type cacheEntry struct {
	response []byte
	expireAt time.Time
}

// Cache provides a thread-safe in-memory cache for DNS responses.
type Cache struct {
	entries  sync.Map // map[CacheKey]*cacheEntry
	count    atomic.Int32
	maxTTL   time.Duration
	stopChan chan struct{}
	stopOnce sync.Once
}

// NewCache initializes a new DNS cache with the specified maximum TTL and starts background cleanup.
func NewCache(maxTTL time.Duration) *Cache {
	if maxTTL <= 0 {
		maxTTL = 300 * time.Second
	}
	c := &Cache{
		maxTTL:   maxTTL,
		stopChan: make(chan struct{}),
	}
	go c.cleanupLoop()
	runtime.SetFinalizer(c, (*Cache).Stop)
	return c
}

// CacheKey uniquely identifies a cached DNS query without string heap allocations.
type CacheKey struct {
	IP    [16]byte
	QType uint16
	QName string
}

func makeCacheKey(dstIP net.IP, qname string, qtype uint16) CacheKey {
	var k CacheKey
	if ip4 := dstIP.To4(); ip4 != nil {
		copy(k.IP[:4], ip4)
	} else {
		copy(k.IP[:], dstIP)
	}
	k.QType = qtype
	k.QName = qname
	return k
}

// Get looks up a cached response for the given query and rewrites the transaction ID to match reqID.
func (c *Cache) Get(dstIP net.IP, qname string, qtype uint16, reqID uint16) ([]byte, bool) {
	key := makeCacheKey(dstIP, qname, qtype)
	val, ok := c.entries.Load(key)
	if !ok {
		return nil, false
	}

	entry := val.(*cacheEntry)
	if time.Now().After(entry.expireAt) {
		if _, loaded := c.entries.LoadAndDelete(key); loaded {
			c.count.Add(-1)
		}
		return nil, false
	}

	// Make a defensive copy and update the Transaction ID (bytes 0-1) to match client's query ID
	resp := make([]byte, len(entry.response))
	copy(resp, entry.response)
	binary.BigEndian.PutUint16(resp[0:2], reqID)

	return resp, true
}

// Set stores a raw DNS response in cache with its extracted TTL (clamped by maxTTL).
func (c *Cache) Set(dstIP net.IP, qname string, qtype uint16, resp []byte) {
	if len(resp) < 12 {
		return
	}

	minTTLSec := ExtractMinTTL(resp, uint32(c.maxTTL.Seconds()))
	ttl := time.Duration(minTTLSec) * time.Second
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	if ttl < 5*time.Second {
		ttl = 5 * time.Second // Minimum 5s cache
	}

	key := makeCacheKey(dstIP, qname, qtype)
	// Store copy
	respCopy := make([]byte, len(resp))
	copy(respCopy, resp)

	entry := &cacheEntry{
		response: respCopy,
		expireAt: time.Now().Add(ttl),
	}

	if _, loaded := c.entries.Swap(key, entry); !loaded {
		if c.count.Add(1) > maxDNSCacheEntries {
			// Capacity limit exceeded: proactively purge expired entries
			c.evictExpired()
		}
	}
}

// Purge removes all entries from the cache.
func (c *Cache) Purge() {
	c.entries.Range(func(key, value any) bool {
		c.entries.Delete(key)
		return true
	})
	c.count.Store(0)
}

// evictExpired removes expired entries from the cache to release memory.
func (c *Cache) evictExpired() {
	now := time.Now()
	c.entries.Range(func(key, value any) bool {
		entry := value.(*cacheEntry)
		if now.After(entry.expireAt) {
			if _, loaded := c.entries.LoadAndDelete(key); loaded {
				c.count.Add(-1)
			}
		}
		return true
	})
}

func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.evictExpired()
		}
	}
}

// Stop stops the background cleanup goroutine.
func (c *Cache) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopChan)
	})
}

// SetMaxTTL updates the maximum TTL for future cached responses.
func (c *Cache) SetMaxTTL(maxTTL time.Duration) {
	if maxTTL <= 0 {
		maxTTL = 300 * time.Second
	}
	c.maxTTL = maxTTL
}

