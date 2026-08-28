package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

type cacheEntry struct {
	response []byte
	expireAt time.Time
}

// Cache provides a thread-safe in-memory cache for DNS responses.
type Cache struct {
	entries sync.Map // map[string]*cacheEntry
	maxTTL  time.Duration
}

// NewCache initializes a new DNS cache with the specified maximum TTL.
func NewCache(maxTTL time.Duration) *Cache {
	if maxTTL <= 0 {
		maxTTL = 300 * time.Second
	}
	return &Cache{
		maxTTL: maxTTL,
	}
}

func makeCacheKey(dstIP net.IP, qname string, qtype uint16) string {
	return fmt.Sprintf("%s|%s|%d", dstIP.String(), qname, qtype)
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
		c.entries.Delete(key)
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

	c.entries.Store(key, &cacheEntry{
		response: respCopy,
		expireAt: time.Now().Add(ttl),
	})
}

// Purge removes all entries from the cache.
func (c *Cache) Purge() {
	c.entries.Range(func(key, value any) bool {
		c.entries.Delete(key)
		return true
	})
}
