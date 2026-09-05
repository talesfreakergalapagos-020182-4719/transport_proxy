package dns

import (
	"fmt"
	"net"
	"sync"
)

type coalesceCall struct {
	wg  sync.WaitGroup
	val []byte
	err error
}

// CoalesceGroup deduplicates simultaneous in-flight DNS DoH queries for the same (dstIP, qname, qtype).
// This prevents redundant upstream queries and spikes during concurrent bursts.
type CoalesceGroup struct {
	mu sync.Mutex
	m  map[string]*coalesceCall
}

// NewCoalesceGroup initializes a new query coalescing group.
func NewCoalesceGroup() *CoalesceGroup {
	return &CoalesceGroup{
		m: make(map[string]*coalesceCall),
	}
}

func makeCoalesceKey(dstIP net.IP, qname string, qtype uint16) string {
	return fmt.Sprintf("%s:%s:%d", dstIP.String(), qname, qtype)
}

// Do executes fn for the given key, ensuring that only one execution is in-flight for a given key at a time.
// If duplicate queries arrive while the primary query is in flight, they wait and receive the identical result.
// Returns:
//   - val: DNS response wire bytes (defensive copy)
//   - shared: true if this request was coalesced with another concurrent in-flight query
//   - err: query error if any
func (g *CoalesceGroup) Do(dstIP net.IP, qname string, qtype uint16, fn func() ([]byte, error)) ([]byte, bool, error) {
	key := makeCoalesceKey(dstIP, qname, qtype)

	g.mu.Lock()
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		if c.err != nil {
			return nil, true, c.err
		}
		respCopy := make([]byte, len(c.val))
		copy(respCopy, c.val)
		return respCopy, true, nil
	}

	c := new(coalesceCall)
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	panicked := true
	defer func() {
		if r := recover(); r != nil || panicked {
			if c.err == nil {
				c.err = fmt.Errorf("dns coalesce query panicked: %v", r)
			}
			g.mu.Lock()
			delete(g.m, key)
			g.mu.Unlock()
			c.wg.Done()
			if r != nil {
				panic(r)
			}
			return
		}
		g.mu.Lock()
		delete(g.m, key)
		g.mu.Unlock()
		c.wg.Done()
	}()

	c.val, c.err = fn()
	panicked = false

	if c.err != nil {
		return nil, false, c.err
	}
	respCopy := make([]byte, len(c.val))
	copy(respCopy, c.val)
	return respCopy, false, nil
}
