package dns

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCoalesceGroup_Deduplication(t *testing.T) {
	g := NewCoalesceGroup()
	dstIP := net.ParseIP("1.1.1.2")
	qname := "api.github.com"
	qtype := TypeA

	var execCount atomic.Int32
	var wg sync.WaitGroup
	const numGoroutines = 50

	results := make([][]byte, numGoroutines)
	sharedFlags := make([]bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res, shared, err := g.Do(dstIP, qname, qtype, func() ([]byte, error) {
				execCount.Add(1)
				time.Sleep(30 * time.Millisecond) // Simulate network latency
				return []byte("dns-answer-payload"), nil
			})
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			results[idx] = res
			sharedFlags[idx] = shared
		}(i)
	}

	wg.Wait()

	// The actual function should have been called only once or very few times (typically 1)
	if count := execCount.Load(); count != 1 {
		t.Errorf("Expected exactly 1 underlying execution, got %d", count)
	}

	// All goroutines must receive the identical payload
	for i := 0; i < numGoroutines; i++ {
		if string(results[i]) != "dns-answer-payload" {
			t.Errorf("Goroutine %d received unexpected result: %s", i, string(results[i]))
		}
	}
}

func TestCoalesceGroup_ErrorPropagation(t *testing.T) {
	g := NewCoalesceGroup()
	dstIP := net.ParseIP("1.1.1.2")
	qname := "failing.domain"
	qtype := TypeAAAA

	expectedErr := errors.New("upstream timeout")
	var wg sync.WaitGroup
	const numGoroutines = 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := g.Do(dstIP, qname, qtype, func() ([]byte, error) {
				time.Sleep(20 * time.Millisecond)
				return nil, expectedErr
			})
			if !errors.Is(err, expectedErr) {
				t.Errorf("Expected %v, got %v", expectedErr, err)
			}
		}()
	}

	wg.Wait()
}

func TestCoalesceGroup_PanicSafety(t *testing.T) {
	g := NewCoalesceGroup()
	dstIP := net.ParseIP("1.1.1.2")
	qname := "panic.domain"
	qtype := TypeA

	var wg sync.WaitGroup

	// 1. Primary caller panics
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			_ = recover() // Catch expected panic
		}()
		_, _, _ = g.Do(dstIP, qname, qtype, func() ([]byte, error) {
			time.Sleep(10 * time.Millisecond)
			panic("simulated fatal panic inside DoH")
		})
	}()

	// 2. Secondary concurrent caller must not deadlock
	wg.Add(1)
	var secondaryDone bool
	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Millisecond) // Ensure primary has registered call
		_, _, _ = g.Do(dstIP, qname, qtype, func() ([]byte, error) {
			return []byte("fallback"), nil
		})
		secondaryDone = true
	}()

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if !secondaryDone {
			t.Errorf("Expected secondary caller to complete without deadlock")
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("Deadlock detected! WaitGroup did not complete after panic")
	}

	// 3. Subsequent calls on the same key must work normally (key was cleaned up)
	res, shared, err := g.Do(dstIP, qname, qtype, func() ([]byte, error) {
		return []byte("recovered"), nil
	})
	if err != nil || string(res) != "recovered" || shared {
		t.Errorf("Subsequent call failed: res=%s, shared=%v, err=%v", string(res), shared, err)
	}
}

