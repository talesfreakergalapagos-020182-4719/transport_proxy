//go:build ignore

package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"time"
)

func main() {
	f, err := os.Open("log.txt")
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	defer f.Close()

	var deltas []float64
	var lastTime time.Time
	scanner := bufio.NewScanner(f)
	layout := "2006/01/02 15:04:05.000000"

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 26 {
			continue
		}
		tStr := line[:26]
		t, err := time.Parse(layout, tStr)
		if err != nil {
			continue
		}
		if !lastTime.IsZero() {
			diff := t.Sub(lastTime).Seconds() * 1000.0 // ms
			if diff >= 0 {
				deltas = append(deltas, diff)
			}
		}
		lastTime = t
	}

	sort.Float64s(deltas)
	if len(deltas) == 0 {
		return
	}

	sum := 0.0
	for _, d := range deltas {
		sum += d
	}
	p50 := deltas[len(deltas)/2]
	p90 := deltas[int(float64(len(deltas))*0.90)]
	p95 := deltas[int(float64(len(deltas))*0.95)]
	p99 := deltas[int(float64(len(deltas))*0.99)]

	fmt.Printf("Total line intervals: %d\n", len(deltas))
	fmt.Printf("Min: %.2f ms | Avg: %.2f ms | Median(p50): %.2f ms | p90: %.2f ms | p95: %.2f ms | p99: %.2f ms | Max: %.2f ms\n",
		deltas[0], sum/float64(len(deltas)), p50, p90, p95, p99, deltas[len(deltas)-1])

	// Histogram
	buckets := []struct {
		name string
		min  float64
		max  float64
		cnt  int
	}{
		{"< 1ms", 0, 1, 0},
		{"1ms - 10ms", 1, 10, 0},
		{"10ms - 25ms", 10, 25, 0},
		{"25ms - 50ms", 25, 50, 0},
		{"50ms - 100ms", 50, 100, 0},
		{"100ms - 250ms", 100, 250, 0},
		{">= 250ms", 250, 1e9, 0},
	}

	for _, d := range deltas {
		for i := range buckets {
			if d >= buckets[i].min && d < buckets[i].max {
				buckets[i].cnt++
				break
			}
		}
	}

	fmt.Println("\n--- Interval Distribution ---")
	for _, b := range buckets {
		fmt.Printf("  %-15s: %5d lines (%5.1f%%)\n", b.name, b.cnt, float64(b.cnt)/float64(len(deltas))*100)
	}
}
