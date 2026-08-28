//go:build ignore

package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type TargetStat struct {
	Count     int
	SentBytes int64
	RecvBytes int64
}

func parseBytes(s string) int64 {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, " ")
	if len(parts) < 2 {
		return 0
	}
	val, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0
	}
	unit := parts[1]
	switch unit {
	case "B":
		return int64(val)
	case "KB":
		return int64(val * 1024)
	case "MB":
		return int64(val * 1024 * 1024)
	case "GB":
		return int64(val * 1024 * 1024 * 1024)
	}
	return int64(val)
}

func parseDuration(s string) time.Duration {
	s = strings.TrimSpace(s)
	d, _ := time.ParseDuration(s)
	return d
}

func main() {
	f, err := os.Open("log.txt")
	if err != nil {
		fmt.Printf("Error opening log.txt: %v\n", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	allowRe := regexp.MustCompile(`\[ALLOW\]\s+([A-Za-z0-9_-]+)\s+\|\s+Client:\s+([^|]+)\s+\|\s+Target:\s+([^\s|]+)`)
	closeRe := regexp.MustCompile(`\[CLOSE\]\s+Client:\s+([^|]+)\s+\|\s+Target:\s+([^|]+)\s+\|\s+Sent:\s+([^|]+)\s+\|\s+Recv:\s+([^|]+)\s+\|\s+Duration:\s+([^\r\n]+)`)
	dohRe := regexp.MustCompile(`\[ALLOW\]\s+DNS-DoH\s+\|\s+Client:\s+([^|]+)\s+\|\s+Target:\s+([^|]+)\s+\|\s+Query:\s+([^\s]+)\s+\(([^)]+)\)\s+->\s+DoH\s+\((\d+)ms\)`)

	totalLines := 0
	protoCounts := make(map[string]int)
	clientIPs := make(map[string]int)
	targetStats := make(map[string]*TargetStat)
	var dohLatencies []int
	var durations []time.Duration
	var totalSent, totalRecv int64

	v4Count, v6Count := 0, 0
	startTime, endTime := "", ""

	for scanner.Scan() {
		line := scanner.Text()
		totalLines++

		if len(line) >= 26 && strings.HasPrefix(line, "2026/") {
			if startTime == "" {
				startTime = line[:26]
			}
			endTime = line[:26]
		}

		if m := dohRe.FindStringSubmatch(line); len(m) > 0 {
			lat, _ := strconv.Atoi(m[5])
			dohLatencies = append(dohLatencies, lat)
		}

		if m := allowRe.FindStringSubmatch(line); len(m) > 0 {
			proto := m[1]
			client := strings.TrimSpace(m[2])
			target := strings.TrimSpace(m[3])

			protoCounts[proto]++
			if strings.HasPrefix(client, "[") || strings.Contains(client, ":") && strings.Count(client, ":") > 1 {
				v6Count++
			} else {
				v4Count++
			}

			clientHost := client
			if h, _, err := strings.Cut(client, "]:"); err {
				clientHost = h + "]"
			} else if h, _, err := strings.Cut(client, ":"); err {
				clientHost = h
			}
			clientIPs[clientHost]++

			st, exists := targetStats[target]
			if !exists {
				st = &TargetStat{}
				targetStats[target] = st
			}
			st.Count++
		}

		if m := closeRe.FindStringSubmatch(line); len(m) > 0 {
			target := strings.TrimSpace(m[2])
			sent := parseBytes(m[3])
			recv := parseBytes(m[4])
			dur := parseDuration(m[5])

			totalSent += sent
			totalRecv += recv
			durations = append(durations, dur)

			st, exists := targetStats[target]
			if !exists {
				st = &TargetStat{}
				targetStats[target] = st
			}
			st.SentBytes += sent
			st.RecvBytes += recv
		}
	}

	fmt.Println("================================================================")
	fmt.Println("               TRANSPORT PROXY LOG COMPREHENSIVE AUDIT           ")
	fmt.Println("================================================================")
	fmt.Printf("Log Time Span:     %s -> %s\n", startTime, endTime)
	fmt.Printf("Total Log Lines:   %d\n", totalLines)
	fmt.Printf("Total ALLOW Events:%d\n", v4Count+v6Count)
	fmt.Printf("Total CLOSE Events:%d\n", len(durations))
	fmt.Printf("Total Traffic:     Sent: %.2f MB | Recv: %.2f MB | Total: %.2f MB\n",
		float64(totalSent)/(1024*1024), float64(totalRecv)/(1024*1024), float64(totalSent+totalRecv)/(1024*1024))

	fmt.Println("\n--- [Protocol Breakdown] ---")
	for p, c := range protoCounts {
		fmt.Printf("  %-10s: %5d requests (%5.1f%%)\n", p, c, float64(c)/float64(v4Count+v6Count)*100)
	}

	fmt.Println("\n--- [Client Address Family] ---")
	fmt.Printf("  IPv4: %5d requests (%5.1f%%)\n", v4Count, float64(v4Count)/float64(v4Count+v6Count)*100)
	fmt.Printf("  IPv6: %5d requests (%5.1f%%)\n", v6Count, float64(v6Count)/float64(v4Count+v6Count)*100)

	fmt.Println("\n--- [DoH Latency Statistics] ---")
	if len(dohLatencies) > 0 {
		sort.Ints(dohLatencies)
		sum := 0
		for _, l := range dohLatencies {
			sum += l
		}
		p50 := dohLatencies[len(dohLatencies)/2]
		p95 := dohLatencies[int(float64(len(dohLatencies))*0.95)]
		p99 := dohLatencies[int(float64(len(dohLatencies))*0.99)]
		fmt.Printf("  Count: %d | Min: %dms | Avg: %.2fms | p50: %dms | p95: %dms | p99: %dms | Max: %dms\n",
			len(dohLatencies), dohLatencies[0], float64(sum)/float64(len(dohLatencies)), p50, p95, p99, dohLatencies[len(dohLatencies)-1])
	}

	fmt.Println("\n--- [Connection Duration Distribution] ---")
	sub100ms, sub1s, sub10s, sub1m, over1m := 0, 0, 0, 0, 0
	for _, d := range durations {
		if d < 100*time.Millisecond {
			sub100ms++
		} else if d < 1*time.Second {
			sub1s++
		} else if d < 10*time.Second {
			sub10s++
		} else if d < 1*time.Minute {
			sub1m++
		} else {
			over1m++
		}
	}
	fmt.Printf("  < 100ms:     %4d (%5.1f%%)\n", sub100ms, float64(sub100ms)/float64(len(durations))*100)
	fmt.Printf("  100ms - 1s:  %4d (%5.1f%%)\n", sub1s, float64(sub1s)/float64(len(durations))*100)
	fmt.Printf("  1s - 10s:    %4d (%5.1f%%)\n", sub10s, float64(sub10s)/float64(len(durations))*100)
	fmt.Printf("  10s - 1m:    %4d (%5.1f%%)\n", sub1m, float64(sub1m)/float64(len(durations))*100)
	fmt.Printf("  >= 1m:       %4d (%5.1f%%)\n", over1m, float64(over1m)/float64(len(durations))*100)

	type kv struct {
		Target string
		Stat   *TargetStat
	}
	var list []kv
	for k, v := range targetStats {
		list = append(list, kv{k, v})
	}

	// Sort by Request Count
	sort.Slice(list, func(i, j int) bool {
		return list[i].Stat.Count > list[j].Stat.Count
	})
	fmt.Println("\n--- [Top 10 Targets by Request Count] ---")
	for i := 0; i < len(list) && i < 10; i++ {
		fmt.Printf("  %2d. %-45s: %4d reqs (Sent: %9.1f KB, Recv: %9.1f KB)\n",
			i+1, list[i].Target, list[i].Stat.Count, float64(list[i].Stat.SentBytes)/1024, float64(list[i].Stat.RecvBytes)/1024)
	}

	// Sort by Bandwidth
	sort.Slice(list, func(i, j int) bool {
		return (list[i].Stat.SentBytes + list[i].Stat.RecvBytes) > (list[j].Stat.SentBytes + list[j].Stat.RecvBytes)
	})
	fmt.Println("\n--- [Top 10 Targets by Data Volume] ---")
	for i := 0; i < len(list) && i < 10; i++ {
		total := list[i].Stat.SentBytes + list[i].Stat.RecvBytes
		fmt.Printf("  %2d. %-45s: %8.2f MB (Sent: %7.2f MB, Recv: %7.2f MB, Reqs: %d)\n",
			i+1, list[i].Target, float64(total)/(1024*1024),
			float64(list[i].Stat.SentBytes)/(1024*1024), float64(list[i].Stat.RecvBytes)/(1024*1024), list[i].Stat.Count)
	}
}
