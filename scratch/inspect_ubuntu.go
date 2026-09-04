//go:build ignore

package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func main() {
	f, err := os.Open("log.txt")
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	
	allowMap := make(map[string]string) // client -> target
	pipeStartMap := make(map[string]string)
	
	allowRe := regexp.MustCompile(`\[ALLOW\]\s+([A-Za-z0-9_-]+)\s+\|\s+Client:\s+([^|]+)\s+\|\s+Target:\s+([^\s|]+)`)
	closeRe := regexp.MustCompile(`\[CLOSE\]\s+Client:\s+([^|]+)\s+\|\s+Target:\s+([^|]+)\s+\|\s+Sent:\s+([^|]+)\s+\|\s+Recv:\s+([^|]+)\s+\|\s+Duration:\s+([^\r\n]+)`)
	pipeRe := regexp.MustCompile(`\[PIPE\]\s+PipeConn finished for Client:\s+([^<]+)<->\s+Upstream:\s+([^(]+)\s+\(Client->Up:\s+(\d+)\s+B,\s+Up->Client:\s+(\d+)\s+B\)`)
	pipeStartRe := regexp.MustCompile(`\[PIPE-DOWN\] Started: Upstream \(([^)]+)\) -> Client \(([^)]+)\)`)

	var closedConns []string
	closedSet := make(map[string]bool)

	for scanner.Scan() {
		line := scanner.Text()
		
		if m := allowRe.FindStringSubmatch(line); len(m) > 0 {
			client := strings.TrimSpace(m[2])
			target := strings.TrimSpace(m[3])
			allowMap[client] = target
		}

		if m := pipeStartRe.FindStringSubmatch(line); len(m) > 0 {
			up := strings.TrimSpace(m[1])
			client := strings.TrimSpace(m[2])
			pipeStartMap[client] = up
		}

		if m := pipeRe.FindStringSubmatch(line); len(m) > 0 {
			client := strings.TrimSpace(m[1])
			up := strings.TrimSpace(m[2])
			upBytes := m[3]
			downBytes := m[4]
			closedConns = append(closedConns, fmt.Sprintf("PIPE END: Client %s <-> %s | Up: %s B, Down: %s B", client, up, upBytes, downBytes))
			closedSet[client] = true
		}

		if m := closeRe.FindStringSubmatch(line); len(m) > 0 {
			client := strings.TrimSpace(m[1])
			target := strings.TrimSpace(m[2])
			sent := strings.TrimSpace(m[3])
			recv := strings.TrimSpace(m[4])
			dur := strings.TrimSpace(m[5])
			closedConns = append(closedConns, fmt.Sprintf("CLOSE: %s -> %s (Sent: %s, Recv: %s, Dur: %s)", client, target, sent, recv, dur))
			closedSet[client] = true
		}
	}

	fmt.Println("=== Active / Ongoing Connections (Started but not Closed) ===")
	activeCount := 0
	for client, target := range allowMap {
		if !closedSet[client] {
			activeCount++
			fmt.Printf("  ACTIVE: Client %s -> Target %s (Upstream: %s)\n", client, target, pipeStartMap[client])
		}
	}
	if activeCount == 0 {
		fmt.Println("  (No active connections found)")
	}

	fmt.Println("\n=== Recent Closed Connections with > 100KB transfer ===")
	for _, c := range closedConns {
		if strings.Contains(c, "MB") || strings.Contains(c, "KB") {
			// filter small
			if strings.Contains(c, "MB") || strings.Contains(c, "09.") || strings.Contains(c, "516.") || strings.Contains(c, "123.") {
				fmt.Println("  " + c)
			}
		}
	}
}
