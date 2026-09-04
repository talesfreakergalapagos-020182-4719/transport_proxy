//go:build ignore

package main

import (
	"bufio"
	"fmt"
	"os"
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
	var events []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "[ALLOW]") ||
			strings.Contains(line, "[CLOSE]") ||
			strings.Contains(line, "[BLOCK]") ||
			strings.Contains(line, "[ERROR]") {
			if strings.Contains(line, "22:04:") || strings.Contains(line, "22:05:") || strings.Contains(line, "22:06:") {
				events = append(events, line)
			}
		}
	}

	fmt.Printf("Total recent events (22:04 - 22:06): %d\n", len(events))
	// Print last 60 events
	start := 0
	if len(events) > 60 {
		start = len(events) - 60
	}
	for _, ev := range events[start:] {
		fmt.Println(ev)
	}
}
