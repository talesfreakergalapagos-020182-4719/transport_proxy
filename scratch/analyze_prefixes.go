//go:build ignore

package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
)

func main() {
	f, err := os.Open("log.txt")
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	defer f.Close()

	counts := make(map[string]int)
	re := regexp.MustCompile(`^2026/\d\d/\d\d \d\d:\d\d:\d\d\.\d+ \[(.*?)\]`)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		m := re.FindStringSubmatch(line)
		if len(m) > 1 {
			tag := m[1]
			// collapse details like "RNAT" / "RNAT-v6" or "NAT" / "NAT-v6"
			counts[tag]++
		} else {
			counts["OTHER"]++
		}
	}

	type kv struct {
		tag   string
		count int
	}
	var list []kv
	for k, v := range counts {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].count > list[j].count
	})

	fmt.Println("=== Log Tag Breakdown ===")
	for _, item := range list {
		fmt.Printf("%-20s: %5d lines (%5.1f%%)\n", item.tag, item.count, float64(item.count)/3100.0*100)
	}
}
