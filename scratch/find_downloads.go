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
	for scanner.Scan() {
		line := scanner.Text()
		lLower := strings.ToLower(line)
		if strings.Contains(lLower, "ubuntu") ||
			strings.Contains(lLower, "iso") ||
			strings.Contains(lLower, "download") ||
			strings.Contains(lLower, "mirror") ||
			strings.Contains(lLower, "canonical") {
			if strings.Contains(line, "[ALLOW]") || strings.Contains(line, "[CLOSE]") || strings.Contains(line, "[BLOCK]") || strings.Contains(line, "[DEBUG]") {
				fmt.Println(line)
			}
		}
	}
}
