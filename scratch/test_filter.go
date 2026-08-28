//go:build ignore

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	dll, err := syscall.LoadDLL("WinDivert.dll")
	if err != nil {
		fmt.Printf("Error loading DLL: %v\n", err)
		return
	}
	defer dll.Release()

	procOpen, err := dll.FindProc("WinDivertOpen")
	if err != nil {
		fmt.Printf("FindProc error: %v\n", err)
		return
	}

	testFilters := []string{
		"((outbound and tcp and !loopback and tcp.DstPort != 18080 and (tcp.SrcPort < 40000 or tcp.SrcPort > 48999) and ((ip and (ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and (ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and (ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and (ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255)) or (ipv6 and (ipv6.DstAddr < fc00:: or ipv6.DstAddr > fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) and (ipv6.DstAddr < fe80:: or ipv6.DstAddr > febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff)))) or (outbound and tcp and tcp.SrcPort == 18080) or (outbound and udp and udp.DstPort == 443 and !loopback) or (outbound and udp and udp.DstPort == 53 and !loopback))",
	}

	procClose, _ := dll.FindProc("WinDivertClose")

	for i, f := range testFilters {
		filterBytes := append([]byte(f), 0)
		r, _, err := procOpen.Call(
			uintptr(unsafe.Pointer(&filterBytes[0])),
			uintptr(0), // WINDIVERT_LAYER_NETWORK
			uintptr(0), // Priority
			uintptr(0), // Flags
		)
		handle := syscall.Handle(r)
		if handle == syscall.InvalidHandle {
			// If error is ACCESS_DENIED (because not run as elevated admin in test), syntax is VALID (error was privilege, not ERROR_INVALID_PARAMETER)!
			// If syntax is invalid, error is ERROR_INVALID_PARAMETER (87).
			errno, ok := err.(syscall.Errno)
			if ok && errno == 5 { // ERROR_ACCESS_DENIED
				fmt.Printf("[%d] VALID SYNTAX (Access Denied as expected for non-admin): %s\n\n", i+1, f)
			} else if ok && errno == 87 { // ERROR_INVALID_PARAMETER
				fmt.Printf("[%d] INVALID SYNTAX (Error 87): %s\n\n", i+1, f)
			} else {
				fmt.Printf("[%d] Result: %v (errno=%d)\nFilter: %s\n\n", i+1, err, errno, f)
			}
		} else {
			fmt.Printf("[%d] OPEN SUCCESS: %s\n\n", i+1, f)
			procClose.Call(uintptr(handle))
		}
	}
}
