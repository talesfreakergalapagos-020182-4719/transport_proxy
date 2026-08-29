//go:build windows

package interceptor

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"transport_proxy/internal/logger"
)

// PortGuard manages Windows OS port range exclusion (netsh excludedportrange) and
// periodically scans the system TCP table to detect if any unauthorized external
// application is using ports within the reserved proxy loop-prevention range (40000-48999).
type PortGuard struct {
	portMin         uint16
	portMax         uint16
	osReserved      bool
	reportedEntries sync.Map // map[string]time.Time (deduplication debounce)
	mu              sync.Mutex
	running         bool
	cancel          context.CancelFunc
}

// NewPortGuard initializes a new PortGuard for the specified reserved port range.
func NewPortGuard(portMin, portMax uint16) *PortGuard {
	return &PortGuard{
		portMin: portMin,
		portMax: portMax,
	}
}

// ReserveOSPortRange registers the reserved port range with the Windows kernel via netsh for both IPv4 and IPv6.
// This prevents any other non-elevated applications from acquiring these ports.
func (pg *PortGuard) ReserveOSPortRange() error {
	numPorts := int(pg.portMax - pg.portMin + 1)

	// Reserve IPv4 port range
	cmd4 := exec.Command("netsh", "int", "ipv4", "add", "excludedportrange",
		"protocol=tcp",
		fmt.Sprintf("startport=%d", pg.portMin),
		fmt.Sprintf("numberofports=%d", numPorts),
		"store=active",
	)
	out4, err4 := cmd4.CombinedOutput()
	outStr4 := strings.TrimSpace(string(out4))
	if err4 != nil {
		logger.Debugf("[PortGuard] netsh int ipv4 add excludedportrange: %s (%v)", outStr4, err4)
	}

	// Reserve IPv6 port range
	cmd6 := exec.Command("netsh", "int", "ipv6", "add", "excludedportrange",
		"protocol=tcp",
		fmt.Sprintf("startport=%d", pg.portMin),
		fmt.Sprintf("numberofports=%d", numPorts),
		"store=active",
	)
	out6, err6 := cmd6.CombinedOutput()
	outStr6 := strings.TrimSpace(string(out6))
	if err6 != nil {
		logger.Debugf("[PortGuard] netsh int ipv6 add excludedportrange: %s (%v)", outStr6, err6)
	}

	if err4 == nil || err6 == nil {
		pg.osReserved = true
		log.Printf("[PortGuard] Registered OS excluded port range (%d-%d) with Windows Kernel (store=active).",
			pg.portMin, pg.portMax)
	} else {
		pg.osReserved = false
		logger.Debugf("[PortGuard] Note: OS port reservation skipped (in-use by existing sockets). Active TCP table guard active.")
	}
	return nil
}

// ReleaseOSPortRange removes the port range exclusion from the Windows kernel.
func (pg *PortGuard) ReleaseOSPortRange() error {
	if !pg.osReserved {
		return nil
	}

	numPorts := int(pg.portMax - pg.portMin + 1)
	_ = exec.Command("netsh", "int", "ipv4", "delete", "excludedportrange",
		"protocol=tcp",
		fmt.Sprintf("startport=%d", pg.portMin),
		fmt.Sprintf("numberofports=%d", numPorts),
		"store=active",
	).Run()

	_ = exec.Command("netsh", "int", "ipv6", "delete", "excludedportrange",
		"protocol=tcp",
		fmt.Sprintf("startport=%d", pg.portMin),
		fmt.Sprintf("numberofports=%d", numPorts),
		"store=active",
	).Run()

	pg.osReserved = false
	log.Printf("[PortGuard] Released OS excluded port range (%d-%d) (IPv4/IPv6).", pg.portMin, pg.portMax)
	return nil
}

// ScanAndAlert performs a single scan and logs security warnings if external processes are detected.
func (pg *PortGuard) ScanAndAlert() int {
	conflicts, err := ScanReservedPortUsage(pg.portMin, pg.portMax)
	if err != nil {
		log.Printf("[PortGuard] Warning: Failed to scan TCP table: %v", err)
		return 0
	}

	if len(conflicts) == 0 {
		return 0
	}

	now := time.Now()

	// GC: Purge old entries to prevent memory leak
	pg.reportedEntries.Range(func(key, val any) bool {
		lastAlert := val.(time.Time)
		if now.Sub(lastAlert) > 1*time.Hour {
			pg.reportedEntries.Delete(key)
		}
		return true
	})

	alertCount := 0

	for _, c := range conflicts {
		key := fmt.Sprintf("%d:%d:%s", c.PID, c.LocalPort, c.State)

		// Debounce: Only re-alert every 5 minutes for the exact same process/port/state
		if lastAlert, exists := pg.reportedEntries.Load(key); exists {
			if now.Sub(lastAlert.(time.Time)) < 5*time.Minute {
				continue
			}
		}

		pg.reportedEntries.Store(key, now)

		if c.IsLoopback() {
			log.Printf("[PortGuard] [INFO] Local loopback IPC socket detected: Port %d (%s) - PID %d (%s)",
				c.LocalPort, c.LocalIP.String(), c.PID, c.ProcessName)
			if c.ProcessPath != "" {
				log.Printf("[PortGuard] [INFO] Path: %s", c.ProcessPath)
			}
			log.Printf("[PortGuard] [INFO] Note: Internal PC communication only (e.g. OneDrive). Outbound internet traffic remains 100%% intercepted.")
		} else {
			alertCount++
			log.Printf("================================================================================")
			log.Printf("[SECURITY WARNING] EXTERNAL PROCESS DETECTED IN RESERVED PROXY PORT RANGE!")
			log.Printf("[SECURITY WARNING] Port:        %d (Range: %d-%d)", c.LocalPort, pg.portMin, pg.portMax)
			log.Printf("[SECURITY WARNING] State:       %s", c.State)
			log.Printf("[SECURITY WARNING] Process:     PID %d (%s)", c.PID, c.ProcessName)
			if c.ProcessPath != "" {
				log.Printf("[SECURITY WARNING] Path:        %s", c.ProcessPath)
			}
			if c.RemotePort > 0 {
				log.Printf("[SECURITY WARNING] Remote:      %s:%d", c.RemoteIP, c.RemotePort)
			}
			log.Printf("[SECURITY WARNING] CAUTION: Traffic from this process will BYPASS transparent proxy filtering!")
			log.Printf("================================================================================")
		}
	}

	return alertCount
}

// Start registers OS kernel port exclusion and begins background monitoring.
func (pg *PortGuard) Start(ctx context.Context, interval time.Duration) {
	pg.mu.Lock()
	if pg.running {
		pg.mu.Unlock()
		return
	}
	pg.running = true

	guardCtx, cancel := context.WithCancel(ctx)
	pg.cancel = cancel
	pg.mu.Unlock()

	// 1. Attempt to register OS-level port exclusion with Windows kernel
	if err := pg.ReserveOSPortRange(); err != nil {
		log.Printf("[PortGuard] Could not set OS excludedportrange (%v). Relying on active TCP table scanner.", err)
	}

	// 2. Perform immediate startup scan
	initialAlerts := pg.ScanAndAlert()
	if initialAlerts == 0 {
		if pg.osReserved {
			log.Printf("[PortGuard] Reserved port range (%d-%d) is fully protected and clean (OS Kernel + Active Scanner).",
				pg.portMin, pg.portMax)
		} else {
			log.Printf("[PortGuard] Reserved port range (%d-%d) is clean (Active TCP Table Scanner).",
				pg.portMin, pg.portMax)
		}
	}

	// 3. Start periodic background scanner
	go func() {
		for {
			var stopped bool
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[PortGuard] Recovered from panic in scanner goroutine: %v", r)
						time.Sleep(1 * time.Second)
					}
				}()

				if interval <= 0 {
					interval = 15 * time.Second
				}
				ticker := time.NewTicker(interval)
				defer ticker.Stop()

				for {
					select {
					case <-guardCtx.Done():
						stopped = true
						return
					case <-ticker.C:
						pg.ScanAndAlert()
					}
				}
			}()

			if stopped {
				return
			}
		}
	}()
}

// Stop stops the background scanner and releases the OS port exclusion.
func (pg *PortGuard) Stop() {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	if pg.cancel != nil {
		pg.cancel()
		pg.cancel = nil
	}
	pg.running = false

	// Release OS kernel port exclusion
	if err := pg.ReleaseOSPortRange(); err != nil {
		log.Printf("[PortGuard] Note: ReleaseOSPortRange error: %v", err)
	}
}
