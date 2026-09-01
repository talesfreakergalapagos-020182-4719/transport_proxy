package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"transport_proxy/internal/config"
	"transport_proxy/internal/dns"
	"transport_proxy/internal/filter"
	"transport_proxy/internal/interceptor"
	"transport_proxy/internal/logger"
	"transport_proxy/internal/pac"
	"transport_proxy/internal/proxy"
)

var (
	version   = "1.0.0"
	buildTime = "unspecified"
)

type syncedWriter struct {
	file *os.File
}

func (s *syncedWriter) Write(p []byte) (n int, err error) {
	n, err = s.file.Write(p)
	_ = s.file.Sync()
	return n, err
}

func main() {
	configPath := flag.String("c", "config.json", "Path to configuration file")
	verboseFlag := flag.Bool("v", false, "Enable verbose debug logging")
	verboseLong := flag.Bool("verbose", false, "Enable verbose debug logging (long)")
	versionFlag := flag.Bool("version", false, "Show application version")
	versionShort := flag.Bool("V", false, "Show application version (shorthand)")
	dryRunFlag := flag.Bool("dry-run", false, "Run in dry-run audit mode (sniff traffic without intercepting/modifying)")
	dryRunShort := flag.Bool("d", false, "Run in dry-run audit mode (shorthand)")
	logPathFlag := flag.String("log", "", "Path to output log file (in addition to console)")
	logPathShort := flag.String("l", "", "Path to output log file (shorthand)")
	cleanupFlag := flag.Bool("cleanup", false, "Clean up any residual platform redirection rules and exit")
	flag.Parse()

	if *cleanupFlag {
		if err := cleanupPlatformRules(); err != nil {
			fmt.Printf("Error cleaning up platform rules: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Platform redirection rules cleaned up successfully.")
		return
	}

	if *versionFlag || *versionShort {
		fmt.Printf("Transparent Proxy Gateway (tproxy) v%s (built %s)\n", version, buildTime)
		return
	}

	// Route standard logging to os.Stdout so PowerShell redirection (> or *>) does not trigger NativeCommandError
	var logOutput io.Writer = os.Stdout

	isVerbose := *verboseFlag || *verboseLong
	logger.SetVerbose(isVerbose)

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(logOutput)

	// 1. Load configuration
	absConfigPath, err := filepath.Abs(*configPath)
	if err != nil {
		absConfigPath = *configPath
	}

	cfgMgr, err := config.NewManager(absConfigPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load configuration from %s: %v", absConfigPath, err)
	}
	cfg := cfgMgr.Get()

	// Configure file logging if specified via CLI or config.json
	logFilePath := *logPathFlag
	if logFilePath == "" {
		logFilePath = *logPathShort
	}
	if logFilePath == "" {
		logFilePath = cfg.LogFile
	}
	if logFilePath != "" {
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			log.Printf("[WARNING] Failed to open log file %s: %v", logFilePath, err)
		} else {
			defer f.Close()
			logOutput = io.MultiWriter(os.Stdout, &syncedWriter{file: f})
			log.SetOutput(logOutput)
			log.Printf("[Log] Logging to console and file (auto-truncate): %s", logFilePath)
		}
	}

	log.Printf("================================================================")
	log.Printf("  Transparent Proxy Gateway v%s starting...", version)
	log.Printf("================================================================")

	if isVerbose {
		log.Printf("[Mode]   VERBOSE Debug Logging is ENABLED.")
	}

	// Check for administrative privileges (required for packet redirection / WinDivert / iptables)
	if !isAdmin() {
		log.Println("[WARNING] This application requires elevated Administrator (Windows) or root/sudo (Linux) privileges.")
		log.Println("[WARNING] Please restart this application with elevated privileges.")
	}

	log.Printf("[Config] Loaded configuration from %s", absConfigPath)

	isDryRun := *dryRunFlag || *dryRunShort || cfg.DryRun
	if isDryRun {
		log.Printf("[Mode]   DRY-RUN (Audit/Monitoring) Mode is ACTIVE.")
		log.Printf("[Mode]   Traffic will NOT be modified or blocked. Actions will be logged to console.")
	}

	// 2. Initialize PAC / Upstream Proxy Resolver
	pacResolver, err := pac.NewResolver(cfg.PacURL, cfg.UpstreamProxy)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize proxy resolver: %v", err)
	}
	defer pacResolver.Close()

	// 3. Initialize filter engine (Whitelist / Blacklist mode)
	filterMode := cfg.FilterMode
	if filterMode == "" {
		filterMode = "whitelist"
	}

	var activeDomains, activeIPs []string
	if filterMode == "blacklist" {
		activeDomains = cfg.BlockedDomains
		activeIPs = cfg.BlockedIPs
	} else {
		activeDomains = cfg.AllowedDomains
		activeIPs = cfg.AllowedIPs
	}

	filterEng := filter.NewEngine(filterMode, activeDomains, activeIPs)
	lowerMode := strings.ToLower(filterMode)
	if lowerMode == "none" || lowerMode == "off" || lowerMode == "disabled" || lowerMode == "all" || lowerMode == "passthrough" {
		log.Printf("[Filter] Initialized in ALL-PASS mode (filtering disabled: all outbound traffic allowed)")
	} else {
		log.Printf("[Filter] Initialized in %s mode with %d domain rules, %d IP rules",
			filterMode, len(activeDomains), len(activeIPs))
	}

	// Register dynamic reload callback
	cfgMgr.OnReload(func(newCfg *config.Config) {
		mode := newCfg.FilterMode
		if mode == "" {
			mode = "whitelist"
		}
		var d, ips []string
		if mode == "blacklist" {
			d = newCfg.BlockedDomains
			ips = newCfg.BlockedIPs
		} else {
			d = newCfg.AllowedDomains
			ips = newCfg.AllowedIPs
		}
		filterEng.UpdateRules(mode, d, ips)
		pacResolver.UpdateConfig(newCfg.PacURL, newCfg.UpstreamProxy)
		mLower := strings.ToLower(mode)
		if mLower == "none" || mLower == "off" || mLower == "disabled" || mLower == "all" || mLower == "passthrough" {
			log.Printf("[Config] Reloaded: ALL-PASS mode (filtering disabled). PAC=%s, Upstream=%s",
				newCfg.PacURL, newCfg.UpstreamProxy)
		} else {
			log.Printf("[Config] Reloaded (%s mode): %d domains, %d IPs. PAC=%s, Upstream=%s",
				mode, len(d), len(ips), newCfg.PacURL, newCfg.UpstreamProxy)
		}
	})
	cfgMgr.StartAutoReload()
	defer cfgMgr.Stop()

	// 4. Acquire Proxy Server Listener (with automatic port collision detection & fallback)
	var proxyListener net.Listener
	var localPort uint16 = 18080

	if !isDryRun {
		var err error
		proxyListener, localPort, err = proxy.AcquireListener(cfg.ListenAddr)
		if err != nil {
			log.Fatalf("[FATAL] Failed to initialize proxy listener: %v", err)
		}
		defer proxyListener.Close()
	} else {
		_, portStr, _ := net.SplitHostPort(cfg.ListenAddr)
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			localPort = uint16(p)
		}
	}

	actualListenAddr := fmt.Sprintf("0.0.0.0:%d", localPort)
	forwardCond, fullFilter := cfg.BuildDivertFilter(localPort)

	redirector, err := interceptor.NewRedirector(actualListenAddr, fullFilter)
	if err != nil {
		if proxyListener != nil {
			_ = proxyListener.Close()
		}
		log.Fatalf("[FATAL] Failed to initialize network redirector: %v", err)
	}
	redirector.SetDryRun(isDryRun, forwardCond, filterEng, pacResolver)
	redirector.SetDNSServers(cfg.DNSServers)

	// 5. Initialize DNS-to-DoH Engine
	dnsEng := dns.NewEngine(cfgMgr, filterEng, pacResolver)
	redirector.SetDNSEngine(dnsEng)
	if cfg.IsCustomDNS() {
		log.Printf("[DNS] Custom Upstream DNS configured: %v (Direct bypass enabled)", cfg.DNSServers)
	} else if cfg.DohEnabled {
		log.Printf("[DNS] No custom DNS configured. Using default Cloudflare Security DoH (1.1.1.2 / 1.0.0.2 / 2606:4700:4700::1112 / 2606:4700:4700::1002)")
	}

	// Panic safety recovery handler to ensure network restoration even on critical failure
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[CRITICAL PANIC] Main process recovered from panic: %v", r)
			log.Printf("[Cleanup] Forcing redirector handle cleanup to restore network state...")
			_ = redirector.Close()
			os.Exit(1)
		}
	}()

	// 6. Initialize Transparent Proxy Server
	proxyServer := proxy.NewServer(cfgMgr, filterEng, redirector, pacResolver)

	// Context for graceful cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Proxy Server Listener
	if !isDryRun {
		if err := proxyServer.StartWithListener(ctx, proxyListener); err != nil {
			log.Fatalf("[FATAL] Failed to start transparent proxy server: %v", err)
		}
	}

	// Start Network Packet Interceptor
	if err := redirector.Start(ctx); err != nil {
		if !isDryRun {
			_ = proxyServer.Close()
		}
		log.Fatalf("[FATAL] Failed to start network interceptor: %v", err)
	}

	// Start PortGuard to monitor reserved proxy outbound port range (40000-48999) for suspicious external apps
	portGuard := interceptor.NewPortGuard(config.OutboundPortMin, config.OutboundPortMax)
	portGuard.Start(ctx, 15*time.Second)
	defer portGuard.Stop()

	if isDryRun {
		log.Printf("[System] Dry-run packet sniffer is active. Monitoring outbound web traffic...")
	} else {
		log.Printf("[System] Transparent proxy is fully active and intercepting outbound traffic.")
	}

	// 6. Signal handling for Graceful Shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("[Shutdown] Received signal %v. Initiating graceful shutdown...", sig)

	// Shutdown sequence:
	// Step 1: Immediately cancel context to stop packet loop
	cancel()

	// Step 2: Close redirector handle to restore OS network routing instantly
	if err := redirector.Close(); err != nil {
		log.Printf("[Shutdown] Redirector close error: %v", err)
	} else {
		log.Printf("[Shutdown] Redirector closed successfully. Network routing restored to standard OS path.")
	}

	// Step 3: Close local proxy listener and drain active connections
	if err := proxyServer.Close(); err != nil {
		log.Printf("[Shutdown] Proxy server close error: %v", err)
	} else {
		log.Printf("[Shutdown] Proxy server closed and drained.")
	}

	// Step 4: Close PAC resolver and config manager
	pacResolver.Close()
	cfgMgr.Stop()

	// Step 5: Stop PortGuard and release OS port exclusion
	portGuard.Stop()

	log.Printf("[Shutdown] Graceful shutdown completed cleanly. Goodbye.")
}
