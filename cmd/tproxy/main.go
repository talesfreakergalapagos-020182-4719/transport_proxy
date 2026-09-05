package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

type cliOptions struct {
	configPath string
	isVerbose  bool
	isVersion  bool
	isDryRun   bool
	logPath    string
	isCleanup  bool
}

func parseCLIFlags(args []string) (*cliOptions, error) {
	fs := flag.NewFlagSet("tproxy", flag.ContinueOnError)
	configPath := fs.String("c", "config.json", "Path to configuration file")
	verboseFlag := fs.Bool("v", false, "Enable verbose debug logging")
	verboseLong := fs.Bool("verbose", false, "Enable verbose debug logging (long)")
	versionFlag := fs.Bool("version", false, "Show application version")
	versionShort := fs.Bool("V", false, "Show application version (shorthand)")
	dryRunFlag := fs.Bool("dry-run", false, "Run in dry-run audit mode (sniff traffic without intercepting/modifying)")
	dryRunShort := fs.Bool("d", false, "Run in dry-run audit mode (shorthand)")
	logPathFlag := fs.String("log", "", "Path to output log file (in addition to console)")
	logPathShort := fs.String("l", "", "Path to output log file (shorthand)")
	cleanupFlag := fs.Bool("cleanup", false, "Clean up any residual platform redirection rules and exit")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	logPath := *logPathFlag
	if logPath == "" {
		logPath = *logPathShort
	}

	return &cliOptions{
		configPath: *configPath,
		isVerbose:  *verboseFlag || *verboseLong,
		isVersion:  *versionFlag || *versionShort,
		isDryRun:   *dryRunFlag || *dryRunShort,
		logPath:    logPath,
		isCleanup:  *cleanupFlag,
	}, nil
}

func main() {
	opts, err := parseCLIFlags(os.Args[1:])
	if err != nil {
		os.Exit(2)
	}

	if opts.isCleanup {
		if err := cleanupPlatformRules(); err != nil {
			fmt.Printf("Error cleaning up platform rules: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Platform redirection rules cleaned up successfully.")
		return
	}

	if opts.isVersion {
		fmt.Printf("Transparent Proxy Gateway (tproxy) v%s (built %s)\n", version, buildTime)
		return
	}

	logger.SetVerbose(opts.isVerbose)

	// Configure file logging if specified via CLI or config.json
	cliLogFile := opts.logPath

	// 1. Load configuration
	absConfigPath, err := filepath.Abs(opts.configPath)
	if err != nil {
		absConfigPath = opts.configPath
	}

	cfgMgr, err := config.NewManager(absConfigPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load configuration from %s: %v", absConfigPath, err)
	}
	cfg := cfgMgr.Get()

	var currentLogPath string
	var logMu sync.Mutex

	setLoggerOutput := func(targetPath string) {
		logMu.Lock()
		defer logMu.Unlock()

		if targetPath == currentLogPath && currentLogPath != "" {
			return
		}
		currentLogPath = targetPath

		if err := logger.SetupGlobalLogger(targetPath, true); err != nil {
			log.Printf("[WARNING] Failed to setup async logger for %s: %v", targetPath, err)
			return
		}
		if targetPath != "" {
			log.Printf("[Log] Logging to console and file (async buffered): %s", targetPath)
		}
	}

	initialLogPath := cliLogFile
	if initialLogPath == "" {
		initialLogPath = cfg.LogFile
	}
	setLoggerOutput(initialLogPath)
	defer logger.CloseGlobal()

	log.Printf("================================================================")
	log.Printf("  Transparent Proxy Gateway v%s starting...", version)
	log.Printf("================================================================")

	if opts.isVerbose {
		log.Printf("[Mode]   VERBOSE Debug Logging is ENABLED.")
	}

	// Check for administrative privileges (required for packet redirection / WinDivert / iptables)
	if !isAdmin() {
		log.Println("[WARNING] This application requires elevated Administrator (Windows) or root/sudo (Linux) privileges.")
		log.Println("[WARNING] Please restart this application with elevated privileges.")
	}

	log.Printf("[Config] Loaded configuration from %s", absConfigPath)

	isDryRun := opts.isDryRun || cfg.DryRun
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

	lowerMode := strings.ToLower(filterMode)
	isAllPass := lowerMode == "none" || lowerMode == "off" || lowerMode == "disabled" || lowerMode == "all" || lowerMode == "passthrough"

	var activeDomains, activeIPs []string
	if !isAllPass {
		if filterMode == "blacklist" {
			activeDomains = cfg.BlockedDomains
			activeIPs = cfg.BlockedIPs
		} else {
			activeDomains = cfg.AllowedDomains
			activeIPs = cfg.AllowedIPs
		}
	}

	filterEng := filter.NewEngine(filterMode, activeDomains, activeIPs)
	if isAllPass {
		log.Printf("[Filter] Initialized in ALL-PASS mode (filtering disabled: all outbound traffic allowed)")
	} else {
		log.Printf("[Filter] Initialized in %s mode with %d domain rules, %d IP rules",
			filterMode, len(activeDomains), len(activeIPs))
	}


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
	redirector.SetUDPFilter(cfg.FilterUDP, filterEng)
	if cfg.FilterUDP {
		log.Printf("[UDP]    General UDP Traffic Audit & Filtering: ENABLED (FilterMode=%s)", filterMode)
	}

	// 5. Initialize DNS-to-DoH Engine
	dnsEng := dns.NewEngine(cfgMgr, filterEng, pacResolver)
	redirector.SetDNSEngine(dnsEng)
	if cfg.IsCustomDNS() {
		log.Printf("[DNS] Custom Upstream DNS configured: %v (Direct bypass enabled)", cfg.DNSServers)
	} else if cfg.DohEnabled {
		log.Printf("[DNS] No custom DNS configured. Using default Cloudflare Security DoH (1.1.1.2 / 1.0.0.2 / 2606:4700:4700::1112 / 2606:4700:4700::1002)")
	}

	// 5.1 Register dynamic reload callback (expanded hot-reload for filter, proxy, DNS, DoH, dry-run, log file)
	cfgMgr.OnReload(func(newCfg *config.Config) {
		mode := newCfg.FilterMode
		if mode == "" {
			mode = "whitelist"
		}
		mLower := strings.ToLower(mode)
		isAllPassReload := mLower == "none" || mLower == "off" || mLower == "disabled" || mLower == "all" || mLower == "passthrough"
		var d, ips []string
		if !isAllPassReload {
			if mode == "blacklist" {
				d = newCfg.BlockedDomains
				ips = newCfg.BlockedIPs
			} else {
				d = newCfg.AllowedDomains
				ips = newCfg.AllowedIPs
			}
		}
		filterEng.UpdateRules(mode, d, ips)
		pacResolver.UpdateConfig(newCfg.PacURL, newCfg.UpstreamProxy)
		dnsEng.UpdateConfig(newCfg)
		redirector.SetDNSServers(newCfg.DNSServers)
		redirector.SetDryRun(newCfg.DryRun, forwardCond, filterEng, pacResolver)
		redirector.SetUDPFilter(newCfg.FilterUDP, filterEng)

		if cliLogFile == "" && newCfg.LogFile != currentLogPath {
			setLoggerOutput(newCfg.LogFile)
		}

		if isAllPassReload {
			log.Printf("[Config] Reloaded: ALL-PASS mode (filtering disabled). PAC=%s, Upstream=%s, DNS=%v, FilterUDP=%v, DryRun=%v",
				newCfg.PacURL, newCfg.UpstreamProxy, newCfg.DNSServers, newCfg.FilterUDP, newCfg.DryRun)
		} else {
			log.Printf("[Config] Reloaded (%s mode): %d domains, %d IPs. PAC=%s, Upstream=%s, DNS=%v, FilterUDP=%v, DryRun=%v",
				mode, len(d), len(ips), newCfg.PacURL, newCfg.UpstreamProxy, newCfg.DNSServers, newCfg.FilterUDP, newCfg.DryRun)
		}
	})
	cfgMgr.StartAutoReload()
	defer cfgMgr.Stop()

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

	// Step 4: Close PAC resolver and config manager (handled by defer)
	// Step 5: Stop PortGuard and release OS port exclusion (handled by defer)
	logger.FlushGlobal()

	log.Printf("[Shutdown] Graceful shutdown completed cleanly. Goodbye.")
	logger.FlushGlobal()
}
