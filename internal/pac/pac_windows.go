//go:build windows

package pac

import (
	"fmt"
	"log"
)

func createPACSession(userAgent string) (pacSession, error) {
	session, err := NewWinHTTPSession(userAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize WinHTTP session for PAC: %w", err)
	}
	return session, nil
}

func detectOSProxy() (*osProxyConfig, error) {
	ieCfg, err := GetIEProxyConfigForCurrentUser()
	if err != nil {
		return nil, err
	}

	cfg := &osProxyConfig{
		AutoConfigURL: ieCfg.AutoConfigURL,
		Proxy:         ieCfg.Proxy,
		AutoDetect:    ieCfg.AutoDetect,
	}

	if cfg.AutoConfigURL == "" && cfg.Proxy == "" && cfg.AutoDetect {
		log.Printf("[PAC] Auto-detecting WPAD PAC script via DHCP/DNS...")
		wpadURL, err := DetectAutoProxyConfigURL()
		if err == nil && wpadURL != "" {
			cfg.AutoConfigURL = wpadURL
		}
	}

	return cfg, nil
}
