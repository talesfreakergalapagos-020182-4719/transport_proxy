//go:build linux

package pac

import (
	"log"
	"os"
	"strings"
)

type linuxPACSession struct{}

func (s *linuxPACSession) GetProxyForURL(targetURL, pacURL string) (bool, string, error) {
	// Fallback to direct routing on Linux if no external JS PAC engine is configured
	return true, "DIRECT", nil
}

func (s *linuxPACSession) Close() {
}

func createPACSession(userAgent string) (pacSession, error) {
	return &linuxPACSession{}, nil
}

func detectOSProxy() (*osProxyConfig, error) {
	proxy := os.Getenv("https_proxy")
	if proxy == "" {
		proxy = os.Getenv("HTTPS_PROXY")
	}
	if proxy == "" {
		proxy = os.Getenv("http_proxy")
	}
	if proxy == "" {
		proxy = os.Getenv("HTTP_PROXY")
	}
	if proxy == "" {
		proxy = os.Getenv("all_proxy")
	}
	if proxy == "" {
		proxy = os.Getenv("ALL_PROXY")
	}

	proxy = strings.TrimSpace(proxy)
	if proxy != "" {
		log.Printf("[Proxy] Auto-detected Linux proxy from environment variables: %s", proxy)
		return &osProxyConfig{
			Proxy: proxy,
		}, nil
	}

	return &osProxyConfig{}, nil
}
