//go:build linux

package pac

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type linuxPACSession struct {
	userAgent string
	mu        sync.RWMutex
	engines   map[string]*JSEngine
	client    *http.Client
}

func createPACSession(userAgent string) (pacSession, error) {
	return &linuxPACSession{
		userAgent: userAgent,
		engines:   make(map[string]*JSEngine),
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}, nil
}

func (s *linuxPACSession) GetProxyForURL(targetURL, pacURL string) (bool, string, error) {
	if pacURL == "" {
		return true, "DIRECT", nil
	}

	engine, err := s.getOrLoadEngine(pacURL)
	if err != nil {
		return true, "DIRECT", fmt.Errorf("failed to load PAC script from %s: %w", pacURL, err)
	}

	// Extract host from targetURL for PAC function
	host := targetURL
	if parsed, err := url.Parse(targetURL); err == nil {
		if parsed.Hostname() != "" {
			host = parsed.Hostname()
		} else if parsed.Host != "" {
			host = parsed.Host
		}
	} else if strings.Contains(targetURL, "://") {
		parts := strings.SplitN(targetURL, "://", 2)
		host = strings.SplitN(parts[1], "/", 2)[0]
		host = strings.SplitN(host, ":", 2)[0]
	}

	rawResult, err := engine.FindProxyForURL(targetURL, host)
	if err != nil {
		return true, "DIRECT", fmt.Errorf("FindProxyForURL evaluation error: %w", err)
	}

	decision := ParsePACResult(rawResult)
	if decision.IsDirect {
		return true, "DIRECT", nil
	}
	return false, decision.ProxyURL, nil
}

func (s *linuxPACSession) getOrLoadEngine(pacURL string) (*JSEngine, error) {
	s.mu.RLock()
	engine, exists := s.engines[pacURL]
	s.mu.RUnlock()
	if exists && engine != nil {
		return engine, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double check after lock
	if engine, exists := s.engines[pacURL]; exists && engine != nil {
		return engine, nil
	}

	scriptContent, err := s.fetchPACScript(pacURL)
	if err != nil {
		return nil, err
	}

	engine, err = NewJSEngine(scriptContent)
	if err != nil {
		return nil, fmt.Errorf("failed to compile PAC script: %w", err)
	}

	s.engines[pacURL] = engine
	return engine, nil
}

func (s *linuxPACSession) fetchPACScript(pacURL string) (string, error) {
	if strings.HasPrefix(pacURL, "http://") || strings.HasPrefix(pacURL, "https://") {
		req, err := http.NewRequest("GET", pacURL, nil)
		if err != nil {
			return "", err
		}
		if s.userAgent != "" {
			req.Header.Set("User-Agent", s.userAgent)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to download PAC script: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("HTTP error %d when downloading PAC", resp.StatusCode)
		}

		// Limit PAC file size to 2MB for safety
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		if err != nil {
			return "", err
		}
		return string(bodyBytes), nil
	}

	// Local file path
	data, err := os.ReadFile(pacURL)
	if err != nil {
		return "", fmt.Errorf("failed to read local PAC file: %w", err)
	}
	return string(data), nil
}

func (s *linuxPACSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, engine := range s.engines {
		if engine != nil {
			engine.Close()
		}
	}
	s.engines = make(map[string]*JSEngine)
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
