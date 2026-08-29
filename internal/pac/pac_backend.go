package pac

// pacSession abstracts the platform-specific PAC evaluation engine.
type pacSession interface {
	GetProxyForURL(targetURL, pacURL string) (isDirect bool, proxyList string, err error)
	Close()
}

// osProxyConfig holds auto-detected proxy/PAC settings from the operating system.
type osProxyConfig struct {
	AutoConfigURL string
	Proxy         string
	AutoDetect    bool
}
