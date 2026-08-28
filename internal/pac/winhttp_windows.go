package pac

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modWinHttp  = syscall.NewLazyDLL("winhttp.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGlobalFree                            = modKernel32.NewProc("GlobalFree")
	procWinHttpOpen                           = modWinHttp.NewProc("WinHttpOpen")
	procWinHttpCloseHandle                    = modWinHttp.NewProc("WinHttpCloseHandle")
	procWinHttpSetTimeouts                    = modWinHttp.NewProc("WinHttpSetTimeouts")
	procWinHttpGetProxyForUrl                 = modWinHttp.NewProc("WinHttpGetProxyForUrl")
	procWinHttpGetIEProxyConfigForCurrentUser = modWinHttp.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	procWinHttpDetectAutoProxyConfigUrl       = modWinHttp.NewProc("WinHttpDetectAutoProxyConfigUrl")
)

// DetectAutoProxyConfigURL attempts to auto-detect the PAC URL via WPAD (DHCP and DNS).
func DetectAutoProxyConfigURL() (string, error) {
	var urlPtr *uint16
	flags := uint32(WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A)
	r, _, err := procWinHttpDetectAutoProxyConfigUrl.Call(
		uintptr(flags),
		uintptr(unsafe.Pointer(&urlPtr)),
	)
	if r == 0 {
		return "", err
	}
	if urlPtr == nil {
		return "", nil
	}
	defer procGlobalFree.Call(uintptr(unsafe.Pointer(urlPtr)))
	return utf16PtrToString(urlPtr), nil
}

// WinHttpCurrentUserIEProxyConfig corresponds to WINHTTP_CURRENT_USER_IE_PROXY_CONFIG.
type WinHttpCurrentUserIEProxyConfig struct {
	FAutoDetect       int32
	LpszAutoConfigUrl *uint16
	LpszProxy         *uint16
	LpszProxyBypass   *uint16
}

// IEProxyConfig holds the extracted Windows Internet/Proxy settings for the current user.
type IEProxyConfig struct {
	AutoDetect    bool
	AutoConfigURL string
	Proxy         string
	ProxyBypass   string
}

// GetIEProxyConfigForCurrentUser retrieves the Windows proxy configuration configured in Internet Options / Settings.
func GetIEProxyConfigForCurrentUser() (*IEProxyConfig, error) {
	var cfg WinHttpCurrentUserIEProxyConfig
	r, _, err := procWinHttpGetIEProxyConfigForCurrentUser.Call(uintptr(unsafe.Pointer(&cfg)))
	if r == 0 {
		return nil, fmt.Errorf("WinHttpGetIEProxyConfigForCurrentUser failed: %w", err)
	}

	defer func() {
		if cfg.LpszAutoConfigUrl != nil {
			procGlobalFree.Call(uintptr(unsafe.Pointer(cfg.LpszAutoConfigUrl)))
		}
		if cfg.LpszProxy != nil {
			procGlobalFree.Call(uintptr(unsafe.Pointer(cfg.LpszProxy)))
		}
		if cfg.LpszProxyBypass != nil {
			procGlobalFree.Call(uintptr(unsafe.Pointer(cfg.LpszProxyBypass)))
		}
	}()

	res := &IEProxyConfig{
		AutoDetect:    cfg.FAutoDetect != 0,
		AutoConfigURL: utf16PtrToString(cfg.LpszAutoConfigUrl),
		Proxy:         utf16PtrToString(cfg.LpszProxy),
		ProxyBypass:   utf16PtrToString(cfg.LpszProxyBypass),
	}
	return res, nil
}

const (
	WINHTTP_ACCESS_TYPE_NO_PROXY    = 1
	WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3

	WINHTTP_AUTOPROXY_AUTO_DETECT = 0x00000001
	WINHTTP_AUTOPROXY_CONFIG_URL  = 0x00000002

	WINHTTP_AUTO_DETECT_TYPE_DHCP  = 0x00000001
	WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002
)

// WinHttpAutoProxyOptions corresponds to WINHTTP_AUTOPROXY_OPTIONS.
type WinHttpAutoProxyOptions struct {
	DwFlags                uint32
	DwAutoDetectFlags      uint32
	LpszAutoConfigUrl      *uint16
	LpvReserved            uintptr
	DwReserved             uint32
	FAutoLogonIfChallenged int32
}

// WinHttpProxyInfo corresponds to WINHTTP_PROXY_INFO.
type WinHttpProxyInfo struct {
	DwAccessType    uint32
	LpszProxy       *uint16
	LpszProxyBypass *uint16
}

// WinHTTPSession wraps a WinHTTP internet session handle.
type WinHTTPSession struct {
	handle uintptr
}

// NewWinHTTPSession creates an initialized WinHTTP session.
func NewWinHTTPSession(userAgent string) (*WinHTTPSession, error) {
	uaPtr, err := syscall.UTF16PtrFromString(userAgent)
	if err != nil {
		return nil, err
	}

	r, _, err := procWinHttpOpen.Call(
		uintptr(unsafe.Pointer(uaPtr)),
		WINHTTP_ACCESS_TYPE_NO_PROXY,
		0,
		0,
		0,
	)

	if r == 0 {
		return nil, fmt.Errorf("WinHttpOpen failed: %w", err)
	}

	// Set timeouts: Resolve=10s, Connect=10s, Send=10s, Receive=10s
	// This prevents the synchronous WinHttpGetProxyForUrl from hanging indefinitely
	// if the WPAD server or PAC URL is unresponsive.
	procWinHttpSetTimeouts.Call(r, 10000, 10000, 10000, 10000)

	return &WinHTTPSession{handle: r}, nil
}

// GetProxyForURL evaluates the PAC file at pacURL for the target targetURL.
// If pacURL is empty, it attempts WPAD auto-detection.
// Returns:
// - isDirect: true if target should be connected directly without proxy
// - proxyServer: proxy host:port (e.g. "proxy.corp.local:8080") or empty if direct
// - err: any error encountered during evaluation
func (s *WinHTTPSession) GetProxyForURL(targetURL string, pacURL string) (bool, string, error) {
	if s.handle == 0 {
		return false, "", fmt.Errorf("WinHTTP session is not opened")
	}

	targetURLPtr, err := syscall.UTF16PtrFromString(targetURL)
	if err != nil {
		return false, "", fmt.Errorf("invalid target URL %q: %w", targetURL, err)
	}

	var options WinHttpAutoProxyOptions
	options.FAutoLogonIfChallenged = 1 // Automatically authenticate if PAC download requires NTLM/Kerberos

	if pacURL != "" {
		pacURLPtr, err := syscall.UTF16PtrFromString(pacURL)
		if err != nil {
			return false, "", fmt.Errorf("invalid PAC URL %q: %w", pacURL, err)
		}
		options.DwFlags = WINHTTP_AUTOPROXY_CONFIG_URL
		options.LpszAutoConfigUrl = pacURLPtr
	} else {
		// WPAD auto-detect
		options.DwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
		options.DwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A
	}

	var proxyInfo WinHttpProxyInfo

	r, _, err := procWinHttpGetProxyForUrl.Call(
		s.handle,
		uintptr(unsafe.Pointer(targetURLPtr)),
		uintptr(unsafe.Pointer(&options)),
		uintptr(unsafe.Pointer(&proxyInfo)),
	)

	if r == 0 {
		return false, "", fmt.Errorf("WinHttpGetProxyForUrl failed for %s (PAC: %s): %w", targetURL, pacURL, err)
	}

	defer func() {
		if proxyInfo.LpszProxy != nil {
			procGlobalFree.Call(uintptr(unsafe.Pointer(proxyInfo.LpszProxy)))
		}
		if proxyInfo.LpszProxyBypass != nil {
			procGlobalFree.Call(uintptr(unsafe.Pointer(proxyInfo.LpszProxyBypass)))
		}
	}()

	if proxyInfo.DwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY {
		return true, "", nil
	}

	if proxyInfo.DwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY && proxyInfo.LpszProxy != nil {
		proxyStr := utf16PtrToString(proxyInfo.LpszProxy)
		return false, proxyStr, nil
	}

	return true, "", nil
}

// Close closes the WinHTTP session handle.
func (s *WinHTTPSession) Close() {
	if s.handle != 0 {
		procWinHttpCloseHandle.Call(s.handle)
		s.handle = 0
	}
}

func utf16PtrToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}
	var u16s []uint16
	curr := ptr
	for *curr != 0 {
		u16s = append(u16s, *curr)
		curr = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(curr)) + 2))
	}
	return syscall.UTF16ToString(u16s)
}
