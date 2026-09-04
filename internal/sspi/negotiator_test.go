package sspi

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthenticateProxyTunnel_NoAuthRequired(t *testing.T) {
	// Server responds 200 OK immediately without requiring authentication
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "Hijack not supported", http.StatusInternalServerError)
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			return
		}
		http.Error(w, "Bad method", http.StatusBadRequest)
	}))
	defer server.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to dial test server: %v", err)
	}
	defer conn.Close()

	proxyURL, _ := url.Parse("http://proxy.corp.local")
	reader, err := AuthenticateProxyTunnel(conn, "target.corp.local:443", proxyURL, 2*time.Second)
	if err != nil {
		t.Fatalf("AuthenticateProxyTunnel failed: %v", err)
	}
	if reader == nil {
		t.Fatalf("Expected non-nil reader returned")
	}
}

func TestAuthenticateProxyTunnel_UnsupportedAuthScheme(t *testing.T) {
	// Server responds 407 but only offers unsupported schemes (e.g. Digest, CustomAuth)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Proxy-Authenticate", "Digest realm=\"corp\"")
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer server.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to dial test server: %v", err)
	}
	defer conn.Close()

	proxyURL, _ := url.Parse("http://proxy.corp.local")
	_, err = AuthenticateProxyTunnel(conn, "target.corp.local:443", proxyURL, 2*time.Second)
	if err == nil {
		t.Fatalf("Expected error for unsupported auth scheme, got nil")
	}
	if !strings.Contains(err.Error(), "no supported schemes") {
		t.Errorf("Expected error to mention 'no supported schemes', got: %v", err)
	}
}

func TestAuthenticateProxyTunnel_UnexpectedStatus(t *testing.T) {
	// Server responds with 403 Forbidden instead of 200 or 407
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Access Denied by Policy", http.StatusForbidden)
	}))
	defer server.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to dial test server: %v", err)
	}
	defer conn.Close()

	proxyURL, _ := url.Parse("http://proxy.corp.local")
	_, err = AuthenticateProxyTunnel(conn, "target.corp.local:443", proxyURL, 2*time.Second)
	if err == nil {
		t.Fatalf("Expected error for 403 Forbidden, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected status 403") {
		t.Errorf("Expected error to mention unexpected status 403, got: %v", err)
	}
}

func TestAuthenticateProxyTunnel_BasicAuthSuccess(t *testing.T) {
	expectedUser := "myuser"
	expectedPass := "mypassword"
	expectedToken := base64.StdEncoding.EncodeToString([]byte(expectedUser + ":" + expectedPass))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			authHeader := r.Header.Get("Proxy-Authorization")
			if authHeader == "" {
				w.Header().Set("Proxy-Authenticate", `Basic realm="ProxyAuth"`)
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}

			if authHeader == "Basic "+expectedToken {
				hijacker, ok := w.(http.Hijacker)
				if !ok {
					http.Error(w, "Hijack not supported", http.StatusInternalServerError)
					return
				}
				conn, _, err := hijacker.Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				return
			}

			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		http.Error(w, "Bad method", http.StatusBadRequest)
	}))
	defer server.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to dial test server: %v", err)
	}
	defer conn.Close()

	proxyURL, _ := url.Parse(fmt.Sprintf("http://%s:%s@%s", expectedUser, expectedPass, strings.TrimPrefix(server.URL, "http://")))
	reader, err := AuthenticateProxyTunnel(conn, "example.com:443", proxyURL, 2*time.Second)
	if err != nil {
		t.Fatalf("AuthenticateProxyTunnel failed with Basic auth: %v", err)
	}
	if reader == nil {
		t.Fatalf("Expected non-nil reader on successful Basic auth")
	}
}

func TestAuthenticateProxyTunnel_BasicAuthMissingCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="ProxyAuth"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer server.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to dial test server: %v", err)
	}
	defer conn.Close()

	// proxyURL has no user:pass credentials
	proxyURL, _ := url.Parse(server.URL)
	_, err = AuthenticateProxyTunnel(conn, "example.com:443", proxyURL, 2*time.Second)
	if err == nil {
		t.Fatalf("Expected error when credentials are missing for Basic auth, got nil")
	}
	if !strings.Contains(err.Error(), "no credentials were provided") {
		t.Errorf("Expected error message to mention missing credentials, got: %v", err)
	}
}

func TestAuthenticateProxyTunnel_HeaderParsing(t *testing.T) {
	// Verify that Proxy-Authenticate with multiple schemes correctly identifies supported schemes
	headerTestCases := []struct {
		name          string
		headers       []string
		proxyURLStr   string
		expectSupport bool
	}{
		{
			name:          "Negotiate only (Kerberos)",
			headers:       []string{"Negotiate"},
			proxyURLStr:   "http://proxy.corp.local",
			expectSupport: true,
		},
		{
			name:          "NTLM only",
			headers:       []string{"NTLM"},
			proxyURLStr:   "http://proxy.corp.local",
			expectSupport: true,
		},
		{
			name:          "Multiple headers: Basic and Negotiate",
			headers:       []string{"Basic realm=\"corp\"", "Negotiate"},
			proxyURLStr:   "http://user:pass@proxy.corp.local",
			expectSupport: true,
		},
		{
			name:          "Basic only with credentials",
			headers:       []string{"Basic realm=\"corp\""},
			proxyURLStr:   "http://user:pass@proxy.corp.local",
			expectSupport: true,
		},
		{
			name:          "Only Digest (unsupported)",
			headers:       []string{"Digest realm=\"corp\""},
			proxyURLStr:   "http://proxy.corp.local",
			expectSupport: false,
		},
	}

	for _, tc := range headerTestCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, h := range tc.headers {
					w.Header().Add("Proxy-Authenticate", h)
				}
				w.WriteHeader(http.StatusProxyAuthRequired)
			}))
			defer server.Close()

			conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatalf("Failed to dial: %v", err)
			}
			defer conn.Close()

			proxyURL, _ := url.Parse(tc.proxyURLStr)
			_, err = AuthenticateProxyTunnel(conn, "target.corp:443", proxyURL, 2*time.Second)
			if !tc.expectSupport {
				if err == nil || !strings.Contains(err.Error(), "no supported schemes") {
					t.Errorf("Expected 'no supported schemes' error, got %v", err)
				}
			} else {
				if err != nil && strings.Contains(err.Error(), "no supported schemes") {
					t.Errorf("Should have detected supported scheme, but got %v", err)
				}
			}
		})
	}
}

func TestAuthenticateProxyTunnel_ProxyClosesConnectionOn407(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="CorpProxy"`)
		w.Header().Set("Proxy-Connection", "close")
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer server.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	proxyURL, _ := url.Parse("http://proxy.corp.local")
	_, err = AuthenticateProxyTunnel(conn, "example.com:443", proxyURL, 2*time.Second)
	if err == nil {
		t.Fatalf("Expected error when proxy closes connection on 407, got nil")
	}
	if !strings.Contains(err.Error(), "closed the connection") {
		t.Errorf("Expected error to mention 'closed the connection', got: %v", err)
	}
}

func TestAuthenticateProxyTunnel_SpecialCharactersInCredentials(t *testing.T) {
	// Username and password containing colons, symbols, and spaces
	rawUser := "domain\\user:special"
	rawPass := "P@$$w:rd!#123"
	expectedToken := base64.StdEncoding.EncodeToString([]byte(rawUser + ":" + rawPass))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			auth := r.Header.Get("Proxy-Authorization")
			if auth == "" {
				w.Header().Set("Proxy-Authenticate", `BASIC realm="Secure"`)
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			if auth == "Basic "+expectedToken {
				hijacker, ok := w.(http.Hijacker)
				if !ok {
					http.Error(w, "hijack not supported", 500)
					return
				}
				c, _, _ := hijacker.Hijack()
				defer c.Close()
				c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				return
			}
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
	}))
	defer server.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	proxyURL := &url.URL{
		Scheme: "http",
		Host:   strings.TrimPrefix(server.URL, "http://"),
		User:   url.UserPassword(rawUser, rawPass),
	}

	reader, err := AuthenticateProxyTunnel(conn, "secure.target:443", proxyURL, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed with special character credentials: %v", err)
	}
	if reader == nil {
		t.Fatalf("Expected valid reader")
	}
}

