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

func TestExtractChallengeToken_EdgeCases(t *testing.T) {
	testCases := []struct {
		name           string
		headerValues   []string
		selectedScheme string
		expectScheme   string
		expectToken    string
		expectFound    bool
	}{
		{
			name:           "Comma-combined NTLM and Basic",
			headerValues:   []string{"NTLM TlRMTVNTUAACAAAA...==, Basic realm=\"corp\""},
			selectedScheme: "NTLM",
			expectScheme:   "NTLM",
			expectToken:    "TlRMTVNTUAACAAAA...==",
			expectFound:    true,
		},
		{
			name:           "Comma in quoted realm before NTLM",
			headerValues:   []string{"Basic realm=\"corp, inc\", NTLM TlRMTVNTUAACAAAA...=="},
			selectedScheme: "NTLM",
			expectScheme:   "NTLM",
			expectToken:    "TlRMTVNTUAACAAAA...==",
			expectFound:    true,
		},
		{
			name:           "Negotiate request with NTLM challenge fallback",
			headerValues:   []string{"NTLM TlRMTVNTUAACAAAA...=="},
			selectedScheme: "Negotiate",
			expectScheme:   "NTLM",
			expectToken:    "TlRMTVNTUAACAAAA...==",
			expectFound:    true,
		},
		{
			name:           "Negotiate with trailing comma and whitespace",
			headerValues:   []string{"Negotiate oYG2MIGzoAMKAQChCwYJKoZIgvcSAQIC..., "},
			selectedScheme: "Negotiate",
			expectScheme:   "Negotiate",
			expectToken:    "oYG2MIGzoAMKAQChCwYJKoZIgvcSAQIC...",
			expectFound:    true,
		},
		{
			name:           "No matching scheme",
			headerValues:   []string{"Digest realm=\"corp\""},
			selectedScheme: "NTLM",
			expectScheme:   "",
			expectToken:    "",
			expectFound:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{
				Header: make(http.Header),
			}
			for _, v := range tc.headerValues {
				resp.Header.Add("Proxy-Authenticate", v)
			}

			scheme, token, found := ExtractChallengeToken(resp, tc.selectedScheme)
			if found != tc.expectFound {
				t.Fatalf("Expected found=%v, got %v", tc.expectFound, found)
			}
			if tc.expectFound {
				if !strings.EqualFold(scheme, tc.expectScheme) {
					t.Errorf("Expected scheme %q, got %q", tc.expectScheme, scheme)
				}
				if token != tc.expectToken {
					t.Errorf("Expected token %q, got %q", tc.expectToken, token)
				}
			}
		})
	}
}

func TestAuthenticateProxyTunnel_PreemptiveBasicAuthWhenCredentialsProvided(t *testing.T) {
	// Verify that if credentials are provided in proxy URL, preemptive Basic auth is sent
	// even if on Windows, avoiding 407 disconnects.
	expectedUser := "testuser"
	expectedPass := "testpass"
	expectedToken := base64.StdEncoding.EncodeToString([]byte(expectedUser + ":" + expectedPass))

	reqReceivedAuth := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			authHeader := r.Header.Get("Proxy-Authorization")
			if authHeader == "Basic "+expectedToken {
				reqReceivedAuth = true
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
			// If no preemptive auth was sent, fail the test
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Secure\"")
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
		User:   url.UserPassword(expectedUser, expectedPass),
	}

	reader, err := AuthenticateProxyTunnel(conn, "target.domain:443", proxyURL, 2*time.Second)
	if err != nil {
		t.Fatalf("AuthenticateProxyTunnel failed: %v", err)
	}
	if reader == nil {
		t.Fatalf("Expected non-nil reader")
	}
	if !reqReceivedAuth {
		t.Errorf("Expected preemptive Basic auth header to be received on first request")
	}
}

func TestExtractChallengeToken_CombinedComplex(t *testing.T) {
	testCases := []struct {
		name         string
		headerValues []string
		targetScheme string
		expectFound  bool
		expectToken  string
	}{
		{
			name:         "Multiple comma schemes with empty tokens (no challenge present)",
			headerValues: []string{"Negotiate, NTLM, Basic realm=\"corp\""},
			targetScheme: "NTLM",
			expectFound:  false,
			expectToken:  "",
		},
		{
			name:         "Comma separated schemes where target has base64 token",
			headerValues: []string{"Negotiate, NTLM TlRMTVNTUAACAAAADAAMADgAAAA=, Basic"},
			targetScheme: "NTLM",
			expectFound:  true,
			expectToken:  "TlRMTVNTUAACAAAADAAMADgAAAA=",
		},
		{
			name:         "Negotiate token followed by comma NTLM",
			headerValues: []string{"Negotiate oYG2MIGzoAMKAQChCwYJKoZIgvcSAQIC..., NTLM"},
			targetScheme: "Negotiate",
			expectFound:  true,
			expectToken:  "oYG2MIGzoAMKAQChCwYJKoZIgvcSAQIC...",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: make(http.Header)}
			for _, v := range tc.headerValues {
				resp.Header.Add("Proxy-Authenticate", v)
			}
			_, token, found := ExtractChallengeToken(resp, tc.targetScheme)
			if found != tc.expectFound {
				t.Fatalf("Expected found=%v, got %v", tc.expectFound, found)
			}
			if token != tc.expectToken {
				t.Errorf("Expected token %q, got %q", tc.expectToken, token)
			}
		})
	}
}

func TestAuthenticateProxyTunnel_IPAddressNTLMSelection(t *testing.T) {
	// Upstream proxy offered both Negotiate and NTLM at an IP address
	var receivedScheme string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			authHeader := r.Header.Get("Proxy-Authorization")
			if authHeader == "" {
				w.Header().Add("Proxy-Authenticate", "Negotiate")
				w.Header().Add("Proxy-Authenticate", "NTLM")
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			parts := strings.Fields(authHeader)
			if len(parts) > 0 {
				receivedScheme = parts[0]
			}
			// Respond 200 OK after receiving client auth attempt
			hijacker, ok := w.(http.Hijacker)
			if ok {
				c, _, _ := hijacker.Hijack()
				defer c.Close()
				c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				return
			}
			w.WriteHeader(200)
			return
		}
	}))
	defer server.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to dial test server: %v", err)
	}
	defer conn.Close()

	// URL has IP address (127.0.0.1) as host
	ipProxyURL, _ := url.Parse(server.URL)
	reader, err := AuthenticateProxyTunnel(conn, "target.domain:443", ipProxyURL, 2*time.Second)
	if err != nil {
		t.Fatalf("AuthenticateProxyTunnel failed for IP proxy: %v", err)
	}
	if reader == nil {
		t.Fatalf("Expected non-nil reader")
	}
	// On Windows, when target host is IP address, NTLM must be preferred over Negotiate
	if receivedScheme != "NTLM" {
		t.Errorf("Expected IP address proxy to use NTLM auth, got %q", receivedScheme)
	}
}


