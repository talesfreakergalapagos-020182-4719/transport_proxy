package sspi

import (
	"net"
	"net/http"
	"net/http/httptest"
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

	reader, err := AuthenticateProxyTunnel(conn, "target.corp.local:443", "proxy.corp.local", 2*time.Second)
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

	_, err = AuthenticateProxyTunnel(conn, "target.corp.local:443", "proxy.corp.local", 2*time.Second)
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

	_, err = AuthenticateProxyTunnel(conn, "target.corp.local:443", "proxy.corp.local", 2*time.Second)
	if err == nil {
		t.Fatalf("Expected error for 403 Forbidden, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected status 403") {
		t.Errorf("Expected error to mention unexpected status 403, got: %v", err)
	}
}

func TestAuthenticateProxyTunnel_HeaderParsing(t *testing.T) {
	// Verify that Proxy-Authenticate with multiple schemes correctly selects Negotiate or NTLM
	headerTestCases := []struct {
		name          string
		headers       []string
		expectSupport bool
	}{
		{
			name:          "Negotiate only (Kerberos)",
			headers:       []string{"Negotiate"},
			expectSupport: true,
		},
		{
			name:          "NTLM only",
			headers:       []string{"NTLM"},
			expectSupport: true,
		},
		{
			name:          "Multiple headers: Basic and Negotiate",
			headers:       []string{"Basic realm=\"corp\"", "Negotiate"},
			expectSupport: true,
		},
		{
			name:          "Only Basic and Digest",
			headers:       []string{"Basic realm=\"corp\"", "Digest realm=\"corp\""},
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

			_, err = AuthenticateProxyTunnel(conn, "target.corp:443", "proxy.corp", 2*time.Second)
			if !tc.expectSupport {
				if err == nil || !strings.Contains(err.Error(), "no supported schemes") {
					t.Errorf("Expected 'no supported schemes' error, got %v", err)
				}
			} else {
				// On Windows it will attempt SSPI NextStep; on Linux it will report SSPI not supported
				if err != nil && strings.Contains(err.Error(), "no supported schemes") {
					t.Errorf("Should have detected supported scheme, but got %v", err)
				}
			}
		})
	}
}
