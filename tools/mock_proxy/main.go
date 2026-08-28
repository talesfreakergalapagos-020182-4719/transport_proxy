package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"transport_proxy/internal/sspi"
)

var (
	listenAddr = flag.String("addr", "127.0.0.1:8080", "Listen address for mock upstream proxy and PAC server")
	authMode   = flag.String("auth", "none", "Authentication mode: 'none', 'sso' (Windows SSO / NTLM), 'basic'")
	basicUser  = flag.String("user", "user", "Username for basic authentication")
	basicPass  = flag.String("pass", "pass", "Password for basic authentication")
)

func main() {
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	fmt.Println("================================================================")
	fmt.Println("  Mock Upstream HTTP/HTTPS Proxy & PAC Server")
	fmt.Println("================================================================")
	fmt.Printf("Listening on: %s\n", *listenAddr)
	fmt.Printf("Auth Mode:    %s\n", strings.ToUpper(*authMode))
	if strings.ToLower(*authMode) == "basic" {
		fmt.Printf("Credentials:  %s:%s\n", *basicUser, *basicPass)
	}
	fmt.Printf("PAC URL:      http://%s/proxy.pac\n", *listenAddr)
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("Usage in tproxy config.json:")
	fmt.Printf("  \"upstream_proxy\": \"http://%s\"\n", *listenAddr)
	fmt.Println("  -- OR --")
	fmt.Printf("  \"pac_url\": \"http://%s/proxy.pac\"\n", *listenAddr)
	fmt.Println("================================================================")

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("[FATAL] Failed to listen on %s: %v", *listenAddr, err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleConnection(conn)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n[SHUTDOWN] Stopping mock proxy server...")
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	var serverSSPI *sspi.ServerSSPIContext
	reader := bufio.NewReader(conn)
	mode := strings.ToLower(*authMode)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		// 1. Serve built-in PAC file for GET requests
		if req.Method == http.MethodGet && (req.URL.Path == "/proxy.pac" || req.URL.Path == "/wpad.dat") {
			pacContent := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.yahoo.co.jp") || shExpMatch(host, "*.github.com") || shExpMatch(host, "httpbin.org")) {
        return "PROXY %s";
    }
    return "DIRECT";
}
`, *listenAddr)
			resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: %d\r\n\r\n%s",
				len(pacContent), pacContent)
			_, _ = conn.Write([]byte(resp))
			log.Printf("[PAC-REQ] Served proxy.pac to %s", conn.RemoteAddr())
			return
		}

		// 2. Authentication Enforcement
		if mode == "basic" {
			authHeader := req.Header.Get("Proxy-Authorization")
			expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(*basicUser+":"+*basicPass))
			if authHeader != expected {
				log.Printf("[AUTH] 407 Proxy Auth Required (Basic) for %s", conn.RemoteAddr())
				resp := "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"MockProxy\"\r\nProxy-Connection: Keep-Alive\r\nContent-Length: 0\r\n\r\n"
				_, _ = conn.Write([]byte(resp))
				continue
			}
			log.Printf("[AUTH] Basic Authentication SUCCESS for user %q from %s", *basicUser, conn.RemoteAddr())
		} else if mode == "sso" || mode == "ntlm" || mode == "negotiate" {
			authHeader := req.Header.Get("Proxy-Authorization")
			if authHeader == "" {
				// Step 1: Challenge client with Negotiate / NTLM
				log.Printf("[AUTH] 407 Proxy Auth Required (Challenge Initiated: Negotiate/NTLM) for %s", conn.RemoteAddr())
				resp := "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\nProxy-Authenticate: NTLM\r\nProxy-Connection: Keep-Alive\r\nContent-Length: 0\r\n\r\n"
				_, _ = conn.Write([]byte(resp))
				continue
			}

			parts := strings.Fields(authHeader)
			if len(parts) >= 2 {
				scheme := parts[0]
				clientToken := parts[1]

				if serverSSPI == nil {
					sspiPkg := "Negotiate"
					if strings.EqualFold(scheme, "ntlm") {
						sspiPkg = "NTLM"
					}
					sCtx, err := sspi.NewServerSSPIContext(sspiPkg)
					if err == nil {
						serverSSPI = sCtx
						defer serverSSPI.Release()
					}
				}

				if serverSSPI != nil {
					challengeToken, done, err := serverSSPI.AcceptStep(clientToken)
					if err != nil {
						log.Printf("[AUTH] SSPI AcceptStep error from %s: %v", conn.RemoteAddr(), err)
					} else if !done {
						log.Printf("[AUTH] Received SSPI Client Token -> Sending Server Challenge (%s) to %s", scheme, conn.RemoteAddr())
						resp := fmt.Sprintf("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: %s %s\r\nProxy-Connection: Keep-Alive\r\nContent-Length: 0\r\n\r\n",
							scheme, challengeToken)
						_, _ = conn.Write([]byte(resp))
						continue
					} else {
						log.Printf("[AUTH] Windows SSO (%s) Authentication SUCCESS from %s", scheme, conn.RemoteAddr())
					}
				}
			}
		}

		// 3. Handle HTTPS CONNECT tunnel
		if req.Method == http.MethodConnect {
			target := req.Host
			log.Printf("[CONNECT] CONNECT to %s from Client %s", target, conn.RemoteAddr())

			destConn, err := net.DialTimeout("tcp", target, 5*time.Second)
			if err != nil {
				log.Printf("[CONNECT] Failed to dial remote target %s: %v", target, err)
				resp := fmt.Sprintf("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
				_, _ = conn.Write([]byte(resp))
				return
			}
			defer destConn.Close()

			// Send HTTP 200 Connection Established
			if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
				return
			}
			log.Printf("[CONNECT] Tunnel established: Client %s <==> Target %s", conn.RemoteAddr(), target)

			// Relay data bidirectionally
			startTime := time.Now()
			var bytesClientToTarget, bytesTargetToClient int64
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				n, _ := io.Copy(destConn, reader)
				bytesClientToTarget = n
				closeWrite(destConn)
			}()

			go func() {
				defer wg.Done()
				n, _ := io.Copy(conn, destConn)
				bytesTargetToClient = n
				closeWrite(conn)
			}()

			wg.Wait()
			duration := time.Since(startTime).Round(time.Millisecond)
			log.Printf("[CONNECT] Tunnel closed for %s | Up: %s | Down: %s | Duration: %v",
				target, formatBytes(bytesClientToTarget), formatBytes(bytesTargetToClient), duration)
			return
		}

		// 4. Handle standard plain HTTP forward request
		log.Printf("[HTTP] %s %s from %s", req.Method, req.URL.String(), conn.RemoteAddr())
		req.RequestURI = ""
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			httpResp := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
			_, _ = conn.Write([]byte(httpResp))
			return
		}
		_ = resp.Write(conn)
		_ = resp.Body.Close()
		return
	}
}



type closeWriter interface {
	CloseWrite() error
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	} else if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

func formatBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(1024), 0
	for n := b / 1024; n >= 1024; n /= 1024 {
		div *= 1024
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
