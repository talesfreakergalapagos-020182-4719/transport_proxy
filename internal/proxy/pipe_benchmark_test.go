package proxy

import (
	"net"
	"testing"
	"time"
)

func BenchmarkPipeConnThroughput(b *testing.B) {
	// Setup high-throughput simulated in-memory TCP pipe
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	chunkSize := 64 * 1024
	totalBytes := int64(b.N) * int64(chunkSize)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, chunkSize)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatalf("Failed to dial: %v", err)
	}
	defer clientConn.Close()

	// Intermediary proxy pipe
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to listen proxyLn: %v", err)
	}
	defer proxyLn.Close()

	var proxyClientConn net.Conn
	connChan := make(chan net.Conn, 1)
	go func() {
		c, err := proxyLn.Accept()
		if err == nil {
			connChan <- c
		}
	}()

	rawClient, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		b.Fatalf("Failed to dial proxy: %v", err)
	}
	defer rawClient.Close()
	proxyClientConn = <-connChan

	go func() {
		PipeConn(proxyClientConn, clientConn, nil, 10*time.Second)
	}()

	sendData := make([]byte, chunkSize)
	b.SetBytes(int64(chunkSize))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := rawClient.Write(sendData)
		if err != nil {
			b.Fatalf("Write failed: %v", err)
		}
	}

	_ = totalBytes
}
