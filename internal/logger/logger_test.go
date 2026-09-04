package logger

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestAsyncWriter(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	w, err := NewAsyncWriter(logPath, false)
	if err != nil {
		t.Fatalf("failed to create AsyncWriter: %v", err)
	}

	const nGoroutines = 10
	const nMessages = 100
	var wg sync.WaitGroup
	wg.Add(nGoroutines)

	for g := 0; g < nGoroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < nMessages; i++ {
				_, _ = w.Write([]byte("test log message\n"))
			}
		}(g)
	}

	wg.Wait()
	w.Flush()
	if err := w.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	expected := nGoroutines * nMessages
	if len(lines) != expected {
		t.Errorf("expected %d lines, got %d", expected, len(lines))
	}
}

func TestSetupGlobalLogger(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "global.log")

	if err := SetupGlobalLogger(logPath, false); err != nil {
		t.Fatalf("SetupGlobalLogger failed: %v", err)
	}
	defer CloseGlobal()

	SetVerbose(true)
	Debugf("hello debug\n")
	Infof("hello info\n")

	FlushGlobal()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "hello debug") {
		t.Errorf("missing debug log: %s", content)
	}
	if !strings.Contains(content, "hello info") {
		t.Errorf("missing info log: %s", content)
	}
}
