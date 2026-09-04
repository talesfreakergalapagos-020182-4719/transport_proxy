package logger

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	isVerbose    atomic.Bool
	globalWriter *AsyncWriter
	writerMu     sync.Mutex
)

// AsyncWriter provides high-performance non-blocking asynchronous log writing
// with internal buffering, queue-drop protection, and periodic flushing.
type AsyncWriter struct {
	queue     chan []byte
	done      chan struct{}
	flushReq  chan chan struct{}
	file      *os.File
	filePath  string
	bufWriter *bufio.Writer
	dropped   atomic.Int64
	closed    atomic.Bool
	stopOnce  sync.Once
}

// NewAsyncWriter creates a new asynchronous log writer wrapping stdout and optional file.
func NewAsyncWriter(filePath string, alsoStdout bool) (*AsyncWriter, error) {
	var f *os.File
	var err error
	if filePath != "" {
		f, err = os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file %s: %w", filePath, err)
		}
	}

	var writers []io.Writer
	if alsoStdout {
		writers = append(writers, os.Stdout)
	}
	if f != nil {
		writers = append(writers, f)
	}

	var dest io.Writer
	if len(writers) == 0 {
		dest = io.Discard
	} else if len(writers) == 1 {
		dest = writers[0]
	} else {
		dest = io.MultiWriter(writers...)
	}

	w := &AsyncWriter{
		queue:     make(chan []byte, 32768),
		done:      make(chan struct{}),
		flushReq:  make(chan chan struct{}),
		file:      f,
		filePath:  filePath,
		bufWriter: bufio.NewWriterSize(dest, 64*1024),
	}

	go w.worker()
	return w, nil
}

func (w *AsyncWriter) worker() {
	defer close(w.done)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case msg, ok := <-w.queue:
			if !ok {
				// Queue closed: drain remaining items
				w.drainQueue()
				_ = w.bufWriter.Flush()
				return
			}
			if d := w.dropped.Swap(0); d > 0 {
				_, _ = w.bufWriter.WriteString(fmt.Sprintf("[LOGGER] Dropped %d log messages due to queue saturation\n", d))
			}
			_, _ = w.bufWriter.Write(msg)
			if len(w.queue) == 0 {
				_ = w.bufWriter.Flush()
			}
		case <-ticker.C:
			_ = w.bufWriter.Flush()
		case reply := <-w.flushReq:
			w.drainQueue()
			_ = w.bufWriter.Flush()
			if w.file != nil {
				_ = w.file.Sync()
			}
			close(reply)
		}
	}
}

func (w *AsyncWriter) drainQueue() {
	for {
		select {
		case msg, ok := <-w.queue:
			if !ok {
				return
			}
			_, _ = w.bufWriter.Write(msg)
		default:
			return
		}
	}
}

// Write queues the message asynchronously without blocking the caller.
func (w *AsyncWriter) Write(p []byte) (int, error) {
	if w.closed.Load() {
		return len(p), nil
	}

	buf := make([]byte, len(p))
	copy(buf, p)

	select {
	case w.queue <- buf:
		return len(p), nil
	default:
		w.dropped.Add(1)
		return len(p), nil
	}
}

// Flush flushes all buffered log messages to disk and destination writer.
func (w *AsyncWriter) Flush() {
	if w.closed.Load() {
		return
	}
	reply := make(chan struct{})
	select {
	case w.flushReq <- reply:
		<-reply
	case <-w.done:
	}
}

// Close flushes all queued log entries and closes the output file.
func (w *AsyncWriter) Close() error {
	var closeErr error
	w.stopOnce.Do(func() {
		w.closed.Store(true)
		close(w.queue)
		<-w.done
		if w.file != nil {
			closeErr = w.file.Close()
			w.file = nil
		}
	})
	return closeErr
}

// FilePath returns the target log file path.
func (w *AsyncWriter) FilePath() string {
	return w.filePath
}

// SetupGlobalLogger initializes the global asynchronous logger and sets log.SetOutput.
func SetupGlobalLogger(logPath string, alsoStdout bool) error {
	writerMu.Lock()
	defer writerMu.Unlock()

	if globalWriter != nil {
		if globalWriter.FilePath() == logPath {
			return nil
		}
		_ = globalWriter.Close()
		globalWriter = nil
	}

	w, err := NewAsyncWriter(logPath, alsoStdout)
	if err != nil {
		return err
	}

	globalWriter = w
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(w)
	return nil
}

// FlushGlobal flushes the global asynchronous log buffer.
func FlushGlobal() {
	writerMu.Lock()
	w := globalWriter
	writerMu.Unlock()
	if w != nil {
		w.Flush()
	}
}

// CloseGlobal closes the global asynchronous logger.
func CloseGlobal() {
	writerMu.Lock()
	w := globalWriter
	globalWriter = nil
	writerMu.Unlock()
	if w != nil {
		_ = w.Close()
	}
}

// SetVerbose enables or disables verbose debug logging.
func SetVerbose(v bool) {
	isVerbose.Store(v)
}

// IsVerbose returns true if verbose debug logging is enabled.
func IsVerbose() bool {
	return isVerbose.Load()
}

// Debugf logs formatted output only when verbose logging is enabled.
func Debugf(format string, v ...any) {
	if isVerbose.Load() {
		log.Printf(format, v...)
	}
}

// Infof logs formatted output unconditionally.
func Infof(format string, v ...any) {
	log.Printf(format, v...)
}

// Warnf logs warning formatted output unconditionally.
func Warnf(format string, v ...any) {
	log.Printf(format, v...)
}

// Errorf logs error formatted output unconditionally.
func Errorf(format string, v ...any) {
	log.Printf(format, v...)
}
