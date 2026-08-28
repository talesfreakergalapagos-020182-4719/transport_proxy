package logger

import (
	"log"
	"sync/atomic"
)

var isVerbose atomic.Bool

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
