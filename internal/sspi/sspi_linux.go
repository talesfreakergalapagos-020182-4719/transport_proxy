//go:build linux

package sspi

import "fmt"

// SSPIContext is a stub context for Linux.
type SSPIContext struct{}

// NewSSPIContext creates a Linux SSPI context stub.
func NewSSPIContext(packageScheme string, spn string) (*SSPIContext, error) {
	return &SSPIContext{}, nil
}

// NextStep returns an error on Linux since Windows SSPI is not natively supported.
func (ctx *SSPIContext) NextStep(serverTokenBase64 string) (string, bool, error) {
	return "", false, fmt.Errorf("SSPI authentication is not supported natively on Linux")
}

// Release releases any allocated resources.
func (ctx *SSPIContext) Release() {
}

// ServerSSPIContext is a server-side stub context for Linux.
type ServerSSPIContext struct{}

// NewServerSSPIContext creates a Linux server SSPI context stub.
func NewServerSSPIContext(packageScheme string) (*ServerSSPIContext, error) {
	return &ServerSSPIContext{}, nil
}

// AcceptStep returns an error on Linux.
func (ctx *ServerSSPIContext) AcceptStep(clientTokenBase64 string) (string, bool, error) {
	return "", false, fmt.Errorf("SSPI authentication is not supported natively on Linux")
}

// Release releases resources.
func (ctx *ServerSSPIContext) Release() {
}
