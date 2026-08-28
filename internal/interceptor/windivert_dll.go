package interceptor

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	ErrPacketTooShort        = errors.New("packet is too short")
	ErrInvalidHeaderLength   = errors.New("invalid header length")
	ErrWinDivertNotAvailable = errors.New("WinDivert.dll could not be loaded. Please ensure WinDivert.dll and WinDivert64.sys are placed in the same directory or system PATH")
)

// WinDivertDLL wraps the dynamically loaded WinDivert.dll procedures.
type WinDivertDLL struct {
	dll                          *syscall.LazyDLL
	procWinDivertOpen            *syscall.LazyProc
	procWinDivertRecv            *syscall.LazyProc
	procWinDivertSend            *syscall.LazyProc
	procWinDivertClose           *syscall.LazyProc
	procWinDivertSetParam        *syscall.LazyProc
	procWinDivertHelperCalcCksum *syscall.LazyProc
}

// LoadWinDivertDLL loads WinDivert.dll and resolves its exports.
func LoadWinDivertDLL() (*WinDivertDLL, error) {
	dll := syscall.NewLazyDLL("WinDivert.dll")
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWinDivertNotAvailable, err)
	}

	return &WinDivertDLL{
		dll:                          dll,
		procWinDivertOpen:            dll.NewProc("WinDivertOpen"),
		procWinDivertRecv:            dll.NewProc("WinDivertRecv"),
		procWinDivertSend:            dll.NewProc("WinDivertSend"),
		procWinDivertClose:           dll.NewProc("WinDivertClose"),
		procWinDivertSetParam:        dll.NewProc("WinDivertSetParam"),
		procWinDivertHelperCalcCksum: dll.NewProc("WinDivertHelperCalcChecksums"),
	}, nil
}

// Open opens a WinDivert handle with the specified filter expression, layer, priority, and flags.
func (d *WinDivertDLL) Open(filter string, layer int32, priority int16, flags uint64) (syscall.Handle, error) {
	filterBytes := append([]byte(filter), 0)

	r, _, err := d.procWinDivertOpen.Call(
		uintptr(unsafe.Pointer(&filterBytes[0])),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)

	handle := syscall.Handle(r)
	if handle == syscall.InvalidHandle {
		return syscall.InvalidHandle, fmt.Errorf("WinDivertOpen failed (filter=%q): %w", filter, err)
	}

	return handle, nil
}

// SetParam configures WinDivert kernel parameters (e.g. queue length, queue size, timeout).
func (d *WinDivertDLL) SetParam(handle syscall.Handle, param uint32, value uint64) error {
	r, _, err := d.procWinDivertSetParam.Call(
		uintptr(handle),
		uintptr(param),
		uintptr(value),
	)
	if r == 0 {
		return fmt.Errorf("WinDivertSetParam failed (param=%d, val=%d): %w", param, value, err)
	}
	return nil
}

// Recv receives a packet from the WinDivert handle.
func (d *WinDivertDLL) Recv(handle syscall.Handle, packetBuf []byte, addr *WinDivertAddress) (int, error) {
	var recvLen uint32

	r, _, err := d.procWinDivertRecv.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&packetBuf[0])),
		uintptr(len(packetBuf)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(addr)),
	)

	if r == 0 {
		return 0, fmt.Errorf("WinDivertRecv error: %w", err)
	}

	return int(recvLen), nil
}

// Send reinjects a packet to the network stack.
func (d *WinDivertDLL) Send(handle syscall.Handle, packetBuf []byte, addr *WinDivertAddress) (int, error) {
	var sendLen uint32

	r, _, err := d.procWinDivertSend.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&packetBuf[0])),
		uintptr(len(packetBuf)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(addr)),
	)

	if r == 0 {
		return 0, fmt.Errorf("WinDivertSend error: %w", err)
	}

	return int(sendLen), nil
}

// CalcChecksums recalculates IPv4 and TCP/UDP checksums for modified packets.
func (d *WinDivertDLL) CalcChecksums(packetBuf []byte, addr *WinDivertAddress, flags uint64) error {
	r, _, err := d.procWinDivertHelperCalcCksum.Call(
		uintptr(unsafe.Pointer(&packetBuf[0])),
		uintptr(len(packetBuf)),
		uintptr(unsafe.Pointer(addr)),
		uintptr(flags),
	)

	if r == 0 {
		return fmt.Errorf("WinDivertHelperCalcChecksums error: %w", err)
	}

	return nil
}

// Close closes the WinDivert handle, restoring standard OS network routing.
func (d *WinDivertDLL) Close(handle syscall.Handle) error {
	if handle == syscall.InvalidHandle {
		return nil
	}

	r, _, err := d.procWinDivertClose.Call(uintptr(handle))
	if r == 0 {
		return fmt.Errorf("WinDivertClose error: %w", err)
	}

	return nil
}
