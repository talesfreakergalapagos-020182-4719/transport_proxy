//go:build windows

package interceptor

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	modIphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")

	modKernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess               = modKernel32.NewProc("OpenProcess")
	procQueryFullProcessImageName = modKernel32.NewProc("QueryFullProcessImageNameW")
	procCloseHandle               = modKernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot  = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First            = modKernel32.NewProc("Process32FirstW")
	procProcess32Next             = modKernel32.NewProc("Process32NextW")
)

const (
	afInet                 = 2  // AF_INET (IPv4)
	afInet6                = 23 // AF_INET6 (IPv6)
	tcpTableOwnerPidAll    = 5  // TCP_TABLE_OWNER_PID_ALL
	processQueryLimitedInf = 0x1000
	th32csSnapProcess      = 0x00000002
)

// TCPState maps Windows TCP state numbers to readable strings.
var tcpStateNames = map[uint32]string{
	1:  "CLOSED",
	2:  "LISTEN",
	3:  "SYN_SENT",
	4:  "SYN_RCVD",
	5:  "ESTABLISHED",
	6:  "FIN_WAIT1",
	7:  "FIN_WAIT2",
	8:  "CLOSE_WAIT",
	9:  "CLOSING",
	10: "LAST_ACK",
	11: "TIME_WAIT",
	12: "DELETE_TCB",
}

// MIB_TCPROW_OWNER_PID represents a single IPv4 row in the extended TCP table.
type mibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32 // in network byte order
	RemoteAddr uint32
	RemotePort uint32 // in network byte order
	OwningPid  uint32
}

// MIB_TCP6ROW_OWNER_PID represents a single IPv6 row in the extended TCP table.
type mibTcp6RowOwnerPid struct {
	LocalAddr     [16]byte
	LocalScopeId  uint32
	LocalPort     uint32 // in network byte order
	RemoteAddr    [16]byte
	RemoteScopeId uint32
	RemotePort    uint32 // in network byte order
	State         uint32
	OwningPid     uint32
}

type processEntry32W struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [260]uint16
}

// ScanReservedPortUsage scans both IPv4 and IPv6 Windows TCP tables and finds any non-tproxy process using ports in [portMin, portMax].
func ScanReservedPortUsage(portMin, portMax uint16) ([]ConflictingPortInfo, error) {
	selfPID := uint32(os.Getpid())
	var results []ConflictingPortInfo

	// 1. Scan IPv4 TCP Table
	v4Results, err4 := scanIPv4Table(portMin, portMax, selfPID)
	if err4 == nil {
		results = append(results, v4Results...)
	}

	// 2. Scan IPv6 TCP Table
	v6Results, err6 := scanIPv6Table(portMin, portMax, selfPID)
	if err6 == nil {
		results = append(results, v6Results...)
	}

	if err4 != nil && err6 != nil {
		return nil, fmt.Errorf("failed to scan TCP tables (v4: %v, v6: %v)", err4, err6)
	}

	return results, nil
}

// FindProcessUsingPort checks who is occupying a specific port (e.g. 18080 or any single port).
func FindProcessUsingPort(port uint16) (*ConflictingPortInfo, error) {
	list, err := ScanReservedPortUsage(port, port)
	if err != nil {
		return nil, err
	}
	if len(list) > 0 {
		return &list[0], nil
	}
	return nil, nil
}

func scanIPv4Table(portMin, portMax uint16, selfPID uint32) ([]ConflictingPortInfo, error) {
	var buf []byte
	var numEntries uint32

	for attempt := 0; attempt < 3; attempt++ {
		var bufSize uint32
		r, _, _ := procGetExtendedTcpTable.Call(
			0,
			uintptr(unsafe.Pointer(&bufSize)),
			0,
			afInet,
			tcpTableOwnerPidAll,
			0,
		)
		if r != 0 && r != uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
			return nil, fmt.Errorf("GetExtendedTcpTable size query failed: %d", r)
		}

		buf = make([]byte, bufSize)
		r, _, _ = procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&bufSize)),
			0,
			afInet,
			tcpTableOwnerPidAll,
			0,
		)
		if r == 0 {
			if len(buf) >= 4 {
				numEntries = binary.LittleEndian.Uint32(buf[0:4])
			}
			break
		}
		if r != uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
			return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", r)
		}
	}

	if len(buf) < 4 {
		return nil, nil
	}

	rowSize := int(unsafe.Sizeof(mibTcpRowOwnerPid{}))
	offset := 4
	var results []ConflictingPortInfo

	for i := uint32(0); i < numEntries; i++ {
		if offset+rowSize > len(buf) {
			break
		}

		row := (*mibTcpRowOwnerPid)(unsafe.Pointer(&buf[offset]))
		offset += rowSize

		localPort := binary.BigEndian.Uint16([]byte{byte(row.LocalPort), byte(row.LocalPort >> 8)})
		remotePort := binary.BigEndian.Uint16([]byte{byte(row.RemotePort), byte(row.RemotePort >> 8)})

		if localPort >= portMin && localPort <= portMax && row.OwningPid != selfPID && row.OwningPid != 0 {
			stateStr := tcpStateNames[row.State]
			if stateStr == "" {
				stateStr = fmt.Sprintf("STATE_%d", row.State)
			}

			localIP := make(net.IP, 4)
			binary.LittleEndian.PutUint32(localIP, row.LocalAddr)

			remoteIP := make(net.IP, 4)
			binary.LittleEndian.PutUint32(remoteIP, row.RemoteAddr)

			procName, procPath := resolveProcessInfo(row.OwningPid)

			results = append(results, ConflictingPortInfo{
				LocalPort:   localPort,
				RemotePort:  remotePort,
				LocalIP:     localIP,
				RemoteIP:    remoteIP,
				State:       stateStr,
				PID:         row.OwningPid,
				ProcessName: procName,
				ProcessPath: procPath,
			})
		}
	}

	return results, nil
}

func scanIPv6Table(portMin, portMax uint16, selfPID uint32) ([]ConflictingPortInfo, error) {
	var buf []byte
	var numEntries uint32

	for attempt := 0; attempt < 3; attempt++ {
		var bufSize uint32
		r, _, _ := procGetExtendedTcpTable.Call(
			0,
			uintptr(unsafe.Pointer(&bufSize)),
			0,
			afInet6,
			tcpTableOwnerPidAll,
			0,
		)
		if r != 0 && r != uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
			return nil, fmt.Errorf("GetExtendedTcpTable (v6) size query failed: %d", r)
		}

		buf = make([]byte, bufSize)
		r, _, _ = procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&bufSize)),
			0,
			afInet6,
			tcpTableOwnerPidAll,
			0,
		)
		if r == 0 {
			if len(buf) >= 4 {
				numEntries = binary.LittleEndian.Uint32(buf[0:4])
			}
			break
		}
		if r != uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
			return nil, fmt.Errorf("GetExtendedTcpTable (v6) failed: %d", r)
		}
	}

	if len(buf) < 4 {
		return nil, nil
	}

	rowSize := int(unsafe.Sizeof(mibTcp6RowOwnerPid{}))
	offset := 4
	var results []ConflictingPortInfo

	for i := uint32(0); i < numEntries; i++ {
		if offset+rowSize > len(buf) {
			break
		}

		row := (*mibTcp6RowOwnerPid)(unsafe.Pointer(&buf[offset]))
		offset += rowSize

		localPort := binary.BigEndian.Uint16([]byte{byte(row.LocalPort), byte(row.LocalPort >> 8)})
		remotePort := binary.BigEndian.Uint16([]byte{byte(row.RemotePort), byte(row.RemotePort >> 8)})

		if localPort >= portMin && localPort <= portMax && row.OwningPid != selfPID && row.OwningPid != 0 {
			stateStr := tcpStateNames[row.State]
			if stateStr == "" {
				stateStr = fmt.Sprintf("STATE_%d", row.State)
			}

			localIP := append(net.IP(nil), row.LocalAddr[:]...)
			remoteIP := append(net.IP(nil), row.RemoteAddr[:]...)

			procName, procPath := resolveProcessInfo(row.OwningPid)

			results = append(results, ConflictingPortInfo{
				LocalPort:   localPort,
				RemotePort:  remotePort,
				LocalIP:     localIP,
				RemoteIP:    remoteIP,
				State:       stateStr,
				PID:         row.OwningPid,
				ProcessName: procName,
				ProcessPath: procPath,
			})
		}
	}

	return results, nil
}

// resolveProcessInfo retrieves the process image name and full executable path for a PID.
func resolveProcessInfo(pid uint32) (string, string) {
	if pid == 0 {
		return "System (TIME_WAIT)", ""
	}
	if pid == 4 {
		return "System", "ntoskrnl.exe"
	}

	path := getProcessPath(pid)
	if path != "" {
		return filepath.Base(path), path
	}

	// Fallback to Toolhelp snapshot if OpenProcess failed (e.g. system services)
	name := getProcessNameFromSnapshot(pid)
	if name != "" {
		return name, ""
	}

	return fmt.Sprintf("Process (PID %d)", pid), ""
}

// getProcessPath queries the executable image path for a given process ID.
func getProcessPath(pid uint32) string {
	hProc, _, _ := procOpenProcess.Call(processQueryLimitedInf, 0, uintptr(pid))
	if hProc == 0 {
		return ""
	}
	defer procCloseHandle.Call(hProc)

	var buf [1024]uint16
	size := uint32(len(buf))

	r, _, _ := procQueryFullProcessImageName.Call(
		hProc,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r == 0 {
		return ""
	}

	return syscall.UTF16ToString(buf[:size])
}

// getProcessNameFromSnapshot queries the process name from a system process snapshot.
func getProcessNameFromSnapshot(targetPID uint32) string {
	hSnapshot, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if hSnapshot == uintptr(syscall.InvalidHandle) || hSnapshot == 0 {
		return ""
	}
	defer procCloseHandle.Call(hSnapshot)

	var pe processEntry32W
	pe.Size = uint32(unsafe.Sizeof(pe))

	r, _, _ := procProcess32First.Call(hSnapshot, uintptr(unsafe.Pointer(&pe)))
	for r != 0 {
		if pe.ProcessID == targetPID {
			return syscall.UTF16ToString(pe.ExeFile[:])
		}
		r, _, _ = procProcess32Next.Call(hSnapshot, uintptr(unsafe.Pointer(&pe)))
	}
	return ""
}
