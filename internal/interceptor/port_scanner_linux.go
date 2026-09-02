//go:build linux

package interceptor

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FindProcessUsingPort checks who is occupying a specific port (e.g. 18080) on Linux.
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

type procDetails struct {
	pid      uint32
	procName string
	exePath  string
}

// ScanReservedPortUsage scans for processes using ports in [portMin, portMax] in a single pass.
func ScanReservedPortUsage(portMin, portMax uint16) ([]ConflictingPortInfo, error) {
	// 1. Scan /proc/net/tcp and /proc/net/tcp6 in a single pass to map socket inodes to ports
	inodeToPort := scanSocketInodesInRange(portMin, portMax)
	if len(inodeToPort) == 0 {
		return nil, nil
	}

	// 2. Scan /proc/*/fd in a single pass to resolve process info for all matched inodes
	inodeToProc := resolveProcessesForInodes(inodeToPort)

	results := make([]ConflictingPortInfo, 0, len(inodeToPort))
	for inode, port := range inodeToPort {
		info := ConflictingPortInfo{
			LocalPort: port,
			State:     "LISTEN",
		}
		if proc, ok := inodeToProc[inode]; ok {
			info.PID = proc.pid
			info.ProcessName = proc.procName
			info.ProcessPath = proc.exePath
		} else {
			info.ProcessName = "Unknown"
		}
		results = append(results, info)
	}

	return results, nil
}

func scanSocketInodesInRange(portMin, portMax uint16) map[string]uint16 {
	inodeToPort := make(map[string]uint16)
	files := []string{"/proc/net/tcp", "/proc/net/tcp6"}

	for _, fPath := range files {
		scanProcNetFile(fPath, portMin, portMax, inodeToPort)
	}
	return inodeToPort
}

func scanProcNetFile(fPath string, portMin, portMax uint16, result map[string]uint16) {
	f, err := os.Open(fPath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		port64, err := strconv.ParseUint(parts[1], 16, 16)
		if err != nil {
			continue
		}
		port := uint16(port64)

		if port >= portMin && port <= portMax {
			inode := fields[9]
			if inode != "0" && inode != "" {
				result[inode] = port
			}
		}
	}
}

func resolveProcessesForInodes(targetInodes map[string]uint16) map[string]procDetails {
	resolved := make(map[string]procDetails)
	if len(targetInodes) == 0 {
		return resolved
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return resolved
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pidInt, err := strconv.Atoi(entry.Name())
		if err != nil || pidInt <= 0 {
			continue
		}

		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fdEntry := range fdEntries {
			linkPath := filepath.Join(fdDir, fdEntry.Name())
			dest, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}

			if strings.HasPrefix(dest, "socket:[") && strings.HasSuffix(dest, "]") {
				inode := dest[8 : len(dest)-1]
				if _, needed := targetInodes[inode]; needed {
					pid := uint32(pidInt)
					cmdlineBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
					cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
					exePath, _ := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
					procName := filepath.Base(exePath)
					if procName == "" || procName == "." {
						procName = cmdline
					}
					resolved[inode] = procDetails{
						pid:      pid,
						procName: procName,
						exePath:  exePath,
					}
				}
			}
		}
	}

	return resolved
}
