//go:build linux

package interceptor

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FindProcessUsingPort checks who is occupying a specific port (e.g. 18080) on Linux.
func FindProcessUsingPort(port uint16) (*ConflictingPortInfo, error) {
	// 1. Find the socket inode in /proc/net/tcp or /proc/net/tcp6
	targetHexPort := fmt.Sprintf("%04X", port)
	inode := findSocketInode(targetHexPort)
	if inode == "" {
		return nil, nil
	}

	// 2. Scan /proc/[pid]/fd to match socket:[inode]
	pid, procName, procPath := findProcessBySocketInode(inode)
	if pid == 0 {
		return &ConflictingPortInfo{
			LocalPort:   port,
			ProcessName: "Unknown",
			State:       "LISTEN",
		}, nil
	}

	return &ConflictingPortInfo{
		LocalPort:   port,
		PID:         pid,
		ProcessName: procName,
		ProcessPath: procPath,
		State:       "LISTEN",
	}, nil
}

// ScanReservedPortUsage scans for processes using ports in [portMin, portMax].
func ScanReservedPortUsage(portMin, portMax uint16) ([]ConflictingPortInfo, error) {
	var results []ConflictingPortInfo
	for p := portMin; p <= portMax; p++ {
		info, err := FindProcessUsingPort(p)
		if err == nil && info != nil {
			results = append(results, *info)
		}
	}
	return results, nil
}

func findSocketInode(hexPort string) string {
	files := []string{"/proc/net/tcp", "/proc/net/tcp6"}
	for _, fPath := range files {
		f, err := os.Open(fPath)
		if err != nil {
			continue
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
			if len(parts) == 2 && strings.EqualFold(parts[1], hexPort) {
				inode := fields[9]
				return inode
			}
		}
	}
	return ""
}

func findProcessBySocketInode(targetInode string) (uint32, string, string) {
	targetTarget := fmt.Sprintf("socket:[%s]", targetInode)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, "", ""
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
			if err == nil && dest == targetTarget {
				pid := uint32(pidInt)
				cmdlineBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
				cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
				exePath, _ := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
				procName := filepath.Base(exePath)
				if procName == "" || procName == "." {
					procName = cmdline
				}
				return pid, procName, exePath
			}
		}
	}

	return 0, "", ""
}
