package proxy

import "testing"

func TestIsInteractiveService(t *testing.T) {
	tests := []struct {
		name      string
		proto     string
		port      uint16
		domain    string
		expected  bool
	}{
		// Standard interactive ports
		{"SSH port 22", "TCP", 22, "server.corp", true},
		{"Telnet port 23", "TCP", 23, "switch.corp", true},
		{"RDP port 3389", "TCP", 3389, "windows-vdi.corp", true},
		{"VNC standard 5900", "TCP", 5900, "workstation", true},
		{"VNC display 1 5901", "TCP", 5901, "workstation", true},
		{"TeamViewer port 5938", "TCP", 5938, "router.teamviewer.com", true},
		{"AnyDesk port 7070", "TCP", 7070, "relay.anydesk.com", true},

		// Database ports
		{"MySQL 3306", "TCP", 3306, "db.internal", true},
		{"Postgres 5432", "TCP", 5432, "pg.internal", true},
		{"Oracle 1521", "TCP", 1521, "oracle.corp", true},
		{"MSSQL 1433", "TCP", 1433, "sql.corp", true},
		{"Redis 6379", "TCP", 6379, "redis.cache", true},
		{"MongoDB 27017", "TCP", 27017, "mongo.internal", true},

		// Remote desktop domains
		{"AnyDesk domain", "HTTPS", 443, "relay.anydesk.com", true},
		{"TeamViewer domain", "HTTPS", 443, "router.teamviewer.com", true},
		{"Splashtop domain", "HTTPS", 443, "relay.splashtop.com", true},
		{"Windows Virtual Desktop", "HTTPS", 443, "client.wvd.microsoft.com", true},
		{"LogMeIn domain", "HTTPS", 443, "secure.logmein.com", true},
		{"RemoteDesktop domain", "HTTPS", 443, "gateway.remotedesktop.corp.com", true},

		// Detected protocols
		{"Proto SSH", "SSH", 8022, "gateway", true},
		{"Proto RDP", "RDP", 8389, "gateway", true},
		{"Proto VNC", "VNC", 8900, "gateway", true},

		// Standard web traffic (must NOT be treated as interactive permanent hold)
		{"Standard HTTP 80", "HTTP", 80, "example.com", false},
		{"Standard HTTPS 443", "HTTPS", 443, "api.github.com", false},
		{"Alt HTTP 8080", "HTTP", 8080, "jenkins.corp", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isInteractiveService(tt.proto, tt.port, tt.domain)
			if got != tt.expected {
				t.Errorf("isInteractiveService(%q, %d, %q) = %v, want %v",
					tt.proto, tt.port, tt.domain, got, tt.expected)
			}
		})
	}
}

func TestIsServerFirstPort(t *testing.T) {
	serverFirstPorts := []uint16{21, 22, 23, 25, 110, 143, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}
	for _, port := range serverFirstPorts {
		if !isServerFirstPort(port) {
			t.Errorf("Expected port %d to be server-first", port)
		}
	}

	clientFirstPorts := []uint16{80, 443, 8080, 8443, 9000, 3000, 5000}
	for _, port := range clientFirstPorts {
		if isServerFirstPort(port) {
			t.Errorf("Expected port %d NOT to be server-first", port)
		}
	}
}
