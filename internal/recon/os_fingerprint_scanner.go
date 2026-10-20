package recon

import (
	"context"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OSFingerprintOptions configures OS fingerprinting behavior.
type OSFingerprintOptions struct {
	AllowPrivilegedNmap bool
	UseSudo             bool
	Timeout             time.Duration
}

// OSFingerprint holds the structured OS identification result.
type OSFingerprint struct {
	Family        string   `json:"family"`
	Distro        string   `json:"distro,omitempty"`
	Generation    string   `json:"generation,omitempty"`
	Confidence    float64  `json:"confidence"`
	CPEs          []string `json:"cpes"`
	Signals       []string `json:"signals"`
	PrivilegeMode string   `json:"privilege_mode"`
	Note          string   `json:"note,omitempty"`
}

func isRootPrivilege() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return os.Geteuid() == 0
}

// FingerprintOS performs multi-signal OS fingerprinting with graceful handling
// of insufficient privileges: if privileged nmap (-O) is permitted and root/sudo
// is available, it attempts nmap OS detection first; otherwise (or on failure)
// it falls back to unprivileged native banner/protocol/port-signature analysis.
func FingerprintOS(ctx context.Context, ip string, openPorts []int, services []Service, opts OSFingerprintOptions) OSFingerprint {
	fp := OSFingerprint{
		Family:        "UNKNOWN",
		Confidence:    0.0,
		CPEs:          []string{},
		Signals:       []string{},
		PrivilegeMode: "unprivileged_native",
	}

	if opts.AllowPrivilegedNmap && (isRootPrivilege() || opts.UseSudo) {
		if _, err := exec.LookPath("nmap"); err == nil {
			timeout := opts.Timeout
			if timeout <= 0 {
				timeout = 15 * time.Second
			}
			cctx, cancel := context.WithTimeout(ctx, timeout)
			argv, note := ApplyNmapPrivilege([]string{"nmap", "-O", "--osscan-limit", "-Pn", ip}, isRootPrivilege(), opts.UseSudo, true)
			cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
			outBytes, err := cmd.CombinedOutput()
			cancel()
			if err == nil {
				out := string(outBytes)
				if strings.Contains(out, "OS details:") || strings.Contains(out, "Running:") {
					fp.PrivilegeMode = "nmap_privileged"
					if strings.Contains(strings.ToLower(out), "linux") {
						fp.Family = "Linux"
						fp.Confidence = 0.92
						fp.CPEs = append(fp.CPEs, "cpe:/o:linux:linux_kernel")
						fp.Signals = append(fp.Signals, "nmap -O TCP/IP stack match: Linux")
						return fp
					}
					if strings.Contains(strings.ToLower(out), "windows") {
						fp.Family = "Windows"
						fp.Confidence = 0.92
						fp.CPEs = append(fp.CPEs, "cpe:/o:microsoft:windows")
						fp.Signals = append(fp.Signals, "nmap -O TCP/IP stack match: Windows")
						return fp
					}
				}
			}
			if note != "" {
				fp.Note = note
			}
		} else {
			fp.Note = "nmap binary not present; using native unprivileged fingerprinting"
		}
	} else if opts.AllowPrivilegedNmap {
		fp.Note = "insufficient privileges for raw-socket OS scan; downgraded to unprivileged native fingerprinting"
	}

	verdict, hints := InferOS(openPorts, services)
	fp.Family = verdict
	fp.Signals = append(fp.Signals, hints...)

	combined := strings.ToLower(strings.Join(hints, " "))
	for _, s := range services {
		b := strings.ToLower(s.Banner + " " + s.Version)
		combined += " " + b
		switch {
		case strings.Contains(b, "ubuntu"):
			fp.Family = "Linux"
			fp.Distro = "Ubuntu"
			fp.Signals = append(fp.Signals, "banner distro token: Ubuntu")
			addUniqueStr(&fp.CPEs, "cpe:/o:canonical:ubuntu_linux")
		case strings.Contains(b, "debian"):
			fp.Family = "Linux"
			fp.Distro = "Debian"
			fp.Signals = append(fp.Signals, "banner distro token: Debian")
			addUniqueStr(&fp.CPEs, "cpe:/o:debian:debian_linux")
		case strings.Contains(b, "alpine"):
			fp.Family = "Linux"
			fp.Distro = "Alpine"
			fp.Signals = append(fp.Signals, "banner distro token: Alpine")
			addUniqueStr(&fp.CPEs, "cpe:/o:alpinelinux:alpine_linux")
		case strings.Contains(b, "centos") || strings.Contains(b, "rhel") || strings.Contains(b, "red hat"):
			fp.Family = "Linux"
			fp.Distro = "RHEL/CentOS"
			fp.Signals = append(fp.Signals, "banner distro token: RHEL/CentOS")
			addUniqueStr(&fp.CPEs, "cpe:/o:redhat:enterprise_linux")
		case strings.Contains(b, "freebsd"):
			fp.Family = "BSD"
			fp.Distro = "FreeBSD"
			fp.Signals = append(fp.Signals, "banner distro token: FreeBSD")
			addUniqueStr(&fp.CPEs, "cpe:/o:freebsd:freebsd")
		case strings.Contains(b, "microsoft-iis") || strings.Contains(b, "win32") || strings.Contains(b, "windows"):
			fp.Family = "Windows"
			fp.Distro = "Windows Server"
			fp.Signals = append(fp.Signals, "banner token: Microsoft Windows/IIS")
			addUniqueStr(&fp.CPEs, "cpe:/o:microsoft:windows")
		}
	}

	switch fp.Family {
	case "Linux":
		addUniqueStr(&fp.CPEs, "cpe:/o:linux:linux_kernel")
		if fp.Distro != "" {
			fp.Confidence = 0.85
		} else {
			fp.Confidence = 0.70
		}
	case "Windows":
		addUniqueStr(&fp.CPEs, "cpe:/o:microsoft:windows")
		if fp.Distro != "" {
			fp.Confidence = 0.85
		} else {
			fp.Confidence = 0.75
		}
	case "BSD":
		fp.Confidence = 0.80
	default:
		fp.Confidence = 0.0
	}
	_ = combined
	return fp
}

func addUniqueStr(slice *[]string, val string) {
	for _, s := range *slice {
		if s == val {
			return
		}
	}
	*slice = append(*slice, val)
}

// FastScannerOptions configures high-speed port discovery (rustscan/masscan/native).
type FastScannerOptions struct {
	PreferExternal bool
	Rate           int
	Concurrency    int
	Timeout        time.Duration
}

// FastScanSummary reports the high-speed port scan outcome and backend used.
type FastScanSummary struct {
	Backend   string `json:"backend"`
	OpenPorts []int  `json:"open_ports"`
	Note      string `json:"note,omitempty"`
}

var (
	masscanRe  = regexp.MustCompile(`Discovered open port (\d+)/tcp`)
	rustscanRe = regexp.MustCompile(`Open [^\s:]+:(\d+)`)
)

// ParseMasscanOutput extracts sorted unique open TCP ports from masscan stdout.
func ParseMasscanOutput(out string) []int {
	seen := map[int]bool{}
	var ports []int
	for _, m := range masscanRe.FindAllStringSubmatch(out, -1) {
		if p, err := strconv.Atoi(m[1]); err == nil && p > 0 && p <= 65535 && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	return ports
}

// ParseRustscanOutput extracts sorted unique open TCP ports from rustscan stdout.
func ParseRustscanOutput(out string) []int {
	seen := map[int]bool{}
	var ports []int
	for _, m := range rustscanRe.FindAllStringSubmatch(out, -1) {
		if p, err := strconv.Atoi(m[1]); err == nil && p > 0 && p <= 65535 && !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	return ports
}

// RunFastScanner executes port discovery using rustscan or masscan when
// PreferExternal is true and the binary/privileges are available, and
// seamlessly falls back to the high-concurrency native Go connect scanner.
func RunFastScanner(ctx context.Context, ip string, ports []int, opts FastScannerOptions) FastScanSummary {
	if len(ports) == 0 {
		ports = DefaultFastPorts
	}
	if opts.PreferExternal {
		portSpec := intsToCSV(ports)
		if _, err := exec.LookPath("rustscan"); err == nil {
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			cmd := exec.CommandContext(cctx, "rustscan", "-a", ip, "-p", portSpec, "-g")
			out, err := cmd.CombinedOutput()
			cancel()
			if err == nil {
				return FastScanSummary{
					Backend:   "rustscan",
					OpenPorts: ParseRustscanOutput(string(out)),
				}
			}
		}
		if isRootPrivilege() {
			if _, err := exec.LookPath("masscan"); err == nil {
				rate := opts.Rate
				if rate <= 0 {
					rate = 1000
				}
				cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				cmd := exec.CommandContext(cctx, "masscan", ip, "-p"+portSpec, "--rate", strconv.Itoa(rate))
				out, err := cmd.CombinedOutput()
				cancel()
				if err == nil {
					return FastScanSummary{
						Backend:   "masscan",
						OpenPorts: ParseMasscanOutput(string(out)),
					}
				}
			}
		}
	}

	workers := opts.Concurrency
	if workers <= 0 {
		workers = 64
	}
	perPort := opts.Timeout
	if perPort <= 0 {
		perPort = 800 * time.Millisecond
	}
	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	var open []int
	var wg sync.WaitGroup
	for _, port := range ports {
		port := port
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			d := net.Dialer{Timeout: perPort}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			if err == nil {
				_ = conn.Close()
				mu.Lock()
				open = append(open, port)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Ints(open)
	if open == nil {
		open = []int{}
	}
	return FastScanSummary{
		Backend:   "native_go",
		OpenPorts: open,
	}
}

func intsToCSV(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ",")
}
