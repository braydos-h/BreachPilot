// Native UDP probing (no nmap subprocess). A connected UDP socket reports
// ECONNREFUSED when the target answers ICMP port-unreachable (closed),
// delivers a datagram when a service replies (open), and times out when
// packets vanish (open|filtered). Empty datagrams only: some services stay
// silent without a valid request, so silence is "filtered", never "closed".

package recon

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// UDPState is open, closed, or filtered (open|filtered).
type UDPState string

const (
	UDPOpen     UDPState = "open"
	UDPClosed   UDPState = "closed"
	UDPFiltered UDPState = "filtered"
)

// UDPResult is one UDP probe outcome.
type UDPResult struct {
	Port    int      `json:"port"`
	State   UDPState `json:"state"`
	Service string   `json:"service"`
}

// DefaultUDPProbes mirrors the common-service UDP surface (DNS, DHCP, TFTP,
// NTP, MSRPC, NetBIOS, SNMP, ISAKMP, SSDP).
var DefaultUDPProbes = []int{53, 67, 69, 123, 135, 137, 138, 161, 500, 1900}

var udpServiceNames = map[int]string{
	53: "dns", 67: "dhcp", 69: "tftp", 123: "ntp", 135: "msrpc",
	137: "netbios-ns", 138: "netbios-dgm", 161: "snmp", 500: "isakmp", 1900: "ssdp",
}

// ScanUDP probes UDP ports in parallel with an 800ms per-probe cap.
// ctx cancels the whole sweep.
func ScanUDP(ctx context.Context, ip string, ports []int) []UDPResult {
	const perProbe = 800 * time.Millisecond
	const maxParallel = 10
	out := make([]UDPResult, len(ports))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for i, port := range ports {
		i, port := i, port
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out[i] = UDPResult{Port: port, State: UDPFiltered}
				return
			}
			out[i] = probeUDP(ctx, ip, port, perProbe)
		}()
	}
	wg.Wait()
	return out
}

func probeUDP(ctx context.Context, ip string, port int, timeout time.Duration) UDPResult {
	res := UDPResult{Port: port, State: UDPFiltered, Service: udpServiceNames[port]}
	d := &net.Dialer{Timeout: timeout}
	cctx, cancel := context.WithTimeout(ctx, timeout+time.Second)
	defer cancel()
	conn, err := d.DialContext(cctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return res
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{}); err != nil {
		if refused(err) {
			res.State = UDPClosed
		}
		return res
	}
	buf := make([]byte, 2048)
	if _, err := conn.Read(buf); err != nil {
		if refused(err) {
			res.State = UDPClosed
		}
		return res
	}
	res.State = UDPOpen
	return res
}

// refused reports ICMP port-unreachable surfaced as ECONNREFUSED/RESET
// on the connected socket (works unprivileged on Linux and Windows).
func refused(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			return sysErr.Err == syscall.ECONNREFUSED || sysErr.Err == syscall.ECONNRESET
		}
		return strings.Contains(opErr.Err.Error(), "refused") || strings.Contains(opErr.Err.Error(), "reset")
	}
	return false
}

// MergeUDP folds open UDP results into the assessment: udp_ports plus
// protocol-tagged service entries. Closed ports never appear.
func (a *Assessment) MergeUDP(results []UDPResult) {
	if a == nil {
		return
	}
	for _, r := range results {
		if r.State != UDPOpen {
			continue
		}
		a.UDPPorts = append(a.UDPPorts, r.Port)
		name := r.Service
		if name == "" {
			name = udpServiceNames[r.Port]
		}
		if name == "" {
			name = "unknown-udp"
		}
		a.Services = append(a.Services, Service{Port: r.Port, Protocol: "udp", Service: name})
	}
}
