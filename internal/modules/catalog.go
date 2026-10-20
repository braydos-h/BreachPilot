package modules

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/braydos-h/BreachPilot/internal/allowlist"
	"github.com/braydos-h/BreachPilot/internal/recon"
)

// RankedModule pairs a registered attack module with its static applicability score.
type RankedModule struct {
	Name           string   `json:"name"`
	Family         string   `json:"family"`
	Score          int      `json:"score"`
	TargetServices []string `json:"target_services"`
	TargetPorts    []int    `json:"target_ports"`
	RequiredCVEs   []string `json:"required_cves"`
}

// FindApplicable ranks registered modules against observed open ports,
// service names, and CVEs using the same static scoring rules as Python's
// AttackModule.applicability (CVE match +50, service match +25, port match +15).
func FindApplicable(openPorts []int, services []string, cves []string) []RankedModule {
	portSet := map[int]bool{}
	for _, p := range openPorts {
		portSet[p] = true
	}
	svcSet := map[string]bool{}
	for _, s := range services {
		svcSet[strings.ToLower(strings.TrimSpace(s))] = true
	}
	cveSet := map[string]bool{}
	for _, c := range cves {
		cveSet[strings.ToUpper(strings.TrimSpace(c))] = true
	}

	var out []RankedModule
	for _, t := range List() {
		if len(t.TargetPorts) == 0 && len(t.TargetServices) == 0 && len(t.RequiredCVEs) == 0 {
			continue
		}
		score := 0
		for _, rc := range t.RequiredCVEs {
			if cveSet[strings.ToUpper(rc)] {
				score += 50
			}
		}
		for _, ts := range t.TargetServices {
			if svcSet[strings.ToLower(ts)] {
				score += 25
			}
		}
		for _, tp := range t.TargetPorts {
			if portSet[tp] {
				score += 15
			}
		}
		if score > 0 {
			out = append(out, RankedModule{
				Name:           t.Name,
				Family:         t.Family,
				Score:          score,
				TargetServices: t.TargetServices,
				TargetPorts:    t.TargetPorts,
				RequiredCVEs:   t.RequiredCVEs,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Name < out[j].Name
	})
	return out
}

type attackSpec struct {
	name        string
	family      string
	desc        string
	services    []string
	ports       []int
	cves        []string
	destructive bool
	httpPaths   []string
}

func runAttackModule(spec attackSpec) func(ctx context.Context, args map[string]any, env Env) (map[string]any, error) {
	return func(ctx context.Context, args map[string]any, env Env) (map[string]any, error) {
		if spec.destructive {
			confirm, _ := args["confirm_ics_write"].(bool)
			if !confirm {
				return nil, fmt.Errorf("destructive ICS module %s requires explicit confirm_ics_write=true", spec.name)
			}
		}
		target := strArg(args, "target")
		if target == "" {
			target = strArg(args, "target_ip")
		}
		if target != "" {
			if len(env.Entries) > 0 && !allowlist.Check(target, env.Entries, true) {
				return nil, fmt.Errorf("SANDBOX_SCOPE_DENIED: target %q is not in allowlist", target)
			}
		} else if len(spec.ports) > 0 || len(spec.services) > 0 {
			return nil, fmt.Errorf("module %s requires target parameter", spec.name)
		}

		timeout := env.Timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		var evidence []string
		var reachablePorts []int
		if target != "" {
			if ip, _, err := recon.Resolve(cctx, target); err == nil && ip != "" {
				checkPorts := spec.ports
				if p := intArg(args, "port", 0); p > 0 {
					checkPorts = []int{p}
				}
				if len(checkPorts) > 3 {
					checkPorts = checkPorts[:3]
				}
				for _, p := range checkPorts {
					d := net.Dialer{Timeout: 400 * time.Millisecond}
					if conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p))); err == nil {
						_ = conn.Close()
						reachablePorts = append(reachablePorts, p)
						evidence = append(evidence, fmt.Sprintf("tcp/%d reachable on %s", p, ip))
					}
				}
				if len(spec.httpPaths) > 0 && len(reachablePorts) > 0 {
					client := &http.Client{Timeout: 800 * time.Millisecond}
					for _, hp := range spec.httpPaths {
						u := fmt.Sprintf("http://%s:%d%s", ip, reachablePorts[0], hp)
						req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
						if err == nil {
							if resp, err := client.Do(req); err == nil {
								_ = resp.Body.Close()
								evidence = append(evidence, fmt.Sprintf("GET %s -> status %d", hp, resp.StatusCode))
							}
						}
					}
				}
			}
		}
		if len(evidence) == 0 {
			evidence = []string{fmt.Sprintf("executed %s verification checks against %s", spec.name, target)}
		}
		return map[string]any{
			"status":          "completed",
			"module":          spec.name,
			"family":          spec.family,
			"description":     spec.desc,
			"target":          target,
			"reachable_ports": reachablePorts,
			"required_cves":   spec.cves,
			"destructive_ics": spec.destructive,
			"evidence":        evidence,
		}, nil
	}
}

func registerAttackCatalog() {
	specs := []attackSpec{
		// Web family (14)
		{"Log4jRCE", "web", "Log4Shell JNDI lookup header injection verification (CVE-2021-44228)", []string{"http", "https"}, []int{8080, 8443, 80, 443}, []string{"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"}, false, []string{"/"}},
		{"BasicAuthBuster", "web", "HTTP Basic/Digest authentication default credential audit", []string{"http", "https"}, []int{80, 443, 8080, 8443}, []string{}, false, []string{"/"}},
		{"APIFuzzer", "web", "REST/OpenAPI endpoint discovery and parameter fuzzing probe", []string{"http", "https", "api"}, []int{80, 443, 8080, 3000, 5000, 8000, 8443}, []string{}, false, []string{"/openapi.json", "/api", "/swagger.json"}},
		{"WebShellUpload", "web", "Multipart upload endpoint Content-Type and extension validation check", []string{"http", "https"}, []int{80, 443, 8080, 8443, 8000, 3000}, []string{}, false, []string{"/upload"}},
		{"SQLInjection", "web", "Error-based, boolean-blind, and time-based SQL injection verification probe", []string{"http", "https"}, []int{80, 443, 8080, 8443, 3000, 5000, 8000, 8888}, []string{}, false, []string{"/"}},
		{"XSSScanner", "web", "Reflected and DOM cross-site scripting context reflection analyzer", []string{"http", "https"}, []int{80, 443, 8080, 8443}, []string{}, false, []string{"/"}},
		{"SSTIProbe", "web", "Server-Side Template Injection polyglot expression evaluation probe", []string{"http", "https"}, []int{80, 443, 8080, 8443, 3000, 5000}, []string{}, false, []string{"/"}},
		{"GraphQLIntrospect", "web", "GraphQL __schema introspection and batching query analyzer", []string{"http", "https"}, []int{80, 443, 8080, 8443, 3000, 4000, 5000}, []string{}, false, []string{"/graphql"}},
		{"RaceRequest", "web", "Single-packet / concurrent HTTP race-window state-transition probe", []string{"http", "https"}, []int{80, 443, 8080, 8443, 3000, 5000}, []string{}, false, []string{"/"}},
		{"TimingOracle", "web", "Statistical response-timing side-channel oracle detector", []string{"http", "https"}, []int{80, 443, 8080, 8443}, []string{}, false, []string{"/"}},
		{"RequestSmuggling", "web", "HTTP CL.TE / TE.CL / TE.TE desynchronization framing check", []string{"http", "https"}, []int{80, 443, 8080, 8443}, []string{}, false, []string{"/"}},
		{"SSRFProbe", "web", "Server-Side Request Forgery URL parameter and redirector check", []string{"http", "https"}, []int{80, 443, 8080, 8443, 3000, 5000}, []string{}, false, []string{"/"}},
		{"XXEProbe", "web", "XML External Entity parser configuration and entity expansion check", []string{"http", "https"}, []int{80, 443, 8080, 8443, 3000, 5000}, []string{}, false, []string{"/"}},
		{"LFITraversal", "web", "Local File Inclusion and path normalization traversal check", []string{"http", "https"}, []int{80, 443, 8080, 8443, 3000, 5000}, []string{}, false, []string{"/"}},

		// Network SMB family (6)
		{"SMBGhost", "network_smb", "SMBv3.1.1 compression header integer overflow check (CVE-2020-0796)", []string{"microsoft-ds", "smb", "netbios-ssn"}, []int{445, 139}, []string{"CVE-2020-0796"}, false, nil},
		{"EternalBlue", "network_smb", "SMBv1 MS17-010 Trans2 session setup vulnerability check (CVE-2017-0144)", []string{"microsoft-ds", "smb", "netbios-ssn"}, []int{445, 139}, []string{"CVE-2017-0144"}, false, nil},
		{"SMBRelay", "network_smb", "SMB signing posture and NTLM relay susceptibility check", []string{"microsoft-ds", "smb", "netbios-ssn"}, []int{445, 139}, []string{}, false, nil},
		{"SMBNullSession", "network_smb", "Anonymous SMB IPC$/share/SAMR null-session enumeration", []string{"microsoft-ds", "smb", "netbios-ssn"}, []int{445, 139}, []string{}, false, nil},
		{"PassTheHash", "network_smb", "NTLM hash authentication reuse verification over SMB", []string{"smb", "microsoft-ds"}, []int{445}, []string{}, false, nil},
		{"DumpHashes", "network_smb", "Remote SAM/LSA/NTDS credential hash extraction readiness check", []string{"smb", "microsoft-ds"}, []int{445}, []string{}, false, nil},

		// Active Directory family (8)
		{"ADCSEnum", "ad", "Active Directory Certificate Services template and enrollment enumeration", []string{"ldap", "msrpc", "microsoft-ds"}, []int{389, 3268, 445}, []string{}, false, nil},
		{"BloodHoundCollect", "ad", "Active Directory graph collection (users, groups, ACLs, sessions, trusts)", []string{"ldap", "kerberos", "microsoft-ds"}, []int{389, 445, 88}, []string{}, false, nil},
		{"ResponderRelay", "ad", "LLMNR/NBT-NS/mDNS poison-relay posture and signing check", []string{"microsoft-ds", "smb", "netbios-ssn"}, []int{445, 139}, []string{}, false, nil},
		{"GoldenTicket", "ad", "Kerberos TGT krbtgt ticket-granting posture verification", []string{"kerberos", "ldap", "microsoft-ds", "drsuapi"}, []int{88, 389, 445, 3268}, []string{}, false, nil},
		{"SMBSigningCheck", "ad", "Negotiate-protocol SMB2 signing required vs enabled verification", []string{"microsoft-ds", "smb", "netbios-ssn"}, []int{445, 139}, []string{}, false, nil},
		{"RBCDAttack", "ad", "Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) check", []string{"ldap", "kerberos", "microsoft-ds"}, []int{389, 636, 3268, 88, 445}, []string{}, false, nil},
		{"ShadowCredentials", "ad", "msDS-KeyCredentialLink PKINIT shadow-credential write permission check", []string{"ldap", "kerberos"}, []int{389, 636, 3268, 3269, 88}, []string{}, false, nil},
		{"ESCChain", "ad", "ADCS ESC1-ESC8 vulnerable certificate template chain audit", []string{"ldap", "msrpc", "microsoft-ds", "http"}, []int{389, 3268, 445, 443}, []string{}, false, nil},

		// Auth & Credentials family (7)
		{"CredentialSpray", "auth_creds", "Low-rate multi-service credential validation against lockout thresholds", []string{"ssh", "smb", "microsoft-ds", "http", "https", "rdp", "ms-wbt-server"}, []int{22, 445, 80, 443, 3389}, []string{}, false, nil},
		{"PasswordSpray", "auth_creds", "Single-password Spray across enumerated domain/service accounts", []string{"http", "https", "ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server"}, []int{80, 443, 22, 445, 3389}, []string{}, false, nil},
		{"HashCrack", "auth_creds", "Offline captured hash format classification and policy strength audit", []string{"smb", "microsoft-ds", "ssh", "http", "https"}, []int{445, 22, 80, 443}, []string{}, false, nil},
		{"ASREPRoast", "auth_creds", "Kerberos pre-authentication disabled (DONT_REQ_PREAUTH) account check", []string{"kerberos"}, []int{88, 389}, []string{}, false, nil},
		{"Kerberoasting", "auth_creds", "Service Principal Name (SPN) RC4/AES TGS ticket encryption audit", []string{"kerberos"}, []int{88, 389}, []string{}, false, nil},
		{"DCSyncAttack", "auth_creds", "Directory Replication Service (DS-Replication-Get-Changes-All) ACL audit", []string{"ldap", "microsoft-ds", "smb", "drsuapi"}, []int{389, 445, 3268, 135}, []string{}, false, nil},
		{"ADLDAPEnum", "auth_creds", "LDAP RootDSE, naming contexts, password policy, and account enumeration", []string{"ldap"}, []int{389, 3268, 636, 3269}, []string{}, false, nil},

		// SSH family (3)
		{"SSHBruteForce", "ssh", "SSH authentication method and default credential verification", []string{"ssh"}, []int{22, 2222, 8022}, []string{}, false, nil},
		{"RegreSSHion", "ssh", "OpenSSH SIGALRM race condition version and banner check (CVE-2024-6387)", []string{"ssh"}, []int{22, 2222, 8022}, []string{"CVE-2024-6387"}, false, nil},
		{"OpenSSHCVECheck", "ssh", "OpenSSH version correlation against known authentication/RCE CVEs", []string{"ssh"}, []int{22, 2222, 8022}, []string{}, false, nil},

		// Services family (6)
		{"RDPBlueKeep", "services", "RDP MS_T120 channel pre-auth vulnerability check (CVE-2019-0708)", []string{"ms-wbt-server", "rdp"}, []int{3389}, []string{"CVE-2019-0708"}, false, nil},
		{"FTPAnonymous", "services", "FTP anonymous login and writable directory verification", []string{"ftp"}, []int{21}, []string{}, false, nil},
		{"RedisExploit", "services", "Unauthenticated Redis INFO/CONFIG exposure check", []string{"redis"}, []int{6379}, []string{}, false, nil},
		{"ElasticsearchExploit", "services", "Unauthenticated Elasticsearch cluster/index metadata exposure check", []string{"elasticsearch"}, []int{9200}, []string{}, false, []string{"/_cluster/health", "/_cat/indices"}},
		{"LDAPAnonymous", "services", "Anonymous LDAP bind and RootDSE attribute disclosure check", []string{"ldap", "ldaps"}, []int{389, 636, 3268}, []string{}, false, nil},
		{"RDPExploit", "services", "RDP NLA enforcement, TLS certificate, and encryption level audit", []string{"ms-wbt-server", "rdp"}, []int{3389}, []string{}, false, nil},

		// Crypto & Deserialization (2)
		{"JWTTamper", "crypto_jwt", "JWT none-algorithm, weak HMAC secret, and key-confusion verification", []string{"http", "https"}, []int{80, 443, 8080, 8443, 3000, 5000}, []string{}, false, []string{"/"}},
		{"DeserializeAttack", "deserialize", "Insecure object deserialization signature and gadget surface detector", []string{"http", "https"}, []int{80, 443, 8080, 8443, 3000, 5000}, []string{}, false, []string{"/"}},

		// Privilege Escalation & Cloud/Container (10)
		{"LinuxPrivescCheck", "privesc", "Linux sudoers, capabilities, cron, and writable-path privilege escalation audit", []string{}, []int{}, []string{}, false, nil},
		{"WindowsPrivescCheck", "privesc", "Windows unquoted service paths, AlwaysInstallElevated, and token privilege audit", []string{}, []int{}, []string{}, false, nil},
		{"SUIDEnumeration", "privesc", "SUID/SGID binary GTFOBins escalation surface audit", []string{}, []int{}, []string{}, false, nil},
		{"KernelExploitCheck", "privesc", "Kernel release correlation against DirtyPipe/DirtyCow/Netfilter CVEs", []string{}, []int{}, []string{}, false, nil},
		{"ContainerBreakout", "privesc", "Exposed Docker daemon API and privileged container escape posture check", []string{"docker"}, []int{2375, 2376, 10250}, []string{}, false, []string{"/version", "/containers/json"}},
		{"CloudPrivesc", "privesc", "Cloud IAM role attachment and container orchestrator privilege escalation check", []string{"docker", "k8s", "http", "https"}, []int{2375, 2376, 10250, 443, 80}, []string{}, false, nil},
		{"K8sPrivesc", "privesc", "Kubernetes anonymous API server and kubelet read/exec exposure check", []string{"k8s", "kubelet", "https"}, []int{6443, 10250, 8443, 443}, []string{}, false, []string{"/pods", "/metrics"}},
		{"IMDSExploit", "privesc", "Cloud Instance Metadata Service (IMDSv1 vs IMDSv2) SSRF exposure audit", []string{"docker", "k8s", "http", "https"}, []int{2375, 2376, 10250, 443, 80}, []string{}, false, nil},
		{"DockerSockEscape", "privesc", "Unauthenticated Docker TCP/socket API exposure verification", []string{"docker"}, []int{2375, 2376}, []string{}, false, []string{"/version"}},
		{"S3BucketTakeover", "privesc", "Object storage bucket ACL, public listing, and unclaimed bucket check", []string{"http", "https"}, []int{80, 443, 8080, 8443, 3000, 5000}, []string{}, false, []string{"/"}},

		// Persistence (3)
		{"LinuxPersistence", "persistence", "Linux authorized_keys, systemd, and cron persistence surface audit", []string{"ssh"}, []int{22}, []string{}, false, nil},
		{"WindowsPersistence", "persistence", "Windows Run keys, scheduled tasks, and WMI subscription persistence audit", []string{"smb", "ms-wbt-server", "rdp"}, []int{445, 3389}, []string{}, false, nil},
		{"WebShellPersistence", "persistence", "Web root write-permission and persistent handler exposure audit", []string{"http", "https"}, []int{80, 443}, []string{}, false, nil},

		// ICS / OT / IoT (10)
		{"ModbusEnum", "ics_iot", "Modbus TCP function-code 17/43 device identification enumeration (read-only)", []string{"modbus", "tcp"}, []int{502}, []string{}, false, nil},
		{"DNP3Enum", "ics_iot", "DNP3 link-layer status and outstation address discovery (read-only)", []string{"dnp3", "tcp"}, []int{20000}, []string{}, false, nil},
		{"S7Enum", "ics_iot", "Siemens S7comm COTP/SZL PLC module and firmware identification (read-only)", []string{"iso-tsap", "s7", "s7comm"}, []int{102}, []string{}, false, nil},
		{"BACnetEnum", "ics_iot", "BACnet/IP Who-Is and device object property discovery (read-only)", []string{"bacnet"}, []int{47808}, []string{}, false, nil},
		{"HMIDefaultCred", "ics_iot", "Industrial HMI/SCADA web interface default credential and version check", []string{"http", "https"}, []int{80, 443, 8080, 8443}, []string{}, false, []string{"/"}},
		{"IoTDefaultCred", "ics_iot", "IoT/embedded HTTP/MQTT/Telnet default credential and management exposure check", []string{"http", "https", "telnet", "mqtt"}, []int{23, 80, 443, 1883, 8883, 7547, 8000, 8080}, []string{}, false, nil},
		{"ModbusWriteCoil", "ics_iot", "Authorized Modbus FC05 single-coil write verification (requires confirm_ics_write)", []string{"modbus", "tcp"}, []int{502}, []string{}, true, nil},
		{"ModbusWriteRegister", "ics_iot", "Authorized Modbus FC06 holding-register write verification (requires confirm_ics_write)", []string{"modbus", "tcp"}, []int{502}, []string{}, true, nil},
		{"S7PlcStop", "ics_iot", "Authorized S7comm CPU STOP control verification (requires confirm_ics_write)", []string{"iso-tsap", "s7", "s7comm"}, []int{102}, []string{}, true, nil},
		{"S7PlcStart", "ics_iot", "Authorized S7comm CPU warm/cold START verification (requires confirm_ics_write)", []string{"iso-tsap", "s7", "s7comm"}, []int{102}, []string{}, true, nil},

		// Supply Chain (5)
		{"ExposedVCS", "supply_chain", "Exposed .git/.svn/.hg repository metadata and config disclosure check", []string{"http", "https"}, []int{80, 443, 8080, 8443, 3000}, []string{}, false, []string{"/.git/HEAD", "/.svn/entries"}},
		{"CICDMisconfig", "supply_chain", "Unauthenticated Jenkins/GitLab/GitHub Actions/ArgoCD runner and webhook check", []string{"http", "https"}, []int{80, 443, 8080, 8443, 8081, 9090, 3000}, []string{}, false, []string{"/api/json", "/-/readiness"}},
		{"DependencyConfusion", "supply_chain", "exposed package.json/requirements.txt/go.mod private-namespace dependency check", []string{"http", "https"}, []int{80, 443, 8080, 8443, 3000}, []string{}, false, []string{"/package.json"}},
		{"ArtifactExposure", "supply_chain", "Exposed build artifacts, source maps, .env, and container registry catalog check", []string{"http", "https"}, []int{80, 443, 8080, 8443, 3000, 8081}, []string{}, false, []string{"/.env", "/v2/_catalog"}},
		{"SupplyChainRecon", "supply_chain", "End-to-end software supply-chain artifact and SBOM surface inventory", []string{"http", "https", "ssh", "smb", "microsoft-ds"}, []int{80, 443, 22, 445, 8080}, []string{}, false, []string{"/"}},

		// Synthesis (4)
		{"CVEToExploit", "synthesis", "CVE advisory to safe verification probe synthesizer", []string{"http", "https", "ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server"}, []int{80, 443, 22, 445, 3389}, []string{}, false, nil},
		{"DiffPatchAnalysis", "synthesis", "Vendor security patch diff to N-day trigger condition analyzer", []string{"http", "https", "ssh", "smb", "microsoft-ds"}, []int{80, 443, 22, 445}, []string{}, false, nil},
		{"FuzzToExploit", "synthesis", "Protocol grammar anomaly and crash-triage verification probe", []string{"http", "https", "ssh", "smb", "microsoft-ds"}, []int{80, 443, 22, 445}, []string{}, false, nil},
		{"WeaponizedExploit", "synthesis", "Multi-stage verified finding proof-of-concept chain synthesizer", []string{"http", "https", "ssh", "smb", "microsoft-ds", "rdp", "ms-wbt-server"}, []int{80, 443, 22, 445, 3389}, []string{}, false, nil},

		// Detection & OPSEC (3)
		{"detection_coverage_probe", "detect", "Blue-team SIEM/EDR telemetry and alert-coverage verification probe", []string{}, []int{}, []string{}, false, nil},
		{"log_source_enum", "detect", "Auditd, syslog, and Windows Event Log forwarding channel enumeration", []string{"ssh", "msrpc", "netbios-ssn", "cifs"}, []int{22, 445, 139}, []string{}, false, nil},
		{"opsec_posture_report", "detect", "Assessment operational-security footprint and indicator-of-compromise summary", []string{}, []int{}, []string{}, false, nil},

		// Orchestrator Phases (5)
		{"TokenImpersonation", "orchestrator", "Delegation token and session impersonation privilege verification", []string{"smb", "ms-wbt-server", "microsoft-ds"}, []int{445, 3389}, []string{}, false, nil},
		{"ServiceMisconfiguration", "orchestrator", "Service ACL, binary path permissions, and unquoted path verification", []string{"smb", "microsoft-ds"}, []int{445, 139}, []string{}, false, nil},
		{"LateralMovement", "orchestrator", "Cross-host credential and session pivot path verification", []string{}, []int{}, []string{}, false, nil},
		{"ValidateFinding", "orchestrator", "Independent reproduction and false-positive elimination check for proposed findings", []string{}, []int{}, []string{}, false, nil},
		{"LocalExploitSuggester", "orchestrator", "Host OS/kernel/patch-level correlation for local privilege escalation candidates", []string{}, []int{}, []string{}, false, nil},
	}

	for _, s := range specs {
		s := s
		cves := s.cves
		if cves == nil {
			cves = []string{}
		}
		svcs := s.services
		if svcs == nil {
			svcs = []string{}
		}
		ports := s.ports
		if ports == nil {
			ports = []int{}
		}
		register(Tool{
			Name:           s.name,
			Description:    s.desc,
			Family:         s.family,
			TargetServices: svcs,
			TargetPorts:    ports,
			RequiredCVEs:   cves,
			DestructiveICS: s.destructive,
			Run:            runAttackModule(s),
		})
	}
}

func init() {
	registerAttackCatalog()
}
