package modules_test

// Slice 21 RED: all 86 AttackModule classes (+ 5 network primitives = 91 tools)
// registered in internal/modules with metadata, applicability ranking,
// allowlist gating, and destructive-ICS confirmation gates.

import (
	"context"
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/modules"
)

var allExpectedAttackModules = []string{
	"Log4jRCE", "SMBGhost", "EternalBlue", "BasicAuthBuster", "APIFuzzer",
	"RDPBlueKeep", "SSHBruteForce", "RegreSSHion", "OpenSSHCVECheck", "SMBRelay",
	"SMBNullSession", "WebShellUpload", "SQLInjection", "XSSScanner", "CredentialSpray",
	"LinuxPrivescCheck", "WindowsPrivescCheck", "SUIDEnumeration", "KernelExploitCheck", "ContainerBreakout",
	"LinuxPersistence", "WindowsPersistence", "WebShellPersistence", "FTPAnonymous", "RedisExploit",
	"ElasticsearchExploit", "LDAPAnonymous", "RDPExploit", "JWTTamper", "SSTIProbe",
	"DeserializeAttack", "GraphQLIntrospect", "RaceRequest", "TimingOracle", "RequestSmuggling",
	"PasswordSpray", "HashCrack", "PassTheHash", "DumpHashes", "CVEToExploit",
	"DiffPatchAnalysis", "FuzzToExploit", "SSRFProbe", "XXEProbe", "LFITraversal",
	"ASREPRoast", "Kerberoasting", "DCSyncAttack", "ADLDAPEnum", "WeaponizedExploit",
	"CloudPrivesc", "K8sPrivesc", "IMDSExploit", "DockerSockEscape", "S3BucketTakeover",
	"ModbusEnum", "DNP3Enum", "S7Enum", "BACnetEnum", "HMIDefaultCred",
	"IoTDefaultCred", "ModbusWriteCoil", "ModbusWriteRegister", "S7PlcStop", "S7PlcStart",
	"ExposedVCS", "CICDMisconfig", "DependencyConfusion", "ArtifactExposure", "SupplyChainRecon",
	"detection_coverage_probe", "log_source_enum", "opsec_posture_report",
	"TokenImpersonation", "ServiceMisconfiguration", "LateralMovement", "ValidateFinding", "LocalExploitSuggester",
	"ADCSEnum", "BloodHoundCollect", "ResponderRelay", "GoldenTicket", "SMBSigningCheck",
	"RBCDAttack", "ShadowCredentials", "ESCChain",
}

func TestAll86AttackModulesRegisteredAndExecutable(t *testing.T) {
	for _, name := range allExpectedAttackModules {
		tool, ok := modules.Registry[name]
		if !ok {
			t.Fatalf("missing attack module %q in modules.Registry", name)
		}
		if tool.Description == "" || tool.Family == "" {
			t.Fatalf("module %q missing description or family: %+v", name, tool)
		}
	}
	if len(modules.List()) < 91 {
		t.Fatalf("expected >= 91 total registered modules (5 network + 86 attack), got %d", len(modules.List()))
	}

	// Destructive ICS modules must have DestructiveICS=true and refuse execution without confirm_ics_write=true
	for _, icsMod := range []string{"ModbusWriteCoil", "ModbusWriteRegister", "S7PlcStop", "S7PlcStart"} {
		tool := modules.Registry[icsMod]
		if !tool.DestructiveICS {
			t.Fatalf("module %s must mark DestructiveICS=true", icsMod)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := tool.Run(ctx, map[string]any{"target": "127.0.0.1"}, modules.Env{Entries: []string{"127.0.0.1"}, Timeout: time.Second})
		cancel()
		if err == nil {
			t.Fatalf("destructive ICS module %s must refuse without confirm_ics_write=true", icsMod)
		}
	}

	// Out-of-scope target must be denied by attack modules
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := modules.Registry["SQLInjection"].Run(ctx, map[string]any{"target": "192.0.2.99"}, modules.Env{Entries: []string{"127.0.0.1"}, Timeout: time.Second}); err == nil {
		t.Fatal("out-of-scope target must be rejected")
	}

	// In-scope execution succeeds with structured output
	res, err := modules.Registry["SQLInjection"].Run(ctx, map[string]any{"target": "127.0.0.1", "port": 80}, modules.Env{Entries: []string{"127.0.0.1"}, Timeout: time.Second})
	if err != nil {
		t.Fatalf("in-scope SQLInjection run failed: %v", err)
	}
	if res["module"] != "SQLInjection" || res["family"] != "web" {
		t.Fatalf("unexpected module output: %+v", res)
	}

	// Applicability ranking
	ranked := modules.FindApplicable([]int{80, 445}, []string{"http", "smb"}, []string{"CVE-2020-0796"})
	if len(ranked) == 0 {
		t.Fatal("expected applicable modules for ports 80, 445 and CVE-2020-0796")
	}
	if ranked[0].Name != "SMBGhost" {
		t.Fatalf("expected CVE-matching SMBGhost ranked first, got %s (score=%d)", ranked[0].Name, ranked[0].Score)
	}
}
