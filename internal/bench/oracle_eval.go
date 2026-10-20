package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// OracleExpected describes expected findings for an evaluation target.
type OracleExpected struct {
	OpenPorts         []int    `json:"open_ports"`
	Services          []string `json:"services"`
	Vulnerabilities   []string `json:"vulnerabilities"`
	KnownCVEs         []string `json:"known_cves"`
	RootShellPossible bool     `json:"root_shell_possible"`
}

// OracleCheck describes one flag verification check in an oracle file.
type OracleCheck struct {
	Type                   string `json:"type"`
	URL                    string `json:"url"`
	User                   string `json:"user,omitempty"`
	Password               string `json:"password,omitempty"`
	ExpectStatus           int    `json:"expect_status,omitempty"`
	ExpectLocationContains string `json:"expect_location_contains,omitempty"`
}

// OracleFlag is one graded flag in an oracle file.
type OracleFlag struct {
	ID          string      `json:"id"`
	Description string      `json:"description"`
	Check       OracleCheck `json:"check"`
}

// OracleTarget represents one `eval_targets/*.oracle.json` specification.
type OracleTarget struct {
	TargetID              string         `json:"target_id"`
	Host                  string         `json:"host"`
	Ports                 map[string]int `json:"ports"`
	NegativeControl       bool           `json:"negative_control"`
	VerificationSupported *bool          `json:"verification_supported,omitempty"`
	VerificationNote      string         `json:"verification_note,omitempty"`
	ExpectedFindings      OracleExpected `json:"expected_findings"`
	Flags                 []OracleFlag   `json:"flags"`
	HostOwnedWhen         string         `json:"host_owned_when"`
}

// OracleScoreResult summarizes graded evaluation against an OracleTarget.
type OracleScoreResult struct {
	TargetID              string  `json:"target_id"`
	TruePositives         int     `json:"true_positives"`
	FalsePositives        int     `json:"false_positives"`
	ExpectedTotal         int     `json:"expected_total"`
	Precision             float64 `json:"precision"`
	Recall                float64 `json:"recall"`
	NegativeControlPassed bool    `json:"negative_control_passed"`
	Success               bool    `json:"success"`
}

// OracleFlagResult reports live flag verification against a target.
type OracleFlagResult struct {
	TargetID    string            `json:"target_id"`
	FlagsTotal  int               `json:"flags_total"`
	FlagsPassed int               `json:"flags_passed"`
	Details     map[string]string `json:"details"`
}

// LoadOracles reads all `*.oracle.json` specifications in dir, sorted by filename.
func LoadOracles(dir string) ([]OracleTarget, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".oracle.json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []OracleTarget
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var o OracleTarget
		if json.Unmarshal(raw, &o) == nil {
			if o.TargetID == "" {
				o.TargetID = strings.TrimSuffix(name, ".oracle.json")
			}
			out = append(out, o)
		}
	}
	return out, nil
}

// ScoreAgainstOracle grades discovered ports, services, and findings against
// the oracle's expected_findings and negative_control rules.
func ScoreAgainstOracle(oracle OracleTarget, openPorts []int, services []string, findings []string) OracleScoreResult {
	res := OracleScoreResult{
		TargetID:      oracle.TargetID,
		ExpectedTotal: len(oracle.ExpectedFindings.Vulnerabilities) + len(oracle.ExpectedFindings.KnownCVEs),
	}
	if oracle.NegativeControl {
		res.FalsePositives = len(findings)
		res.NegativeControlPassed = len(findings) == 0
		res.Success = res.NegativeControlPassed
		if res.NegativeControlPassed {
			res.Precision = 1.0
			res.Recall = 1.0
		}
		return res
	}
	expected := map[string]bool{}
	for _, v := range oracle.ExpectedFindings.Vulnerabilities {
		expected[strings.ToLower(strings.TrimSpace(v))] = true
	}
	for _, c := range oracle.ExpectedFindings.KnownCVEs {
		expected[strings.ToLower(strings.TrimSpace(c))] = true
	}
	for _, f := range findings {
		fl := strings.ToLower(strings.TrimSpace(f))
		if fl == "" {
			continue
		}
		matched := expected[fl]
		if !matched {
			for exp := range expected {
				if strings.Contains(fl, exp) {
					matched = true
					break
				}
			}
		}
		if matched {
			res.TruePositives++
		} else {
			res.FalsePositives++
		}
	}
	if res.TruePositives+res.FalsePositives > 0 {
		res.Precision = float64(res.TruePositives) / float64(res.TruePositives+res.FalsePositives)
	}
	if res.ExpectedTotal > 0 {
		res.Recall = float64(res.TruePositives) / float64(res.ExpectedTotal)
	}
	res.NegativeControlPassed = true
	res.Success = res.TruePositives > 0 || (res.ExpectedTotal == 0 && len(openPorts) >= len(oracle.ExpectedFindings.OpenPorts))
	_ = services
	return res
}

// VerifyOracleFlags executes non-destructive HTTP flag verification checks defined in an oracle.
func VerifyOracleFlags(ctx context.Context, oracle OracleTarget) OracleFlagResult {
	res := OracleFlagResult{
		TargetID:   oracle.TargetID,
		FlagsTotal: len(oracle.Flags),
		Details:    map[string]string{},
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, fl := range oracle.Flags {
		chk := fl.Check
		switch chk.Type {
		case "http_request":
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, chk.URL, nil)
			if err != nil {
				res.Details[fl.ID] = fmt.Sprintf("invalid url: %v", err)
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				res.Details[fl.ID] = "target_unreachable"
				continue
			}
			_ = resp.Body.Close()
			want := chk.ExpectStatus
			if want == 0 {
				want = 200
			}
			if resp.StatusCode == want {
				res.FlagsPassed++
				res.Details[fl.ID] = "passed"
			} else {
				res.Details[fl.ID] = fmt.Sprintf("status=%d want=%d", resp.StatusCode, want)
			}
		case "http_login":
			form := url.Values{}
			form.Set("username", chk.User)
			form.Set("password", chk.Password)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, chk.URL, strings.NewReader(form.Encode()))
			if err != nil {
				res.Details[fl.ID] = fmt.Sprintf("invalid url: %v", err)
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := client.Do(req)
			if err != nil {
				res.Details[fl.ID] = "target_unreachable"
				continue
			}
			_ = resp.Body.Close()
			loc := resp.Header.Get("Location")
			if (chk.ExpectStatus == 0 || resp.StatusCode == chk.ExpectStatus) &&
				(chk.ExpectLocationContains == "" || strings.Contains(loc, chk.ExpectLocationContains)) {
				res.FlagsPassed++
				res.Details[fl.ID] = "passed"
			} else {
				res.Details[fl.ID] = fmt.Sprintf("status=%d loc=%q", resp.StatusCode, loc)
			}
		default:
			res.Details[fl.ID] = "unsupported_check_type"
		}
	}
	return res
}
