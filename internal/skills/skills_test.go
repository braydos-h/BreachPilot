package skills_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/skills"
)

const sampleSkill = `---
name: port-scan-basics
description: Baseline TCP port scanning playbook.
tags: [recon, port-scan, tcp]
domain: cybersecurity
nist_csf: [PR.IR-01, DE.CM-01]
---
# Port scan basics

## When to Use
Scan first.

## Workflow
Scan, then report.
`

func writeSkill(t *testing.T, root, name, md string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, name, "SKILL.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverListSearchGet(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "port-scan-basics", sampleSkill)
	st := skills.NewStore([]string{root, filepath.Join(root, "missing")})
	all, err := st.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("list: %v %v", all, err)
	}
	if all[0].Tags[0] != "recon" || all[0].Body != "" {
		t.Fatalf("list must omit body: %+v", all[0])
	}
	res, _ := st.Search("tcp")
	if len(res) != 1 {
		t.Fatalf("search tcp: %v", res)
	}
	res, _ = st.Search("nope-nothing")
	if len(res) != 0 {
		t.Fatalf("search miss: %v", res)
	}
	got, err := st.Get("port-scan-basics")
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if got.Body == "" || len(got.Sections) != 2 || len(got.NistCsf) != 2 {
		t.Fatalf("detail: %+v", got)
	}
	if missing, _ := st.Get("nope"); missing != nil {
		t.Fatal("missing skill must return nil")
	}
}

func TestCreateDeleteRoundTrip(t *testing.T) {
	root := t.TempDir()
	st := skills.NewStore([]string{root})
	sk, err := st.Create("my-skill", sampleSkill)
	if err != nil {
		t.Fatal(err)
	}
	if sk.Name != "port-scan-basics" {
		t.Fatalf("created: %+v", sk)
	}
	if _, err := st.Create("my-skill", sampleSkill); err == nil {
		t.Fatal("duplicate create must fail")
	}
	if err := st.Delete("my-skill"); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete("my-skill"); err == nil {
		t.Fatal("second delete must fail")
	}
	if err := st.Delete("../escape"); err == nil {
		t.Fatal("traversal must fail")
	}
}

func TestNameValidation(t *testing.T) {
	if skills.ValidName("Bad Name!") || !skills.ValidName("ok-name-1") {
		t.Fatal("name regex wrong")
	}
}
