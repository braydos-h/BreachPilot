// Package skills provides real skill discovery over SKILL.md files.
// Mirrors tools/skill_registry.py metadata + tools/api/routes/system/
// skills.py storage: filesystem-backed, SKILL.md front-matter, atomic
// writes, traversal-safe, plugin dirs read-only.
package skills

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Skill is the API-facing metadata. Body holds the full markdown for the
// detail route; List responses omit it (caller controls serialization).
type Skill struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Body        string   `json:"body,omitempty"`
	Sections    []string `json:"sections,omitempty"`
	Tags        []string `json:"tags"`
	References  []string `json:"references,omitempty"`
	NistCsf     []string `json:"nist_csf,omitempty"`
	MitreAttack []string `json:"mitre_attack,omitempty"`
	Domain      string   `json:"domain,omitempty"`
	Subdomain   string   `json:"subdomain,omitempty"`
	Version     string   `json:"version,omitempty"`
	Dir         string   `json:"-"`
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)

// ValidName enforces the ^[a-z0-9][a-z0-9-]{1,63}$ rule.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// Store scans roots for <name>/SKILL.md files.
type Store struct {
	Roots []string
}

// NewStore builds a store; empty roots default to ["skills"].
func NewStore(roots []string) *Store {
	if len(roots) == 0 {
		roots = []string{"skills"}
	}
	return &Store{Roots: roots}
}

// List returns all skills sorted by name.
func (st *Store) List() ([]Skill, error) {
	var out []Skill
	for _, root := range st.Roots {
		entries, err := os.ReadDir(filepath.Clean(root))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			md := filepath.Join(root, e.Name(), "SKILL.md")
			raw, err := os.ReadFile(filepath.Clean(md))
			if err != nil {
				continue
			}
			sk, err := ParseSkillFile(e.Name(), raw, filepath.Join(root, e.Name()))
			if err != nil {
				continue
			}
			sk.Body = ""
			sk.Sections = nil
			out = append(out, sk)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if out == nil {
		out = []Skill{}
	}
	return out, nil
}

// Search matches q against name/description/tags, cap 20.
func (st *Store) Search(q string) ([]Skill, error) {
	all, err := st.List()
	if err != nil {
		return nil, err
	}
	q = strings.ToLower(q)
	var out []Skill
	for _, sk := range all {
		hay := strings.ToLower(sk.Name + " " + sk.Description + " " + strings.Join(sk.Tags, " "))
		if strings.Contains(hay, q) {
			out = append(out, sk)
			if len(out) >= 20 {
				break
			}
		}
	}
	if out == nil {
		out = []Skill{}
	}
	return out, nil
}

// Get returns the full skill including body and sections.
func (st *Store) Get(name string) (*Skill, error) {
	for _, root := range st.Roots {
		md := filepath.Join(root, name, "SKILL.md")
		raw, err := os.ReadFile(filepath.Clean(md))
		if err != nil {
			continue
		}
		sk, err := ParseSkillFile(name, raw, filepath.Join(root, name))
		if err != nil {
			return nil, err
		}
		refs, _ := filepath.Glob(filepath.Join(root, name, "references", "*.md"))
		for _, r := range refs {
			sk.References = append(sk.References, filepath.Base(r))
		}
		return &sk, nil
	}
	return nil, nil
}

// WritableRoot returns the first root that exists as a directory.
func (st *Store) WritableRoot() string {
	for _, root := range st.Roots {
		if fi, err := os.Stat(filepath.Clean(root)); err == nil && fi.IsDir() {
			return root
		}
	}
	return ""
}

// Create writes <root>/<name>/SKILL.md atomically after validation.
func (st *Store) Create(name, markdown string) (Skill, error) {
	if !ValidName(name) {
		return Skill{}, fmt.Errorf("invalid_skill: bad name %q", name)
	}
	root := st.WritableRoot()
	if root == "" {
		return Skill{}, fmt.Errorf("no writable skills root")
	}
	dir := filepath.Join(root, name)
	if fi, err := os.Stat(filepath.Clean(dir)); err == nil && fi.IsDir() {
		return Skill{}, fmt.Errorf("skill_exists: %q", name)
	}
	sk, err := ParseSkillFile(name, []byte(markdown), dir)
	if err != nil {
		return Skill{}, err
	}
	if sk.Name != name {
		return Skill{}, fmt.Errorf("invalid_skill: front-matter name %q != %q", sk.Name, name)
	}
	if err := os.MkdirAll(filepath.Clean(dir), 0o755); err != nil {
		return Skill{}, err
	}
	tmp, err := os.CreateTemp(filepath.Clean(dir), ".SKILL-*")
	if err != nil {
		return Skill{}, err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(markdown); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return Skill{}, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return Skill{}, err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, "SKILL.md")); err != nil {
		_ = os.Remove(tmpName)
		_ = os.Remove(dir)
		return Skill{}, err
	}
	sk.Body = ""
	sk.Sections = nil
	return sk, nil
}

// Delete removes a skill dir, refusing paths outside the writable root
// (traversal) and anything under a plugins tree (read-only contributors).
func (st *Store) Delete(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid_skill: bad name %q", name)
	}
	root := st.WritableRoot()
	if root == "" {
		return fmt.Errorf("no writable skills root")
	}
	absRoot, _ := filepath.Abs(filepath.Clean(root))
	target := filepath.Join(absRoot, name)
	absTarget, err := filepath.Abs(target)
	if err != nil || (absTarget != absRoot && !strings.HasPrefix(absTarget, absRoot+string(os.PathSeparator))) {
		return fmt.Errorf("invalid_skill: traversal")
	}
	if strings.Contains(absTarget, string(os.PathSeparator)+"plugins"+string(os.PathSeparator)) {
		return fmt.Errorf("skill_not_writable: plugin-owned")
	}
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("not_found")
	}
	return os.RemoveAll(target)
}

// ParseSkillFile parses front-matter + ## sections. Missing name falls back
// to the directory name, mirroring parse_skill_file.
func ParseSkillFile(dirName string, raw []byte, dir string) (Skill, error) {
	sk := Skill{Dir: dir}
	text := string(raw)
	front, body := splitFrontMatter(text)
	meta := parseSimpleYAML(front)
	if n, ok := meta["name"]; ok && n != "" {
		sk.Name = n
	} else {
		sk.Name = dirName
	}
	sk.Description = meta["description"]
	sk.Domain = meta["domain"]
	sk.Subdomain = meta["subdomain"]
	sk.Version = meta["version"]
	sk.Tags = parseInlineList(meta["tags"])
	sk.NistCsf = parseInlineList(meta["nist_csf"])
	sk.MitreAttack = parseInlineList(meta["mitre_attack"])
	sk.Body = strings.TrimSpace(body)
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "## ") {
			sk.Sections = append(sk.Sections, strings.TrimSpace(strings.TrimPrefix(line, "## ")))
		}
	}
	if sk.Sections == nil {
		sk.Sections = []string{}
	}
	if sk.Tags == nil {
		sk.Tags = []string{}
	}
	return sk, nil
}

func splitFrontMatter(text string) (front, body string) {
	if !strings.HasPrefix(text, "---") {
		return "", text
	}
	rest := text[3:]
	if i := strings.Index(rest, "\n---"); i >= 0 {
		after := rest[i+4:]
		if strings.HasPrefix(after, "\n") {
			after = after[1:]
		} else if strings.HasPrefix(after, "\r\n") {
			after = after[2:]
		}
		return rest[:i], after
	}
	return "", text
}

// parseSimpleYAML handles flat `key: value` lines (ignores indented/nested
// lines and comments). Values may be single/double quoted.
func parseSimpleYAML(front string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(front, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.TrimSpace(line[i+1:])
		v = strings.Trim(v, `"'`)
		if k != "" {
			out[k] = v
		}
	}
	return out
}

func parseInlineList(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return []string{}
	}
	if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		v = v[1 : len(v)-1]
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.Trim(strings.TrimSpace(p), `"'`)
		if p != "" {
			out = append(out, p)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}
