// Package device checks the developer's own computer. It only reads local
// files and the environment it is handed, never connects anywhere and never
// puts a value it read into its results.
package device

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

// Source is the Finding.Source of everything this package reports.
const Source = "device"

// EnvLocation is the Location of a finding read from the environment.
const EnvLocation = "env"

// maxFileSize bounds how much of one file is read. These files are small;
// a larger one is reported as not verified rather than read in part.
const maxFileSize = 16 << 20

// goos is runtime.GOOS; tests change it to check the Windows places.
var goos = runtime.GOOS

// Tool names of the places looked at.
const (
	ToolKube   = "kubeconfig"
	ToolDocker = "docker"
	ToolAWS    = "aws"
	ToolGh     = "gh"
)

// Place is one file the token check reads.
type Place struct {
	Tool string
	Path string
}

// Places lists the files CheckTokens reads, in the order it reads them. env
// supplies the variables that move them (KUBECONFIG, DOCKER_CONFIG,
// AWS_SHARED_CREDENTIALS_FILE, AWS_CONFIG_FILE, GH_CONFIG_DIR,
// XDG_CONFIG_HOME, APPDATA on Windows).
func Places(home string, env func(string) string) []Place {
	var out []Place
	seen := map[string]bool{}
	add := func(p Place) {
		if p.Path == "" {
			return
		}
		p.Path = filepath.Clean(p.Path)
		if seen[p.Path] {
			return
		}
		seen[p.Path] = true
		out = append(out, p)
	}

	if kc := env("KUBECONFIG"); kc != "" {
		for _, p := range filepath.SplitList(kc) {
			if p != "" {
				add(Place{Tool: ToolKube, Path: p})
			}
		}
	} else {
		add(Place{Tool: ToolKube, Path: filepath.Join(home, ".kube", "config")})
	}

	dockerDir := env("DOCKER_CONFIG")
	if dockerDir == "" {
		dockerDir = filepath.Join(home, ".docker")
	}
	add(Place{Tool: ToolDocker, Path: filepath.Join(dockerDir, "config.json")})

	creds := env("AWS_SHARED_CREDENTIALS_FILE")
	if creds == "" {
		creds = filepath.Join(home, ".aws", "credentials")
	}
	add(Place{Tool: ToolAWS, Path: creds})
	cfg := env("AWS_CONFIG_FILE")
	if cfg == "" {
		cfg = filepath.Join(home, ".aws", "config")
	}
	add(Place{Tool: ToolAWS, Path: cfg})

	switch {
	case env("GH_CONFIG_DIR") != "":
		add(Place{Tool: ToolGh, Path: filepath.Join(env("GH_CONFIG_DIR"), "hosts.yml")})
	default:
		if x := env("XDG_CONFIG_HOME"); x != "" {
			add(Place{Tool: ToolGh, Path: filepath.Join(x, "gh", "hosts.yml")})
		} else {
			add(Place{Tool: ToolGh, Path: filepath.Join(home, ".config", "gh", "hosts.yml")})
		}
		if goos == "windows" && env("APPDATA") != "" {
			add(Place{Tool: ToolGh, Path: filepath.Join(env("APPDATA"), "GitHub CLI", "hosts.yml")})
		}
	}
	return out
}

// Display shows path as the reports do: under home it starts with "~/", so the
// user name does not appear, and the separator is always '/'.
func Display(home, path string) string {
	if home != "" {
		if rel, err := filepath.Rel(home, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			if rel == "." {
				return "~"
			}
			return "~/" + filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(path)
}

// hit is one stored credential: where it is, never what it is.
type hit struct {
	id      string
	keyPath string
}

// CheckTokens looks for deployment credentials stored in plain form on this
// computer. It returns one finding per stored value, and one line per file
// that is there but could not be read or understood (not verified). A missing
// file is neither. No value, part, length or hash of a value is in either.
func CheckTokens(home string, env func(string) string) ([]finding.Finding, []string) {
	var findings []finding.Finding
	var unread []string
	for _, p := range Places(home, env) {
		shown := Display(home, p.Path)
		b, err := readFile(p.Path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			unread = append(unread, shown+": "+err.Error())
			continue
		}
		var hits []hit
		switch p.Tool {
		case ToolKube:
			hits, err = kubeHits(b)
		case ToolDocker:
			hits, err = dockerHits(b)
		case ToolAWS:
			hits = awsHits(b)
		case ToolGh:
			hits, err = ghHits(b)
		}
		if err != nil {
			unread = append(unread, shown+": "+err.Error())
			continue
		}
		for _, h := range hits {
			findings = append(findings, newFinding(h, shown))
		}
	}
	if isLongTermKey(env("AWS_ACCESS_KEY_ID")) {
		findings = append(findings, newFinding(hit{id: "DV-003", keyPath: "env AWS_ACCESS_KEY_ID"}, EnvLocation))
	}
	return findings, unread
}

// readFile reads one file. Its errors are fixed Korean sentences: an error
// from the OS or a parser may quote the path or the file and is not passed on.
func readFile(path string) ([]byte, error) {
	// Checked before opening: opening a FIFO with no writer waits forever.
	st, err := os.Stat(path)
	if err != nil {
		return nil, openError(err)
	}
	if st.IsDir() {
		return nil, errors.New("파일이 아니라 폴더입니다")
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("일반 파일이 아니어서 읽지 않았습니다")
	}
	f, err := openRead(path)
	if err != nil {
		return nil, openError(err)
	}
	defer f.Close()
	if st, err = f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("일반 파일이 아니어서 읽지 않았습니다")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, errors.New("읽을 권한이 없습니다")
		}
		return nil, errors.New("파일을 읽지 못했습니다")
	}
	if len(b) > maxFileSize {
		return nil, fmt.Errorf("파일이 %dMiB보다 커서 읽지 않았습니다", maxFileSize>>20)
	}
	return b, nil
}

// openError words an error from Stat or Open without passing on its text.
func openError(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fs.ErrNotExist
	case errors.Is(err, fs.ErrPermission):
		return errors.New("읽을 권한이 없습니다")
	}
	return errors.New("파일을 열지 못했습니다")
}

var errFormat = errors.New("형식을 읽지 못했습니다")

// present reports whether a decoded value holds anything.
func present(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(x) != ""
	case map[string]any:
		return len(x) > 0
	case []any:
		return len(x) > 0
	}
	return true
}

// kubeFields are the user fields that hold a credential or point to a key
// file. tokenFile, exec and auth-provider are not among them.
var kubeFields = []string{"token", "client-key-data", "client-key", "password"}

func kubeHits(b []byte) ([]hit, error) {
	var cfg struct {
		Users []struct {
			Name string         `yaml:"name"`
			User map[string]any `yaml:"user"`
		} `yaml:"users"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, errFormat
	}
	// A user is named by its name, so that adding or removing another user
	// does not move it; by its place only when the name is empty or used twice.
	names := map[string]int{}
	for _, u := range cfg.Users {
		names[u.Name]++
	}
	var out []hit
	for i, u := range cfg.Users {
		where := fmt.Sprintf("users[%d]", i)
		if u.Name != "" && names[u.Name] == 1 {
			where = "users[" + strconv.Quote(u.Name) + "]"
		}
		for _, k := range kubeFields {
			if present(u.User[k]) {
				out = append(out, hit{id: "DV-001", keyPath: where + ".user." + k})
			}
		}
	}
	return out, nil
}

func dockerHits(b []byte) ([]hit, error) {
	// credsStore and credHelpers are not consulted: a value written in the
	// file stays on disk whatever store is configured. An entry the store
	// keeps is empty here and so not reported.
	var cfg struct {
		Auths map[string]struct {
			Auth          string `json:"auth"`
			IdentityToken string `json:"identitytoken"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, errFormat
	}
	regs := make([]string, 0, len(cfg.Auths))
	for r := range cfg.Auths {
		regs = append(regs, r)
	}
	sort.Strings(regs)
	var out []hit
	for _, r := range regs {
		a := cfg.Auths[r]
		if strings.TrimSpace(a.Auth) != "" {
			out = append(out, hit{id: "DV-002", keyPath: "auths[" + strconv.Quote(r) + "].auth"})
		}
		if strings.TrimSpace(a.IdentityToken) != "" {
			out = append(out, hit{id: "DV-002", keyPath: "auths[" + strconv.Quote(r) + "].identitytoken"})
		}
	}
	return out, nil
}

// isLongTermKey reports whether an AWS access key ID is a long-term (AKIA)
// key. Temporary keys (ASIA) are not reported.
func isLongTermKey(id string) bool {
	return strings.HasPrefix(strings.TrimSpace(id), "AKIA")
}

// awsHits reads an AWS credentials or config file (INI). It is lenient: a line
// it does not understand is skipped, as the AWS CLI does.
func awsHits(b []byte) []hit {
	var out []hit
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && strings.HasSuffix(line, "]") {
			section = strings.Join(strings.Fields(line[1:len(line)-1]), " ")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "aws_access_key_id") {
			continue
		}
		if isLongTermKey(v) {
			out = append(out, hit{id: "DV-003", keyPath: "[" + section + "] aws_access_key_id"})
		}
	}
	return out
}

func ghHits(b []byte) ([]hit, error) {
	var hosts map[string]map[string]any
	if err := yaml.Unmarshal(b, &hosts); err != nil {
		return nil, errFormat
	}
	names := make([]string, 0, len(hosts))
	for h := range hosts {
		names = append(names, h)
	}
	sort.Strings(names)
	var out []hit
	for _, h := range names {
		host := hosts[h]
		base := "hosts[" + strconv.Quote(h) + "]"
		if present(host["oauth_token"]) {
			out = append(out, hit{id: "DV-004", keyPath: base + ".oauth_token"})
		}
		users, _ := host["users"].(map[string]any)
		// User names are listed by position only: they are personal.
		unames := make([]string, 0, len(users))
		for u := range users {
			unames = append(unames, u)
		}
		sort.Strings(unames)
		for i, u := range unames {
			if m, ok := users[u].(map[string]any); ok && present(m["oauth_token"]) {
				out = append(out, hit{id: "DV-004", keyPath: fmt.Sprintf("%s.users[%d].oauth_token", base, i)})
			}
		}
	}
	return out, nil
}

var titles = map[string]string{
	"DV-001": "kubeconfig에 고정 토큰이나 클라이언트 키가 저장되어 있음",
	"DV-002": "Docker 설정 파일에 레지스트리 인증 값이 저장되어 있음",
	"DV-003": "AWS 장기 액세스 키(AKIA 형식)가 저장되어 있음",
	"DV-004": "gh 설정 파일에 GitHub 토큰이 평문으로 저장되어 있음",
	"DV-101": "개발 도구의 실행 파일이 기준값과 다름",
	"DV-102": "Homebrew 실행 파일 링크가 Homebrew 밖을 가리킴",
	"DV-103": "자동 실행 지점이 기준값과 다름",
}

var severities = map[string]finding.Severity{
	"DV-001": finding.High,
	"DV-002": finding.Medium,
	"DV-003": finding.High,
	"DV-004": finding.High,
}

// akiaNote ends the evidence of DV-003: why the key was judged long-term.
const akiaNote = " (AKIA 형식, 장기 키)"

// TokenPrefix starts the baseline key of a stored credential.
const TokenPrefix = "token:"

// isTokenID: the finding is one of the stored-credential checks.
func isTokenID(id string) bool { _, ok := severities[id]; return ok }

// TokenKey is the baseline key of a stored-credential finding: its number,
// the file and the place in it. Never the value or any part, length or hash
// of it. "" for any other finding.
func TokenKey(f finding.Finding) string {
	if f.Source != Source || !isTokenID(f.ID) {
		return ""
	}
	k := strings.TrimSuffix(f.Evidence, akiaNote)
	if f.Location == EnvLocation {
		return TokenPrefix + f.ID + " " + k
	}
	return TokenPrefix + f.ID + " " + f.Location + " " + k
}

// TokenEntries are the baseline entries of the stored credentials found:
// where each one is, so a later check can tell a new one from one that was
// already there.
func TokenEntries(fs []finding.Finding) map[string]watch.Observation {
	out := map[string]watch.Observation{}
	for _, f := range fs {
		if k := TokenKey(f); k != "" {
			out[k] = watch.Observation{"id": f.ID, "file": f.Location, "key": strings.TrimSuffix(f.Evidence, akiaNote)}
		}
	}
	return out
}

func newFinding(h hit, location string) finding.Finding {
	evidence := h.keyPath
	title := titles[h.id]
	if h.id == "DV-003" {
		evidence += akiaNote
		if location == EnvLocation {
			title = "환경 변수에 AWS 장기 액세스 키(AKIA 형식)가 있음"
		}
	}
	return finding.Finding{
		ID:          h.id,
		Kind:        h.id,
		Source:      Source,
		Severity:    severities[h.id],
		Confidence:  finding.Certain,
		Location:    location,
		Evidence:    evidence,
		Title:       title,
		ExplainKo:   readText("explain/" + h.id + ".md"),
		Fix:         readText("fixes/" + h.id + "/device.md"),
		Fingerprint: finding.MakeFingerprint(h.id, location, h.keyPath),
	}
}

func readText(name string) string {
	b, err := fs.ReadFile(aidefensekit.Data, name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
