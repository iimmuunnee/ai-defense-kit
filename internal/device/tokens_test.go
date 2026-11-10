package device

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// Fake values are put together in memory so that no token- or key-shaped
// literal is ever written in this file.
func fakeLongKey() string { return "AK" + "IA" + strings.Repeat("Q7", 8) }
func fakeTempKey() string { return "AS" + "IA" + strings.Repeat("Q7", 8) }
func fakeValue(tag string) string {
	return tag + strings.Repeat("Zq9", 6)
}

// envOf returns an env func that knows only m.
func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeValues are every value TestTokensFound plants, so leak tests can look for them.
type fakeValues struct {
	kubeToken, kubeKeyData, kubePassword, dockerAuth, dockerIdentity, longKey, secretKey, configKey, ghToken, ghUserToken, envKey string
}

func newFakes() fakeValues {
	return fakeValues{
		kubeToken:      fakeValue("kubetok"),
		kubeKeyData:    base64.StdEncoding.EncodeToString([]byte(fakeValue("kubekey"))),
		kubePassword:   fakeValue("kubepw"),
		dockerAuth:     base64.StdEncoding.EncodeToString([]byte("user:" + fakeValue("dockpw"))),
		dockerIdentity: fakeValue("dockid"),
		longKey:        fakeLongKey(),
		secretKey:      fakeValue("awssec"),
		configKey:      "AK" + "IA" + strings.Repeat("W3", 8),
		ghToken:        fakeValue("ghtok"),
		ghUserToken:    fakeValue("ghusr"),
		envKey:         "AK" + "IA" + strings.Repeat("E5", 8),
	}
}

func (v fakeValues) all() []string {
	return []string{v.kubeToken, v.kubeKeyData, v.kubePassword, v.dockerAuth, v.dockerIdentity, v.longKey, v.secretKey, v.configKey, v.ghToken, v.ghUserToken, v.envKey}
}

// plantAll writes one stored token of every kind under home and returns the env
// that goes with it.
func plantAll(t *testing.T, home string, v fakeValues) func(string) string {
	t.Helper()
	write(t, filepath.Join(home, ".kube", "config"), `apiVersion: v1
kind: Config
users:
- name: a
  user:
    token: `+v.kubeToken+`
- name: b
  user:
    client-certificate-data: Y2VydA==
    client-key-data: `+v.kubeKeyData+`
- name: c
  user:
    client-key: /keys/c.key
- name: d
  user:
    username: admin
    password: `+v.kubePassword+`
`)
	write(t, filepath.Join(home, ".docker", "config.json"), `{"auths": {
  "registry.example.test": {"auth": "`+v.dockerAuth+`"},
  "other.example.test": {"identitytoken": "`+v.dockerIdentity+`"}
}}`)
	write(t, filepath.Join(home, ".aws", "credentials"), "[default]\naws_access_key_id = "+v.longKey+"\naws_secret_access_key = "+v.secretKey+"\n")
	write(t, filepath.Join(home, ".aws", "config"), "[profile dev]\nregion = ap-northeast-2\naws_access_key_id="+v.configKey+"\n")
	write(t, filepath.Join(home, ".config", "gh", "hosts.yml"), `github.com:
    oauth_token: `+v.ghToken+`
    user: someone
    users:
        someone:
            oauth_token: `+v.ghUserToken+`
`)
	return envOf(map[string]string{"AWS_ACCESS_KEY_ID": v.envKey})
}

func evidences(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID+" "+f.Location+" "+f.Evidence)
	}
	slices.Sort(out)
	return out
}

func TestTokensFound(t *testing.T) {
	home := t.TempDir()
	v := newFakes()
	env := plantAll(t, home, v)
	fs, unread := CheckTokens(home, env)
	if len(unread) != 0 {
		t.Fatalf("unreadable: %v", unread)
	}
	want := map[string][2]string{
		`users["a"].user.token`:                     {"DV-001", "~/.kube/config"},
		`users["b"].user.client-key-data`:           {"DV-001", "~/.kube/config"},
		`users["c"].user.client-key`:                {"DV-001", "~/.kube/config"},
		`users["d"].user.password`:                  {"DV-001", "~/.kube/config"},
		`auths["registry.example.test"].auth`:       {"DV-002", "~/.docker/config.json"},
		`auths["other.example.test"].identitytoken`: {"DV-002", "~/.docker/config.json"},
		"[default] aws_access_key_id":               {"DV-003", "~/.aws/credentials"},
		"[profile dev] aws_access_key_id":           {"DV-003", "~/.aws/config"},
		"env AWS_ACCESS_KEY_ID":                     {"DV-003", "env"},
		`hosts["github.com"].oauth_token`:           {"DV-004", "~/.config/gh/hosts.yml"},
		`hosts["github.com"].users[0].oauth_token`:  {"DV-004", "~/.config/gh/hosts.yml"},
	}
	sev := map[string]finding.Severity{"DV-001": finding.High, "DV-002": finding.Medium, "DV-003": finding.High, "DV-004": finding.High}
	got := map[string]bool{}
	for _, f := range fs {
		key := strings.TrimSuffix(f.Evidence, " (AKIA 형식, 장기 키)")
		w, ok := want[key]
		if !ok {
			t.Errorf("unexpected finding: %s %s %s", f.ID, f.Location, f.Evidence)
			continue
		}
		got[key] = true
		if f.ID != w[0] || f.Kind != w[0] || f.Location != w[1] {
			t.Errorf("%s: id=%s kind=%s loc=%s, want %s %s", key, f.ID, f.Kind, f.Location, w[0], w[1])
		}
		if f.Severity != sev[f.ID] || f.Source != Source || f.Confidence != finding.Certain {
			t.Errorf("%s: severity=%s source=%s confidence=%s", key, f.Severity, f.Source, f.Confidence)
		}
		if f.Title == "" || f.ExplainKo == "" || f.Fix == "" || f.Fingerprint == "" {
			t.Errorf("%s: title, explain, fix and fingerprint must be set: %+v", key, f)
		}
		if f.ID == "DV-003" && !strings.Contains(f.Evidence, "AKIA 형식") {
			t.Errorf("%s: DV-003 evidence should name the AKIA form: %q", key, f.Evidence)
		}
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing finding %s\ngot: %v", k, evidences(fs))
		}
	}
}

func TestNeverPrintsValue(t *testing.T) {
	home := t.TempDir()
	v := newFakes()
	fs, _ := CheckTokens(home, plantAll(t, home, v))
	if len(fs) == 0 {
		t.Fatal("no findings")
	}
	b, err := json.Marshal(fs)
	if err != nil {
		t.Fatal(err)
	}
	assertNoValue(t, string(b), v.all())
}

// assertNoValue fails if out holds any value or any 6-character piece of one.
func assertNoValue(t *testing.T, out string, values []string) {
	t.Helper()
	for _, val := range values {
		for i := 0; i+6 <= len(val); i++ {
			if piece := val[i : i+6]; strings.Contains(out, piece) {
				t.Errorf("output holds a piece %q of a planted value", piece)
				break
			}
		}
	}
}

func TestSafeForms(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".kube", "config"), `users:
- name: eks
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args: [eks, get-token]
- name: gke
  user:
    auth-provider:
      name: gcp
- name: file
  user:
    tokenFile: /var/run/secrets/token
- name: empty
  user:
    token: ""
`)
	// Entries a store or helper keeps are empty in the file.
	write(t, filepath.Join(home, ".docker", "config.json"), `{
  "auths": {"registry.example.test": {}, "helper.example.test": {"auth": ""}},
  "credsStore": "desktop",
  "credHelpers": {"helper.example.test": "ecr-login"}
}`)
	write(t, filepath.Join(home, ".aws", "credentials"), "[tmp]\naws_access_key_id = "+fakeTempKey()+"\naws_session_token = "+fakeValue("sess")+"\n")
	write(t, filepath.Join(home, ".aws", "config"), "[profile sso]\nsso_start_url = https://example.test/start\n")
	write(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "github.com:\n    user: someone\n    git_protocol: https\n")
	env := envOf(map[string]string{"AWS_ACCESS_KEY_ID": fakeTempKey(), "GH_TOKEN": fakeValue("ghenv"), "GITHUB_TOKEN": fakeValue("ghenv2")})
	fs, unread := CheckTokens(home, env)
	if len(fs) != 0 || len(unread) != 0 {
		t.Fatalf("safe forms reported: %v unreadable=%v", evidences(fs), unread)
	}

}

// An inline value stays on disk whatever store or helper is configured, so it
// is reported: a store does not remove what was written before it.
func TestDockerInlineValueBesideStore(t *testing.T) {
	inline := func(tag string) string {
		return base64.StdEncoding.EncodeToString([]byte("u:" + fakeValue(tag)))
	}
	cases := map[string]struct {
		body string
		want []string
	}{
		"credsStore": {
			body: `{"auths": {"registry.example.test": {"auth": "` + inline("cs") + `", "identitytoken": "` + fakeValue("csid") + `"}, "empty.example.test": {}}, "credsStore": "desktop"}`,
			want: []string{
				`DV-002 ~/.docker/config.json auths["registry.example.test"].auth`,
				`DV-002 ~/.docker/config.json auths["registry.example.test"].identitytoken`,
			},
		},
		"credHelpers": {
			body: `{"auths": {"helper.example.test": {"auth": "` + inline("hp") + `"}}, "credHelpers": {"helper.example.test": "ecr-login"}}`,
			want: []string{`DV-002 ~/.docker/config.json auths["helper.example.test"].auth`},
		},
	}
	for name, c := range cases {
		home := t.TempDir()
		write(t, filepath.Join(home, ".docker", "config.json"), c.body)
		fs, unread := CheckTokens(home, envOf(nil))
		if got := evidences(fs); len(unread) != 0 || !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v unreadable=%v, want %v", name, got, unread, c.want)
		}
	}
}

// A path that is a folder is there but cannot be read: not verified. This
// runs on every platform, unlike the chmod test.
func TestFolderIsUnreadable(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".kube", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	fs, unread := CheckTokens(home, envOf(nil))
	if len(fs) != 0 || len(unread) != 1 || !strings.Contains(unread[0], "~/.kube/config") || !strings.Contains(unread[0], "폴더") {
		t.Fatalf("findings=%v unreadable=%v", evidences(fs), unread)
	}
}

func TestUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 000 does not deny reading on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}
	home := t.TempDir()
	p := filepath.Join(home, ".kube", "config")
	write(t, p, "users: []\n")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	fs, unread := CheckTokens(home, envOf(nil))
	if len(fs) != 0 || len(unread) != 1 || !strings.Contains(unread[0], "~/.kube/config") {
		t.Fatalf("findings=%v unreadable=%v", evidences(fs), unread)
	}
}

// A file that is there but cannot be parsed is not verified, and the parser's
// message (which may quote the file) is not repeated.
func TestMalformedIsUnreadable(t *testing.T) {
	home := t.TempDir()
	secret := fakeValue("broken")
	write(t, filepath.Join(home, ".kube", "config"), "users: "+secret+"\n")
	write(t, filepath.Join(home, ".docker", "config.json"), `{"auths": "`+secret+`"`)
	write(t, filepath.Join(home, ".config", "gh", "hosts.yml"), "- "+secret+"\n")
	fs, unread := CheckTokens(home, envOf(nil))
	if len(fs) != 0 || len(unread) != 3 {
		t.Fatalf("findings=%v unreadable=%v", evidences(fs), unread)
	}
	assertNoValue(t, strings.Join(unread, "\n"), []string{secret})
}

func TestNothingThere(t *testing.T) {
	fs, unread := CheckTokens(t.TempDir(), envOf(nil))
	if len(fs) != 0 || len(unread) != 0 {
		t.Fatalf("findings=%v unreadable=%v", evidences(fs), unread)
	}
}

func TestEnvPaths(t *testing.T) {
	home := t.TempDir()
	other := t.TempDir()
	k1, k2 := filepath.Join(other, "k1.yaml"), filepath.Join(other, "k2.yaml")
	write(t, k1, "users:\n- user:\n    token: "+fakeValue("k1")+"\n")
	write(t, k2, "users:\n- user:\n    password: "+fakeValue("k2")+"\n")
	write(t, filepath.Join(other, "docker", "config.json"), `{"auths": {"r.example.test": {"identitytoken": "`+fakeValue("d")+`"}}}`)
	write(t, filepath.Join(other, "creds"), "[default]\naws_access_key_id = "+fakeLongKey()+"\n")
	write(t, filepath.Join(other, "awsconfig"), "[default]\naws_access_key_id = "+fakeLongKey()+"\n")
	write(t, filepath.Join(other, "gh", "hosts.yml"), "github.com:\n    oauth_token: "+fakeValue("g")+"\n")
	// The default places hold tokens too, and must be passed over.
	plantAll(t, home, newFakes())
	env := envOf(map[string]string{
		"KUBECONFIG":                  k1 + string(os.PathListSeparator) + string(os.PathListSeparator) + k2,
		"DOCKER_CONFIG":               filepath.Join(other, "docker"),
		"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(other, "creds"),
		"AWS_CONFIG_FILE":             filepath.Join(other, "awsconfig"),
		"GH_CONFIG_DIR":               filepath.Join(other, "gh"),
	})
	fs, unread := CheckTokens(home, env)
	if len(unread) != 0 {
		t.Fatalf("unreadable: %v", unread)
	}
	if len(fs) != 6 {
		t.Fatalf("want 6 findings from the env paths, got %v", evidences(fs))
	}
	for _, f := range fs {
		if strings.HasPrefix(f.Location, "~") {
			t.Errorf("default place read although env names another: %s", f.Location)
		}
	}
}

func TestGhXDGAndWindows(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	write(t, filepath.Join(xdg, "gh", "hosts.yml"), "github.com:\n    oauth_token: "+fakeValue("x")+"\n")
	fs, _ := CheckTokens(home, envOf(map[string]string{"XDG_CONFIG_HOME": xdg}))
	if len(fs) != 1 || fs[0].ID != "DV-004" {
		t.Fatalf("XDG_CONFIG_HOME: %v", evidences(fs))
	}

	old := goos
	t.Cleanup(func() { goos = old })
	goos = "windows"
	appData := filepath.Join(home, "AppData", "Roaming")
	write(t, filepath.Join(appData, "GitHub CLI", "hosts.yml"), "github.com:\n    oauth_token: "+fakeValue("w")+"\n")
	fs, _ = CheckTokens(home, envOf(map[string]string{"APPDATA": appData}))
	if len(fs) != 1 || fs[0].Location != "~/AppData/Roaming/GitHub CLI/hosts.yml" {
		t.Fatalf("APPDATA: %v", evidences(fs))
	}
	goos = "linux"
	if fs, _ = CheckTokens(home, envOf(map[string]string{"APPDATA": appData})); len(fs) != 0 {
		t.Fatalf("APPDATA read outside Windows: %v", evidences(fs))
	}
}

func TestPlaces(t *testing.T) {
	home := t.TempDir()
	var got []string
	for _, p := range Places(home, envOf(nil)) {
		got = append(got, Display(home, p.Path))
	}
	for _, w := range []string{"~/.kube/config", "~/.docker/config.json", "~/.aws/credentials", "~/.aws/config", "~/.config/gh/hosts.yml"} {
		if !slices.Contains(got, w) {
			t.Errorf("Places lacks %s: %v", w, got)
		}
	}
}

// The baseline holds where each stored credential is, never any part of it.
func TestTokenEntries(t *testing.T) {
	home := t.TempDir()
	v := newFakes()
	fs, _ := CheckTokens(home, plantAll(t, home, v))
	entries := TokenEntries(fs)
	if len(entries) != len(fs) {
		t.Fatalf("%d findings, %d entries: %v", len(fs), len(entries), entries)
	}
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	assertNoValue(t, string(b), v.all())
	for _, want := range []string{
		"token:DV-003 ~/.aws/credentials [default] aws_access_key_id",
		"token:DV-003 env AWS_ACCESS_KEY_ID",
		`token:DV-004 ~/.config/gh/hosts.yml hosts["github.com"].oauth_token`,
	} {
		if _, ok := entries[want]; !ok {
			t.Errorf("no key %q in %v", want, entries)
		}
	}
	for _, f := range fs {
		if _, ok := entries[TokenKey(f)]; !ok {
			t.Errorf("TokenKey(%s %s) = %q not in entries", f.ID, f.Location, TokenKey(f))
		}
	}
	if TokenKey(finding.Finding{ID: "DV-101", Location: "tool:git"}) != "" {
		t.Errorf("TokenKey of a tool finding")
	}
}

// A kubeconfig user is named by its name, so adding or removing another user
// does not move it. Only a user with no name, or a name used twice, is named
// by its place in the list.
func TestKubeKeyByName(t *testing.T) {
	home := t.TempDir()
	tok := fakeValue("kubetok")
	write(t, filepath.Join(home, ".kube", "config"), `users:
- name: zed
  user:
    token: `+tok+`
- name: ""
  user:
    token: `+tok+`
- name: twin
  user:
    token: `+tok+`
- name: twin
  user:
    password: `+tok+`
`)
	fs, unread := CheckTokens(home, envOf(nil))
	if len(unread) != 0 {
		t.Fatalf("unread = %v", unread)
	}
	got := evidences(fs)
	want := []string{
		`DV-001 ~/.kube/config users["zed"].user.token`,
		"DV-001 ~/.kube/config users[1].user.token",
		"DV-001 ~/.kube/config users[2].user.token",
		"DV-001 ~/.kube/config users[3].user.password",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got %q", got)
	}
	assertNoValue(t, strings.Join(got, "\n"), []string{tok})
	// A user added in front does not change the key of zed.
	write(t, filepath.Join(home, ".kube", "config"), "users:\n- name: aaa\n  user:\n    exec: {}\n- name: zed\n  user:\n    token: "+tok+"\n")
	fs, _ = CheckTokens(home, envOf(nil))
	if len(fs) != 1 || fs[0].Evidence != `users["zed"].user.token` {
		t.Errorf("findings = %v", evidences(fs))
	}
}
