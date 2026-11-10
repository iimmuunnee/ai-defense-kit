package secrets

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/zricethezav/gitleaks/v8/report"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// fakeKey returns a fixed high-entropy token built only from digits and
// uppercase consonants, so it cannot contain a gitleaks stopword and the
// generic-api-key rule always detects it. It is not a real provider format.
func fakeKey(t *testing.T) string {
	t.Helper()
	return "K7Q2X9M4T8W3Z6R1P5V0H2J9L7N4B8D3F6G1"
}

func configLine(key string) string { return "api_key = \"" + key + "\"\n" }

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

func run(t *testing.T, root string) checker.Result {
	t.Helper()
	res, err := New(aidefensekit.Data).Run(context.Background(), checker.Target{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestName(t *testing.T) {
	if got := New(aidefensekit.Data).Name(); got != "secrets" {
		t.Fatalf("Name = %q", got)
	}
}

func TestFindsCurrentSecret(t *testing.T) {
	root := t.TempDir()
	key := fakeKey(t)
	write(t, root, "config.py", configLine(key))
	res := run(t, root)
	if len(res.Findings) < 1 {
		t.Fatalf("no findings; warnings=%v", res.Warnings)
	}
	f := res.Findings[0]
	if f.Severity != finding.High {
		t.Errorf("Severity = %v, want High", f.Severity)
	}
	if f.Kind != "secret-current" {
		t.Errorf("Kind = %q, want secret-current", f.Kind)
	}
	if strings.Contains(f.Evidence, key) || strings.Contains(f.Title+f.Fix+f.ExplainKo, key) {
		t.Errorf("raw key leaked into finding: %+v", f)
	}
	if !strings.HasSuffix(f.Evidence, "****") {
		t.Errorf("Evidence = %q", f.Evidence)
	}
	if f.Location != "config.py" || f.Line != 1 {
		t.Errorf("Location/Line = %q/%d", f.Location, f.Line)
	}
	if f.Confidence != finding.Certain {
		t.Errorf("Confidence = %v", f.Confidence)
	}
	if f.ExplainKo == "" || f.Fingerprint == "" || !strings.HasPrefix(f.ID, "SECRET-") {
		t.Errorf("incomplete finding: %+v", f)
	}
	// The fingerprint comes from the shown evidence, never from the secret.
	if want := finding.MakeMaskedFingerprint(f.ID, f.Location, f.Evidence, 0); f.Fingerprint != want {
		t.Errorf("Fingerprint = %s, want hash of the shown evidence %s", f.Fingerprint, want)
	}
}

func TestHistoryOnlySecretIsMedium(t *testing.T) {
	needGit(t)
	root := t.TempDir()
	key := fakeKey(t)
	git(t, root, "init", "-q")
	write(t, root, "config.py", configLine(key))
	git(t, root, "add", ".")
	git(t, root, "commit", "-q", "-m", "add")
	write(t, root, "config.py", "api_key = os.environ['API_KEY']\n")
	git(t, root, "commit", "-q", "-am", "remove")

	res := run(t, root)
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != finding.Medium {
		t.Errorf("Severity = %v, want Medium", f.Severity)
	}
	if f.Kind != "secret-history" {
		t.Errorf("Kind = %q, want secret-history", f.Kind)
	}
	if f.Location != "config.py" {
		t.Errorf("Location = %q", f.Location)
	}
	if !strings.Contains(f.Evidence, "(커밋 ") || strings.Contains(f.Evidence, key) {
		t.Errorf("Evidence = %q", f.Evidence)
	}
	if !strings.Contains(f.ExplainKo, "다시 발급") {
		t.Errorf("history explanation should tell to reissue the key")
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

func TestSameSecretInBothIsOneFinding(t *testing.T) {
	needGit(t)
	root := t.TempDir()
	git(t, root, "init", "-q")
	write(t, root, "config.py", configLine(fakeKey(t)))
	git(t, root, "add", ".")
	git(t, root, "commit", "-q", "-m", "add")

	res := run(t, root)
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Severity != finding.High {
		t.Errorf("Severity = %v, want High", res.Findings[0].Severity)
	}
}

func TestNoGitDirWarnsNotFails(t *testing.T) {
	root := t.TempDir()
	write(t, root, "config.py", configLine(fakeKey(t)))
	res := run(t, root)
	if len(res.Findings) != 1 {
		t.Errorf("findings = %d, want 1", len(res.Findings))
	}
	joined := strings.Join(res.Warnings, "\n")
	if !strings.Contains(joined, "git 기록이 없어") {
		t.Errorf("Warnings = %v", res.Warnings)
	}
}

func TestTestPathIsSuspect(t *testing.T) {
	root := t.TempDir()
	write(t, root, "tests/config.py", configLine(fakeKey(t)))
	res := run(t, root)
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Confidence != finding.Suspect {
		t.Errorf("Confidence = %v", f.Confidence)
	}
	if f.Location != "tests/config.py" {
		t.Errorf("Location = %q", f.Location)
	}
}

func TestCancelledContext(t *testing.T) {
	root := t.TempDir()
	write(t, root, "config.py", configLine(fakeKey(t)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(aidefensekit.Data).Run(ctx, checker.Target{Root: root}); err == nil {
		t.Error("expected error from cancelled context")
	}
}

func TestNodeModulesIsNotReported(t *testing.T) {
	root := t.TempDir()
	write(t, root, "node_modules/pkg/config.js", configLine(fakeKey(t)))
	res := run(t, root)
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v, want none", res.Findings)
	}
}

// Regression: scanning must never run commands configured in the scanned
// repository's .git/config (diff textconv / external diff drivers).
func TestHistoryDoesNotRunRepoTextconv(t *testing.T) {
	needGit(t)
	root := t.TempDir()
	marker := filepath.Join(t.TempDir(), "PWNED")
	git(t, root, "init", "-q")
	git(t, root, "config", "diff.pwn.textconv", "touch "+marker+"; cat")
	write(t, root, ".gitattributes", "* diff=pwn\n")
	write(t, root, "config.py", configLine(fakeKey(t)))
	git(t, root, "add", ".")
	git(t, root, "commit", "-q", "-m", "add")
	write(t, root, "config.py", "x = 1\n")
	git(t, root, "commit", "-q", "-am", "change")

	run(t, root)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("scan executed a command from the scanned repo's git config")
	}
}

func TestBuildAndToolDirsAreNotReported(t *testing.T) {
	// The scanned folder itself sits under a "build" directory: only folders
	// inside the target are skipped, not the target's own ancestors.
	root := filepath.Join(t.TempDir(), "build", "proj")
	for _, rel := range []string{
		".next/server/x.js", "dist/app.js", ".venv/Lib/site-packages/x.py",
		"build/out.js", "vendor/lib/x.py", "__pycache__/x.py", "sub/.next/y.js",
	} {
		write(t, root, rel, configLine(fakeKey(t)))
	}
	write(t, root, "app/config.py", configLine(fakeKey(t)))
	res := run(t, root)
	if len(res.Findings) != 1 || res.Findings[0].Location != "app/config.py" {
		t.Fatalf("findings = %+v, want only app/config.py", res.Findings)
	}
}

func gitOut(t *testing.T, dir string, stdin string, args ...string) string {
	t.Helper()
	full := append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// Regression: a scanned repo with log.showSignature and gpg.program must not
// make the history scan run its "gpg" program on a signed-looking commit.
func TestHistoryDoesNotRunRepoGPGProgram(t *testing.T) {
	needGit(t)
	if runtime.GOOS == "windows" {
		t.Skip("shell script gpg.program")
	}
	root := t.TempDir()
	tmp := t.TempDir()
	marker := filepath.Join(tmp, "PWNED")
	script := filepath.Join(tmp, "fakegpg.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, root, "init", "-q")
	git(t, root, "config", "log.showSignature", "true")
	git(t, root, "config", "gpg.program", script)
	git(t, root, "config", "gpg.format", "openpgp")
	write(t, root, "config.py", configLine(fakeKey(t)))
	git(t, root, "add", ".")
	git(t, root, "commit", "-q", "-m", "add")

	// Re-create HEAD with a fake gpgsig header so git believes it is signed.
	head := gitOut(t, root, "", "cat-file", "commit", "HEAD")
	hdr, msg, _ := strings.Cut(head, "\n\n")
	sig := "gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEEfakefakefakefakefakefakefakefakeFAKE=\n =fake\n -----END PGP SIGNATURE-----"
	signed := hdr + "\n" + sig + "\n\n" + msg + "\n"
	id := gitOut(t, root, signed, "hash-object", "-t", "commit", "-w", "--stdin")
	git(t, root, "update-ref", "HEAD", id)
	// sanity: plain git log really runs the program in this repo
	exec.Command("git", "-C", root, "log", "-1").Run()
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("test setup: git log did not run gpg.program, test would be vacuous")
	}
	os.Remove(marker)

	write(t, root, "config.py", "x = 1\n")
	git(t, root, "commit", "-q", "-am", "remove key")

	res := run(t, root)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("scan executed gpg.program from the scanned repo's git config")
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != finding.Medium {
		t.Errorf("history scan should still find the committed key: %+v warnings=%v", res.Findings, res.Warnings)
	}
}

func TestSafeGitConfigKeepsExistingEntries(t *testing.T) {
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "user.name")
	t.Setenv("GIT_CONFIG_VALUE_0", "kept")
	t.Setenv("GIT_CONFIG_KEY_1", "") // registers restore of the real value
	os.Unsetenv("GIT_CONFIG_KEY_1")
	var count, key0, keyN string
	err := withGitSettings(safeGitConfig, safeGitEnv, func() error {
		count = os.Getenv("GIT_CONFIG_COUNT")
		key0 = os.Getenv("GIT_CONFIG_KEY_0")
		keyN = os.Getenv("GIT_CONFIG_KEY_1")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != strconv.Itoa(1+len(safeGitConfig)) || key0 != "user.name" || keyN != safeGitConfig[0][0] {
		t.Errorf("count=%q key0=%q key1=%q", count, key0, keyN)
	}
	if os.Getenv("GIT_CONFIG_COUNT") != "1" {
		t.Errorf("environment not restored: %q", os.Getenv("GIT_CONFIG_COUNT"))
	}
	if _, ok := os.LookupEnv("GIT_CONFIG_KEY_1"); ok {
		t.Error("added key not removed")
	}
}

// Regression: in a partial-clone repo a missing history object makes git
// lazily fetch from the promisor remote, which runs remote.origin.uploadpack
// (or core.sshCommand, or an ext:: URL). The scan must never do that, and it
// must say that history could not be read completely.
func TestHistoryDoesNotLazyFetchFromPromisor(t *testing.T) {
	needGit(t)
	if runtime.GOOS == "windows" {
		t.Skip("shell script uploadpack")
	}
	root := t.TempDir()
	tmp := t.TempDir()
	marker := filepath.Join(tmp, "PWNED")
	script := filepath.Join(tmp, "uploadpack.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, root, "init", "-q")
	write(t, root, "config.py", configLine(fakeKey(t)))
	git(t, root, "add", ".")
	git(t, root, "commit", "-q", "-m", "add")
	blob := gitOut(t, root, "", "rev-parse", "HEAD:config.py")
	write(t, root, "config.py", "x = 1\n")
	git(t, root, "commit", "-q", "-am", "remove key")

	git(t, root, "config", "core.repositoryformatversion", "1")
	git(t, root, "config", "extensions.partialClone", "origin")
	git(t, root, "config", "remote.origin.promisor", "true")
	git(t, root, "config", "remote.origin.url", tmp)
	git(t, root, "config", "remote.origin.uploadpack", script)
	if err := os.Remove(filepath.Join(root, ".git", "objects", blob[:2], blob[2:])); err != nil {
		t.Fatal(err)
	}

	// sanity: plain git really runs the script here, so the test is not vacuous
	exec.Command("git", "-C", root, "cat-file", "blob", blob).Run()
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("test setup: git did not lazy-fetch through uploadpack")
	}
	os.Remove(marker)

	res := run(t, root)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("scan lazily fetched from the scanned repo's promisor remote")
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "git 기록을 읽지 못해") {
		t.Errorf("incomplete history must be reported: warnings=%v findings=%+v", res.Warnings, res.Findings)
	}
}

// supabaseJWT builds a fake legacy Supabase key: base64url header and payload
// plus a fixed 43-char signature-like string. Not a real project key.
func supabaseJWT(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(payload)) + "." +
		"K7Q2X9M4T8W3Z6R1P5V0H2J9L7N4B8D3F6G1abcdefg"[:43]
}

func supabaseFixtureLine(key string) string {
	return "SUPABASE_KEY = \"" + key + "\"\n"
}

// requireRawDetected fails unless gitleaks itself reports the fixture, so the
// not-reported tests cannot pass just because gitleaks never saw the value.
func requireRawDetected(t *testing.T, root string) {
	t.Helper()
	raw, err := scanFiles(context.Background(), root, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("gitleaks does not detect the fixture; the test would prove nothing")
	}
}

func TestAnonJWTNotReported(t *testing.T) {
	root := t.TempDir()
	write(t, root, "config.py", supabaseFixtureLine(supabaseJWT(`{"iss":"supabase","ref":"abcdefghij","role":"anon","iat":1700000000,"exp":2000000000}`)))
	requireRawDetected(t, root)
	if res := run(t, root); len(res.Findings) != 0 {
		t.Fatalf("anon JWT reported: %+v", res.Findings)
	}
}

func TestServiceRoleJWTReported(t *testing.T) {
	root := t.TempDir()
	write(t, root, "config.py", supabaseFixtureLine(supabaseJWT(`{"iss":"supabase","ref":"abcdefghij","role":"service_role","iat":1700000000,"exp":2000000000}`)))
	requireRawDetected(t, root)
	if res := run(t, root); len(res.Findings) == 0 {
		t.Fatal("service_role JWT not reported")
	}
}

func TestMalformedJWTReported(t *testing.T) {
	root := t.TempDir()
	// Payload decodes from base64url but is truncated, invalid JSON (it
	// still starts with eyJ so gitleaks' jwt rule matches).
	bad := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + base64.RawURLEncoding.EncodeToString([]byte(`{"role":"anon","ref":"abcdefghij"`)) +
		".K7Q2X9M4T8W3Z6R1P5V0H2J9L7N4B8D3F6G1abcdefg"
	write(t, root, "config.py", supabaseFixtureLine(bad))
	requireRawDetected(t, root)
	if res := run(t, root); len(res.Findings) == 0 {
		t.Fatal("malformed JWT not reported")
	}
}

func TestAnonJWTInHistoryNotReported(t *testing.T) {
	needGit(t)
	root := t.TempDir()
	git(t, root, "init", "-q")
	write(t, root, "config.py", supabaseFixtureLine(supabaseJWT(`{"iss":"supabase","ref":"abcdefghij","role":"anon","iat":1700000000,"exp":2000000000}`)))
	git(t, root, "add", ".")
	git(t, root, "commit", "-q", "-m", "add")
	git(t, root, "rm", "-q", "config.py")
	git(t, root, "commit", "-q", "-m", "rm")
	if res := run(t, root); len(res.Findings) != 0 {
		t.Fatalf("anon JWT in history reported: %+v", res.Findings)
	}
}

func TestPublishableKeyNotReported(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".env", "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=sb_publishable_K7Q2X9M4T8W3Z6R1P5V0H2J9L7N4B8D3\n")
	if raw, _ := scanFiles(context.Background(), root, false); len(raw) == 0 {
		t.Skip("gitleaks default config does not detect sb_publishable_ values; covered by TestIsPublicSupabaseKey")
	}
	if res := run(t, root); len(res.Findings) != 0 {
		t.Fatalf("publishable key reported: %+v", res.Findings)
	}
}

func TestIsPublicSupabaseKey(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	padded := enc([]byte(`{"alg":"HS256"}`)) + "." + base64.URLEncoding.EncodeToString([]byte(`{"role":"anon"}`)) + ".sig"
	cases := []struct {
		name   string
		secret string
		want   bool
	}{
		{"publishable", "sb_publishable_K7Q2X9M4T8W3Z6R1P5V0H2J9L7N4B8D3", true},
		{"anon", supabaseJWT(`{"role":"anon"}`), true},
		{"anon padded payload", padded, true},
		{"service_role", supabaseJWT(`{"role":"service_role"}`), false},
		{"authenticated", supabaseJWT(`{"role":"authenticated"}`), false},
		{"no role", supabaseJWT(`{"iss":"supabase"}`), false},
		{"role not string", supabaseJWT(`{"role":["anon"]}`), false},
		{"payload not json", "eyJhbGciOiJIUzI1NiJ9." + enc([]byte("nope")) + ".sig", false},
		{"payload not base64", "eyJhbGciOiJIUzI1NiJ9.!!!.sig", false},
		{"two parts", "eyJhbGciOiJIUzI1NiJ9." + enc([]byte(`{"role":"anon"}`)), false},
		{"four parts", supabaseJWT(`{"role":"anon"}`) + ".x", false},
		{"secret key", "sb_secret" + "_K7Q2X9M4T8W3Z6R1P5V0H2J9L7N4B8D3", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		if got := isPublicSupabaseKey(c.secret); got != c.want {
			t.Errorf("%s: isPublicSupabaseKey = %v, want %v", c.name, got, c.want)
		}
	}
}

// M2: only the secret itself decides; a real key on a line that also mentions
// a publishable key is still reported.
func TestDropPublicSupabaseKeysUsesSecretOnly(t *testing.T) {
	in := []report.Finding{
		{Secret: "sb_publishable_xxxxxxxxxxxx", Match: "KEY=sb_publishable_xxxxxxxxxxxx"},
		{Secret: "Z8x2Kq9L" + "mN3vB7cX1pR5tY6uW0eA4sD2", Match: `pub="sb_publishable_xxxx" tok` + `en="Z8x2Kq9LmN3vB7cX1pR5tY6uW0eA4sD2"`},
	}
	out := dropPublicSupabaseKeys(in)
	if len(out) != 1 || out[0].Secret != in[1].Secret {
		t.Fatalf("got %+v", out)
	}
}

func TestHistoryChecksSubfolderOfRepo(t *testing.T) {
	needGit(t)
	repo := t.TempDir()
	inside := fakeKey(t)
	outside := "Z9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3I2"
	git(t, repo, "init", "-q")
	write(t, repo, "apps/web/config.py", configLine(inside))
	write(t, repo, "apps/api/config.py", configLine(outside))
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "add")
	write(t, repo, "apps/web/config.py", "api_key = os.environ['API_KEY']\n")
	write(t, repo, "apps/api/config.py", "api_key = os.environ['API_KEY']\n")
	git(t, repo, "commit", "-q", "-am", "remove")

	res := run(t, filepath.Join(repo, "apps", "web"))
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v", res.Warnings)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want only the target folder's secret: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Kind != "secret-history" || f.Location != "config.py" {
		t.Errorf("Kind = %q, Location = %q", f.Kind, f.Location)
	}
}
