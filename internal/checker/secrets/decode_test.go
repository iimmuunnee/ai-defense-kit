package secrets

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// b64Line wraps a source line the way an encoded payload sits in code.
func b64Line(line string) string {
	return `payload = "` + base64.StdEncoding.EncodeToString([]byte(line)) + "\"\n"
}

func TestBase64KeyInCurrentFileIsFoundAndLabelled(t *testing.T) {
	root := t.TempDir()
	key := fakeKey(t)
	write(t, root, "app/payload.js", b64Line(configLine(key)))
	res := run(t, root)
	if len(res.Findings) != 1 {
		t.Fatalf("결과 1건을 기대했습니다: %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.Kind != "secret-current" || f.Severity != finding.High || f.Location != "app/payload.js" || f.Line != 1 {
		t.Errorf("Kind/Severity/Location/Line = %q/%v/%q/%d", f.Kind, f.Severity, f.Location, f.Line)
	}
	// The file holds only the encoded text, so the report must say the shown
	// value is the decoded one.
	if !strings.Contains(f.Title, "base64를 풀어서 찾음") {
		t.Errorf("제목에 풀어서 찾았다는 표시가 없습니다: %q", f.Title)
	}
	if want := finding.Redact(key) + " (base64를 푼 값)"; f.Evidence != want {
		t.Errorf("Evidence = %q, want %q", f.Evidence, want)
	}
	if strings.Contains(f.Title+f.Evidence+f.Fix+f.ExplainKo, key) {
		t.Errorf("키 원문이 결과에 들어갔습니다: %+v", f)
	}
}

// A decoded finding must not take the occurrence number of a plain finding
// with the same masked value in the same file: that would change the plain
// finding's fingerprint, and with it every ignore entry and baseline.
func TestDecodedFindingDoesNotMovePlainFingerprint(t *testing.T) {
	key := fakeKey(t)
	alone := t.TempDir()
	write(t, alone, "config.py", configLine(key))
	plain := run(t, alone).Findings
	if len(plain) != 1 || strings.Contains(plain[0].Title, "풀어서") {
		t.Fatalf("평문 키 결과 1건을 기대했습니다: %+v", plain)
	}

	both := t.TempDir()
	write(t, both, "config.py", b64Line(configLine(key))+configLine(key))
	got := run(t, both).Findings
	if len(got) != 2 {
		t.Fatalf("결과 2건(풀어서 찾은 것, 평문)을 기대했습니다: %+v", got)
	}
	i := slices.IndexFunc(got, func(f finding.Finding) bool { return f.Line == 2 })
	if i < 0 {
		t.Fatalf("둘째 줄의 평문 키 결과가 없습니다: %+v", got)
	}
	if got[i].Fingerprint != plain[0].Fingerprint {
		t.Errorf("평문 키의 지문이 바뀌었습니다: %s → %s", plain[0].Fingerprint, got[i].Fingerprint)
	}
	if got[i].Evidence != plain[0].Evidence || got[i].Title != plain[0].Title {
		t.Errorf("평문 키의 제목이나 근거가 바뀌었습니다: %+v", got[i])
	}
}

// History is not decoded: on a repository with 24,000 commits decoding the
// history made the check about a third slower, while decoding current files
// cost nothing measurable. An encoded key that was committed and then removed
// is therefore missed. docs/benchmark.md says so; change both together.
func TestBase64KeyRemovedFromHistoryIsNotFound(t *testing.T) {
	needGit(t)
	root := t.TempDir()
	git(t, root, "init", "-q")
	write(t, root, "app/payload.js", b64Line(configLine(fakeKey(t))))
	git(t, root, "add", "-A")
	git(t, root, "commit", "-q", "-m", "first")
	git(t, root, "rm", "-q", "app/payload.js")
	git(t, root, "commit", "-q", "-m", "second")
	res := run(t, root)
	if len(res.Findings) != 0 {
		t.Fatalf("과거 기록은 인코딩을 풀지 않습니다(설계). 바꿨다면 docs/benchmark.md도 고치세요: %+v", res.Findings)
	}
}

func TestDecodedNoteNamesTheEncoding(t *testing.T) {
	for _, c := range []struct {
		tags       []string
		note, tail string
	}{
		{nil, "", ""},
		{[]string{"key", "aws"}, "", ""},
		{[]string{"decoded:base64", "decode-depth:1"}, "base64를 풀어서 찾음", " (base64를 푼 값)"},
		{[]string{"decoded:hex", "decode-depth:1"}, "16진수(hex)를 풀어서 찾음", " (16진수(hex)를 푼 값)"},
		{[]string{"decoded:percent", "decode-depth:1"}, "URL 인코딩(%)을 풀어서 찾음", " (URL 인코딩(%)을 푼 값)"},
		{[]string{"decoded:unicode", "decode-depth:1"}, "유니코드 이스케이프(\\u)를 풀어서 찾음", " (유니코드 이스케이프(\\u)를 푼 값)"},
		{[]string{"decoded:something-new"}, "인코딩을 풀어서 찾음", " (인코딩을 푼 값)"},
	} {
		note, tail := decodedNote(c.tags)
		if note != c.note || tail != c.tail {
			t.Errorf("decodedNote(%v) = %q, %q; want %q, %q", c.tags, note, tail, c.note, c.tail)
		}
	}
}

// One decoding pass is all the current-file scan does, so a key wrapped twice
// is missed. docs/benchmark.md says so; change both together.
func TestKeyEncodedTwiceIsNotFound(t *testing.T) {
	root := t.TempDir()
	write(t, root, "app/payload.js", b64Line(b64Line(configLine(fakeKey(t)))))
	if res := run(t, root); len(res.Findings) != 0 {
		t.Fatalf("두 번 감싼 키는 찾지 않습니다(설계). 바꿨다면 docs/benchmark.md도 고치세요: %+v", res.Findings)
	}
}
