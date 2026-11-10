package finding

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	if got := Redact("sk_live_abcdef123"); got != "sk_l****" {
		t.Fatal(got)
	}
	if got := Redact("abcd"); got != "****" {
		t.Fatal(got)
	}
	if got := Redact(""); got != "****" {
		t.Fatal(got)
	}
	// 4자 초과인 한글 값도 문자 단위로 앞 4자만 남긴다
	if got := Redact("가나다라마바"); got != "가나다라****" {
		t.Fatal(got)
	}
}

func TestFingerprintIgnoresLineAndIsStable(t *testing.T) {
	a := MakeFingerprint("KR-PAY-002", "api/webhook.py", "portone")
	if a != MakeFingerprint("KR-PAY-002", "api/webhook.py", "portone") || len(a) != 16 {
		t.Fatal(a)
	}
	if a == MakeFingerprint("KR-PAY-002", "api/other.py", "portone") {
		t.Fatal("location must affect fingerprint")
	}
	// 구분자 NUL 때문에 경계가 다른 입력은 서로 다른 지문이어야 한다
	if MakeFingerprint("a", "bc", "d") == MakeFingerprint("ab", "c", "d") {
		t.Fatal("field boundary must affect fingerprint")
	}
}

func TestNormalizePathWindows(t *testing.T) {
	// filepath.ToSlash는 리눅스에서 '\'를 바꾸지 않으므로, 이 테스트는 입력을 OS 구분자로 만든다
	p := filepath.Join("C:", "repo", "api", "webhook.py")
	if got := NormalizePath(filepath.Join("C:", "repo"), p); got != "api/webhook.py" {
		t.Fatal(got)
	}
}

func TestSortOrder(t *testing.T) {
	fs := []Finding{{ID: "a", Severity: High}, {ID: "b", Severity: Critical}, {ID: "c", Severity: High, Exploited: true}}
	Sort(fs)
	got := fs[0].ID + fs[1].ID + fs[2].ID
	if got != "bca" {
		t.Fatal(got)
	}
}

func TestSortTieBreakers(t *testing.T) {
	fs := []Finding{
		{ID: "d", Severity: Low, Confidence: Suspect, Location: "a.go", Line: 1},
		{ID: "c", Severity: Low, Confidence: Certain, Location: "b.go", Line: 1},
		{ID: "b", Severity: Low, Confidence: Certain, Location: "a.go", Line: 9},
		{ID: "a", Severity: Low, Confidence: Certain, Location: "a.go", Line: 2},
	}
	Sort(fs)
	got := fs[0].ID + fs[1].ID + fs[2].ID + fs[3].ID
	if got != "abcd" {
		t.Fatal(got)
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"HIGH": High, "info": Info, " Low ": Low, "Medium": Medium, "critical": Critical} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Fatalf("%q: got %v, %v", in, got, err)
		}
	}
	if _, err := ParseSeverity("모름"); err == nil {
		t.Fatal("expected error")
	}
}

func TestSeverityString(t *testing.T) {
	for s, want := range map[Severity]string{Info: "info", Low: "low", Medium: "medium", High: "high", Critical: "critical"} {
		if s.String() != want {
			t.Fatal(s, want)
		}
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	b, err := json.Marshal(Finding{Severity: High})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"severity":"high"`) {
		t.Fatalf("want severity \"high\" in %s", b)
	}
	var f Finding
	if err := json.Unmarshal(b, &f); err != nil || f.Severity != High {
		t.Fatalf("want High, got %v, err %v", f.Severity, err)
	}
	if err := json.Unmarshal([]byte(`{"severity":"모름"}`), &f); err == nil {
		t.Fatal("want error for unknown severity string")
	}
	if _, err := json.Marshal(Finding{Severity: Severity(99)}); err == nil {
		t.Fatal("want error for out-of-range severity")
	}
}

// 개인 키나 시드 구문처럼 생긴 값은 접두사도 남기지 않는다. 그 밖의 값은 이전과 같다.
func TestRedactKeyMaterialKeepsNoPrefix(t *testing.T) {
	hex64 := strings.Repeat("a1b2c3d4", 8)
	// 12단어 구문은 시험 안에서 이어 붙인다(한 줄에 구문 모양을 적지 않게).
	words := strings.Join(append([]string{"zoo", "quartz", "vessel", "amber", "robot", "tunnel"},
		"glide", "pencil", "north", "spring", "cabin", "onion"), " ")
	for _, s := range []string{"0x" + hex64, "0X" + hex64, hex64, words, words + " # don't share", words + " (backup)"} {
		if got := Redact(s); got != "****" {
			t.Errorf("Redact(%.20q) = %q", s, got)
		}
	}
	for in, want := range map[string]string{
		"0x" + hex64[:40]:             "0xa1****",
		hex64[:63]:                    "a1b2****",
		"one two three four five six": "one ****",
		"sk_live_abcdef123":           "sk_l****",
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%.20q) = %q, want %q", in, got, want)
		}
	}
	if RedactPrefix(hex64) != "a1b2****" {
		t.Error("RedactPrefix must keep the old behaviour")
	}
}
