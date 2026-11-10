package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEvidenceUntrustedField(t *testing.T) {
	r := evidenceCodeReport()
	r.Untrusted = true
	var m map[string]any
	if err := json.Unmarshal([]byte(evidenceString(t, r, nil)), &m); err != nil {
		t.Fatal(err)
	}
	if m["untrusted"] != true {
		t.Errorf("untrusted = %v", m["untrusted"])
	}
	for name, rep := range map[string]Report{"code": evidenceCodeReport(), "assets": evidenceAssetsReport()} {
		m = nil
		if err := json.Unmarshal([]byte(evidenceString(t, rep, nil)), &m); err != nil {
			t.Fatal(err)
		}
		if m["untrusted"] != false {
			t.Errorf("%s: untrusted = %v", name, m["untrusted"])
		}
	}
}

func TestWriteJSONLeavesUntrustedOut(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, Report{Target: "x", ScannedAt: time.Now(), Untrusted: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "untrusted") {
		t.Errorf("%s", buf.String())
	}
}

func TestMarkdownWarnsWhenAdkignoreHid(t *testing.T) {
	const want = "> ⚠️ .adkignore가 결과 2개를 숨겼습니다. 받은 코드라면 --untrusted로 다시 점검하세요.\n"
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, Report{Target: "x", ScannedAt: time.Now(), Ignored: 2}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "# adk 점검 리포트\n\n"+want+"\n") {
		t.Errorf("%.200s", buf.String())
	}
	for name, r := range map[string]Report{
		"nothing hidden": {Target: "x", ScannedAt: time.Now()},
		"assets":         {Kind: KindAssets, Target: "x", ScannedAt: time.Now(), Ignored: 2},
	} {
		buf.Reset()
		if err := WriteMarkdown(&buf, r); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(buf.String(), "--untrusted") {
			t.Errorf("%s: %s", name, buf.String())
		}
	}
}
