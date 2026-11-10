package assets

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
)

func crtshBody(names ...string) string {
	var rows []string
	for i, n := range names {
		rows = append(rows, `{"issuer_ca_id":1,"issuer_name":"CN=Test CA","common_name":"`+n+`","name_value":"`+n+`","id":`+string(rune('1'+i))+`,"not_before":"2026-11-20T00:00:00","not_after":"2027-02-18T00:00:00","serial_number":"01"}`)
	}
	return "[" + strings.Join(rows, ",") + "]"
}

// I1: 제목은 도구가 만든 문장이라 단어 수를 세지 않는다. 호스트 이름만 따로 검사한다.
func TestSubdomainTitleIsShown(t *testing.T) {
	var w []string
	for i := 0; i < 12; i++ {
		sum := sha256.Sum256([]byte("b3-as" + string(rune('a'+i))))
		b := make([]byte, 6)
		for j := range b {
			b[j] = 'a' + sum[j]%26
		}
		w = append(w, string(b))
	}
	long := "pay.admin.internal.corp.example.test"
	phrase := strings.Join(w[:6], "-") + "." + strings.Join(w[6:], "-") + ".example.test"
	opt, _ := crtsh(t, 200, "application/json", crtshBody(long, phrase))
	c := NewChecker(explainFS, opt, nil, func() time.Time { return checkerNow })
	got, st := checker.RunAll(context.Background(), []checker.Checker{c}, checker.Target{Domain: "example.test"}, 0)
	if st[0].Status != checker.StatusOK {
		t.Fatalf("status %+v", st[0])
	}
	seen := map[string]string{}
	for _, f := range got {
		seen[f.Location] = f.Title
	}
	if seen[long] != "인증서 공개 기록에서 찾은 서브도메인: "+long {
		t.Errorf("title %q", seen[long])
	}
	title := strings.ToLower(seen[phrase])
	if !strings.HasPrefix(title, "인증서 공개 기록에서 찾은 서브도메인: ") {
		t.Errorf("title %q", title)
	}
	for _, word := range w {
		if strings.Contains(title, word) {
			t.Errorf("word shown in title %q", title)
			break
		}
	}
}
