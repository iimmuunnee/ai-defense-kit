package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// section returns the lines after the heading line up to the next blank-line
// separated heading (a line ending in "?" or a known heading word).
func section(text, heading string) []string {
	var out []string
	in := false
	for _, l := range strings.Split(text, "\n") {
		switch {
		case strings.TrimSpace(l) == heading:
			in = true
		case in && strings.TrimSpace(l) == "":
			if len(out) > 0 {
				return out
			}
		case in:
			out = append(out, l)
		}
	}
	return out
}

func TestDocsForEvidenceChanges(t *testing.T) {
	wl := readRepoFile(t, "explain/WL-001.md")
	usage := readRepoFile(t, "docs/usage.md")
	web := readRepoFile(t, "explain/WEB-001.md")

	// I4: 지나친 주장 고치기.
	if strings.Contains(wl+usage, "인자를 하나씩 나눠 적은 나열도 합친 모양에서 찾습니다") {
		t.Error("the split-args claim is still there")
	}
	// M8: WL-001 설명의 출력 항목은 2~3줄이고 자세한 내용은 usage.md에 있다.
	if s := section(wl, "무엇을 출력하고 무엇을 출력하지 않나요?"); len(s) < 2 || len(s) > 3 || !strings.Contains(strings.Join(s, "\n"), "docs/usage.md") {
		t.Errorf("WL-001 printed-output section: %d lines %q", len(s), s)
	}
	// M6: 찾지 못하는 모양.
	for _, want := range []string{"`env.PRIVATE_KEY`", "`config.get(`"} {
		if !strings.Contains(wl, want) {
			t.Errorf("WL-001 explain lacks %q", want)
		}
	}
	for _, want := range []string{
		// I4: AR·CI 근거가 가려질 수 있으니 파일을 열어 보라는 안내, 덮지 못하는 이스케이프.
		"가림 안내가 나오면 파일을 직접 열어",
		"`\\uXXXX`", "`\\xXX`", "`%2520`", "`&#32`", "`&ThinSpace;`",
		// I1~I3: 바뀐 규칙.
		"같은 구분 문자 하나", "camelCase", "UPPER_SNAKE",
		// M4: 지문 변경 안내.
		"`.adkignore`에 다시 적어야", "줄이 움직이면",
		// M6: web3 패키지와 규칙이 꺼지는 조건.
		"`@ethersproject/*`", "`hardhat`", "`@wagmi/core`", "이 패키지가 없으면 `WL-*` 규칙은 돌지 않습니다",
		// M9: 훈련 D7.
		"D7",
	} {
		if !strings.Contains(usage, want) {
			t.Errorf("usage.md lacks %q", want)
		}
	}
	// M2: SRI를 지원하지 않는 제공사 SDK.
	for _, want := range []string{"SRI를 지원하지 않", "제공사의 안내"} {
		if !strings.Contains(web, want) {
			t.Errorf("WEB-001 explain lacks %q", want)
		}
	}
	for name, text := range map[string]string{"WL-001": wl, "usage": usage, "WEB-001": web} {
		for _, bad := range []string{"막는다", "안전하다", "방어한다"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s has %q", name, bad)
			}
		}
	}
}

// M10: 시험 소스에 키처럼 묶은 16진수 글자를 적지 않는다(시험 안에서 만든다).
func TestNoGroupedHexLiteralsInTestSources(t *testing.T) {
	grouped := regexp.MustCompile(`[0-9a-fA-F]{4}(?:[ /:.\-][0-9a-fA-F]{4}){7,}`)
	err := filepath.Walk(filepath.Join("..", ".."), func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && (info.Name() == ".git" || info.Name() == "testdata") {
			return filepath.SkipDir
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for i, l := range strings.Split(string(b), "\n") {
			if grouped.MatchString(l) {
				t.Errorf("%s:%d holds grouped hex", filepath.ToSlash(p), i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
