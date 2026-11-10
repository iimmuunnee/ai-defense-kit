package watch

import (
	"errors"
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

func TestOutsideImageIsAFindingWithoutAChange(t *testing.T) {
	allow := map[string]any{"allowed_registries": []any{podsReg}}
	pods := podList(
		rsPod("web-1-a", "1", ctr("web", podsWeb, dgA)),
		tp{ns: "ops", name: "dbg", ctrs: []pj{ctr("sh", "docker.io/library/busybox:1", dgB)}},
	)
	tg, obs := mustPods(t, pods, allow)

	fs, o := podsFindings(tg, obs, obs, nil)
	if len(fs) != 1 {
		t.Fatalf("findings = %+v (changes %v)", fs, o.Changes)
	}
	f := fs[0]
	if f.ID != "WA-103" || f.Severity != finding.High || f.Confidence != finding.Certain || f.Location != podsKey {
		t.Errorf("finding = %+v", f)
	}
	text := f.Title + " " + f.Evidence
	for _, want := range []string{"허용 목록 밖", "docker.io", "ops/pod:dbg/sh"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q: %s", want, text)
		}
	}
	if code := ExitCode(o, fs, finding.High); code != 1 {
		t.Errorf("exit = %d", code)
	}

	t.Run("the same between rounds", func(t *testing.T) {
		again, _ := podsFindings(tg, obs, obs, nil)
		if len(again) != 1 || again[0].Fingerprint != f.Fingerprint || again[0].Evidence != f.Evidence || again[0].Title != f.Title {
			t.Errorf("round 2 = %+v, round 1 = %+v", again, f)
		}
	})
	t.Run("no list means nothing is outside", func(t *testing.T) {
		tg2 := podsTarget(tg.Options["file"].(string), nil)
		if fs, _ := podsFindings(tg2, obs, obs, nil); len(fs) != 0 {
			t.Errorf("findings = %+v", fs)
		}
	})
	t.Run("the registry added to the list ends it", func(t *testing.T) {
		tg2 := podsTarget(tg.Options["file"].(string), map[string]any{"allowed_registries": []any{podsReg, "docker.io"}})
		if fs, _ := podsFindings(tg2, obs, obs, nil); len(fs) != 0 {
			t.Errorf("findings = %+v", fs)
		}
	})
	t.Run("a change is one finding, not two", func(t *testing.T) {
		cur := Observation{}
		for k, v := range obs {
			cur[k] = v
		}
		cur["image:ops/pod:dbg/sh"] = dgC
		fs, _ := podsFindings(tg, obs, cur, nil)
		if len(fs) != 1 || !strings.Contains(fs[0].Evidence, dgC) || !strings.Contains(fs[0].Title+fs[0].Evidence, "허용 목록 밖") {
			t.Errorf("findings = %+v", fs)
		}
	})
	t.Run("a partial read counts what was read", func(t *testing.T) {
		fs, _ := podsFindings(tg, obs, nil, PartialError{Obs: obs, Err: errors.New("일부 못 읽음")})
		if len(fs) != 1 || fs[0].ID != "WA-103" || fs[0].Confidence != finding.Certain {
			t.Errorf("findings = %+v", fs)
		}
		only := Observation{"file": obs["file"], "image:default/deployment:web/web": dgA, "registry:default/deployment:web/web": podsReg}
		if fs, _ := podsFindings(tg, obs, nil, PartialError{Obs: only, Err: errors.New("일부 못 읽음")}); len(fs) != 0 {
			t.Errorf("a container that was not read counted: %+v", fs)
		}
	})
	t.Run("stale wording still applies", func(t *testing.T) {
		fs, _ := podsFindings(tg, obs, nil, PartialError{Obs: obs, Err: staleError{msg: "오래됨"}})
		if len(fs) != 1 || fs[0].Confidence != finding.Suspect || !strings.Contains(fs[0].Title, "내보내기 파일 오래됨 의심") || !strings.Contains(fs[0].Evidence, staleExportNotice) {
			t.Errorf("findings = %+v", fs)
		}
	})
	t.Run("a target new to the baseline counts", func(t *testing.T) {
		cfg := Config{Targets: []Target{tg}}
		o := Compare(Baseline{Entries: map[string]Observation{}}, map[string]Observation{podsKey: obs}, nil, cfg)
		if fs := Findings(o, cfg, nil); len(fs) != 1 || fs[0].ID != "WA-103" {
			t.Errorf("findings = %+v", fs)
		}
	})
	t.Run("an unknown registry is outside", func(t *testing.T) {
		list := podList(tp{ns: "ops", name: "x", ctrs: []pj{ctr("c", "sha256:"+strings.Repeat("a", 64), dgB)}})
		tg, obs := mustPods(t, list, allow)
		if fs, _ := podsFindings(tg, obs, obs, nil); len(fs) != 1 || !strings.Contains(fs[0].Evidence, unknownRegistry) {
			t.Errorf("findings = %+v", fs)
		}
	})
	// Other kinds have no such rule.
	t.Run("other kinds", func(t *testing.T) {
		tg := repoTarget(map[string]any{"root": "."})
		cfg := Config{Targets: []Target{tg}}
		b := Baseline{Entries: map[string]Observation{tg.Key: {"root": ".", "registry:x": "docker.io"}}}
		o := Compare(b, map[string]Observation{tg.Key: {"root": ".", "registry:x": "docker.io"}}, nil, cfg)
		if fs := Findings(o, cfg, nil); len(fs) != 0 {
			t.Errorf("findings = %+v", fs)
		}
	})
}

func TestOutsideImageTextsMatchTheRule(t *testing.T) {
	for _, p := range []string{"../../docs/watch.md", "../../explain/WA-103.md", "../../fixes/WA-103/watch.md"} {
		s := readText(t, p)
		for _, want := range []string{"점검할 때마다", "accept"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s lacks %q", p, want)
			}
		}
	}
	if s := readText(t, "../../docs/watch.md"); strings.Contains(s, "`check`는 매번 리포트에 참고로 적습니다. 참고는 종료 코드를 바꾸지 않습니다. 새로 생기거나") {
		t.Error("docs/watch.md still describes the off-list note")
	}
}
