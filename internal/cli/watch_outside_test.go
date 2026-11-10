package cli

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

// The allow list is the approval. Adding it to a target whose baseline holds an
// image off the list is a finding, and accept does not silence it.
func TestWatchOutsideImageInTheBaselineIsAFinding(t *testing.T) {
	body := podsJSON(
		podEntry{"prod", "web", "app", "registry.example.com/web:1", unreadDigA, ""},
		podEntry{"ops", "dbg", "sh", "docker.io/library/busybox:1", unreadDigB, ""},
	)
	w, file := podsWsp(t, "", body)
	mustInit(t, w)
	if code, out, _ := w.run("check", "--format", "json"); code != 0 {
		t.Fatalf("before the list: code=%d\n%s", code, out)
	}
	addList := func(list string) {
		t.Helper()
		cfg := "targets:\n  - key: cluster\n    kind: k8s-pods\n    options:\n      file: \"" + strings.ReplaceAll(file, `\`, "/") + "\"\n      allowed_registries: [" + list + "]\n"
		if err := os.WriteFile(w.cfg, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	addList(`"registry.example.com"`)

	rec, hook := newHook(t, 200)
	t.Setenv(webhookEnv, hook)
	code, out, errs := w.run("check", "--format", "json")
	fs := d3Findings(t, out)
	if code != 1 || len(fs) != 1 || fs[0].ID != "WA-103" || fs[0].Severity != "high" {
		t.Fatalf("code=%d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(fs[0].Evidence, "ops/pod:dbg/sh") || !strings.Contains(fs[0].Evidence, "docker.io") {
		t.Errorf("evidence = %q", fs[0].Evidence)
	}
	if strings.Contains(out, "allowed_registries 밖의 레지스트리에서 왔습니다") {
		t.Errorf("the note is still in the report:\n%s", out)
	}
	if all := strings.Join(rec.all(), "\n"); !strings.Contains(all, "WA-103") {
		t.Errorf("the webhook did not carry it: %q", all)
	}
	t.Setenv(webhookEnv, "")

	// accept has nothing to take in and leaves the finding where it is.
	if code, out, errs := w.run("accept", "cluster", "--note", "받아들임"); code != 0 {
		t.Fatalf("accept = %d\n%s\n%s", code, out, errs)
	}
	if code, out, _ := w.run("check", "--format", "json"); code != 1 || len(d3Findings(t, out)) != 1 {
		t.Errorf("after accept: code=%d\n%s", code, out)
	}
	// Approving the registry ends it.
	addList(`"registry.example.com", "docker.io"`)
	if code, out, _ := w.run("check", "--format", "json"); code != 0 {
		t.Errorf("after adding the registry: code=%d\n%s", code, out)
	}
}

// --every reports again only when the state changes.
func TestWatchOutsideImageIsStableBetweenRounds(t *testing.T) {
	body := podsJSON(podEntry{"ops", "dbg", "sh", "docker.io/library/busybox:1", unreadDigB, ""})
	w, file := podsWsp(t, `      allowed_registries: ["registry.example.com"]`+"\n", body)
	mustInit(t, w)
	cfg, err := watch.LoadConfig(w.cfg)
	if err != nil {
		t.Fatal(err)
	}
	base, err := watch.LoadBaseline(w.base, "")
	if err != nil {
		t.Fatal(err)
	}
	opt := watchOptions{failOn: finding.High, targetTimeout: time.Minute}
	a := evaluate(context.Background(), cfg, base, opt, newScrubber())
	b := evaluate(context.Background(), cfg, base, opt, newScrubber())
	if len(a.findings) != 1 || len(b.findings) != 1 {
		t.Fatalf("findings = %v / %v", a.findings, b.findings)
	}
	if a.sig != b.sig || a.sig == "" || a.findings[0].Fingerprint != b.findings[0].Fingerprint {
		t.Errorf("not stable:\n%q\n%q", a.sig, b.sig)
	}
	// The same image from another off-list registry, digest and all unchanged in
	// the baseline's terms, is another state.
	moved := podsJSON(podEntry{"ops", "dbg", "sh", "docker.io/library/busybox:1", unreadDigB, ""}, podEntry{"ops", "dbg", "sh", "mirror.example.net/x/busybox:1", unreadDigB, ""})
	if err := os.WriteFile(file, []byte(moved), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := evaluate(context.Background(), cfg, base, opt, newScrubber()); c.sig == a.sig {
		t.Errorf("a different state has the same signature: %q", c.sig)
	}
}
