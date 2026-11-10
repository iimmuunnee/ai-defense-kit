package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const d3Dir = "../../testdata/drills/d3"

// d3Canary is in the env and args of every pod of the fixtures. It is the
// stand-in for a secret in a pod spec and must never reach any output.
const d3Canary = "synthetic-canary-value-do-not-print"

// d3Export holds the exported pod list that a cron job would rewrite.
type d3Export struct {
	t    *testing.T
	path string
}

func newD3Export(t *testing.T, w *wsp, allowed string, firstFixture string) *d3Export {
	t.Helper()
	e := &d3Export{t: t, path: filepath.Join(t.TempDir(), "pods.json")}
	e.use(firstFixture)
	opts := ""
	if allowed != "" {
		opts = fmt.Sprintf("      allowed_registries: [\"%s\"]\n", allowed)
	}
	cfg := fmt.Sprintf("targets:\n  - key: cluster\n    kind: k8s-pods\n    options:\n      file: \"%s\"\n%s", filepath.ToSlash(e.path), opts)
	if err := os.WriteFile(w.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

// use replaces the export with a fixture, as a new export does.
func (e *d3Export) use(fixture string) {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(d3Dir, fixture))
	if err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(e.path, b, 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func (e *d3Export) age(d time.Duration) {
	e.t.Helper()
	mt := time.Now().Add(-d)
	if err := os.Chtimes(e.path, mt, mt); err != nil {
		e.t.Fatal(err)
	}
}

type d3Finding struct {
	ID         string
	Severity   string
	Confidence string
	Location   string
	Evidence   string
	Title      string
	ExplainKo  string `json:"explain_ko"`
	Fix        string
}

func d3Findings(t *testing.T, out string) []d3Finding {
	t.Helper()
	var rep struct{ Findings []d3Finding }
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return rep.Findings
}

// TestDrillD3 runs the drill against exported pod lists: an unapproved image
// appears, a digest changes, pods are renamed by a rolling restart, and the
// list returns to the baseline. check never talks to a cluster.
func TestDrillD3(t *testing.T) {
	w := newWsp(t)
	exp := newD3Export(t, w, "registry.example.com", "pods.base.json")
	var all strings.Builder
	note := func(out, errs string) { all.WriteString(out + errs) }

	code, out, errs := w.run("init")
	note(out, errs)
	if code != 0 {
		t.Fatalf("init = %d\n%s\n%s", code, out, errs)
	}
	firstCode, first, e := w.run("check", "--format", "json")
	note(first, e)
	if firstCode != 0 {
		t.Fatalf("step 1: code=%d\n%s", firstCode, first)
	}

	// An image from outside the allow list is added to a running pod.
	exp.use("pods.extra-image.json")
	code, out, e = w.run("check", "--format", "json")
	note(out, e)
	fs := d3Findings(t, out)
	if code != 1 || len(fs) != 1 {
		t.Fatalf("step 2: code=%d\n%s", code, out)
	}
	f := fs[0]
	if f.ID != "WA-103" || f.Severity != "high" || f.Location != "cluster" || f.ExplainKo == "" || f.Fix == "" {
		t.Errorf("step 2 finding = %+v", f)
	}
	if !strings.Contains(f.Title+f.Evidence, "허용 목록 밖") || !strings.Contains(f.Evidence, "image:default/deployment:web/debugger") || !strings.Contains(f.Evidence, "docker.io") {
		t.Errorf("step 2 lacks the outside-list wording: %q / %q", f.Title, f.Evidence)
	}

	// The list is back to the baseline: nothing.
	exp.use("pods.base.json")
	lastCode, last, e := w.run("check", "--format", "json")
	note(last, e)
	if lastCode != 0 {
		t.Fatalf("step 3: code=%d\n%s", lastCode, last)
	}
	if a, b := withoutTime(t, first), withoutTime(t, last); a != b {
		t.Errorf("step 3 differs from step 1:\n%s\n%s", a, b)
	}

	// A digest changes under the same tag.
	exp.use("pods.digest-changed.json")
	code, out, e = w.run("check", "--format", "json")
	note(out, e)
	fs = d3Findings(t, out)
	if code != 1 || len(fs) != 1 || fs[0].ID != "WA-103" || !strings.Contains(fs[0].Evidence, "image:default/deployment:web/web") || !strings.Contains(fs[0].Title+fs[0].Evidence, "허용 목록 안") {
		t.Fatalf("step 4: code=%d\n%s", code, out)
	}

	// A rolling restart: new ReplicaSet, new pod names, same image.
	exp.use("pods.rolled.json")
	code, out, e = w.run("check", "--format", "json")
	note(out, e)
	if code != 0 || len(d3Findings(t, out)) != 0 {
		t.Fatalf("step 5 (rolling restart): code=%d\n%s", code, out)
	}

	// A file that is too old: what it says may be behind, so the target is
	// unverified (2), and a change in it is reported with lower confidence (1).
	exp.use("pods.base.json")
	exp.age(48 * time.Hour)
	code, out, e = w.run("check", "--format", "json")
	note(out, e)
	if code != 2 || len(d3Findings(t, out)) != 0 {
		t.Fatalf("stale without change: code=%d\n%s", code, out)
	}
	exp.use("pods.extra-image.json")
	exp.age(48 * time.Hour)
	code, out, e = w.run("check", "--format", "json")
	note(out, e)
	fs = d3Findings(t, out)
	if code != 1 || len(fs) != 1 || fs[0].ID != "WA-103" || fs[0].Confidence != "suspect" || strings.Contains(fs[0].Title, "노드") {
		t.Fatalf("stale with change: code=%d\n%s", code, out)
	}
	if code, _, errs := w.run("accept", "cluster", "--note", "시험"); code != 2 {
		t.Errorf("accept on a stale export = %d\n%s", code, errs)
	}

	// A file that is gone cannot be verified.
	if err := os.Remove(exp.path); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := w.run("check", "--format", "json"); code != 2 {
		t.Errorf("missing export: code=%d", code)
	}

	if strings.Contains(all.String(), d3Canary) {
		t.Error("a value from the pod spec reached the output")
	}
}

func TestDrillD3AcceptAndNotes(t *testing.T) {
	w := newWsp(t)
	exp := newD3Export(t, w, "registry.example.com", "pods.base.json")
	if code, out, errs := w.run("init"); code != 0 || strings.Contains(errs, "allowed_registries") {
		t.Fatalf("init = %d\n%s\n%s", code, out, errs)
	}
	// A debugging container from docker.io appears: a finding, and accept takes it.
	exp.use("pods.extra-image.json")
	if code, out, _ := w.run("check", "--format", "json"); code != 1 {
		t.Fatalf("check = %d\n%s", code, out)
	}
	code, out, errs := w.run("accept", "cluster", "--note", "디버깅 승인", "--expect", "image:default/deployment:web/debugger=sha256:"+strings.Repeat("0", 64))
	if code != 2 {
		t.Fatalf("accept with a wrong --expect = %d\n%s\n%s", code, out, errs)
	}
	code, out, errs = w.run("accept", "cluster", "--note", "디버깅 승인")
	if code != 0 {
		t.Fatalf("accept = %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "allowed_registries") || !strings.Contains(errs, "default/deployment:web/debugger") {
		t.Errorf("accept did not warn about the image outside the list:\n%s", errs)
	}
	// In the baseline or not, it is outside the list: accept does not silence it.
	code, out, errs = w.run("check", "--format", "json")
	if fs := d3Findings(t, out); code != 1 || len(fs) != 1 || fs[0].ID != "WA-103" || !strings.Contains(fs[0].Evidence, "허용 목록 밖") {
		t.Fatalf("check: code=%d\n%s\n%s", code, out, errs)
	}
}

func TestDrillD3InitWarnsOutsideList(t *testing.T) {
	w := newWsp(t)
	newD3Export(t, w, "registry.example.com", "pods.extra-image.json")
	code, out, errs := w.run("init")
	if code != 0 || !strings.Contains(errs, "경고") || !strings.Contains(errs, "allowed_registries") || !strings.Contains(errs, "default/deployment:web/debugger") {
		t.Errorf("init = %d\n%s\n%s", code, out, errs)
	}
}

func TestDrillD3InitRefusals(t *testing.T) {
	w := newWsp(t)
	exp := newD3Export(t, w, "", "pods.base.json")
	if err := os.WriteFile(exp.path, []byte(`{"kind":"List","apiVersion":"v1","items":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs := w.run("init")
	if code != 2 || !strings.Contains(errs, "cluster") {
		t.Errorf("empty list: init = %d\n%s", code, errs)
	}
	if err := os.WriteFile(exp.path, []byte(`{"kind":"Pod","metadata":{"name":"a","namespace":"b"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errs = w.run("init")
	if code != 2 || !strings.Contains(errs, "kubectl get pods -A -o json") {
		t.Errorf("single pod: init = %d\n%s", code, errs)
	}
	if _, err := os.Stat(w.base); err == nil {
		t.Error("a baseline was written")
	}
}

// A pod left over from an old rollout (Failed) beside the live replica must
// not make a normal deploy look like a change.
func TestDrillD3LeftoverFailedPod(t *testing.T) {
	w := newWsp(t)
	exp := newD3Export(t, w, "", "pods.base.json")
	if code, out, errs := w.run("init"); code != 0 {
		t.Fatalf("init = %d\n%s\n%s", code, out, errs)
	}
	b, err := os.ReadFile(exp.path)
	if err != nil {
		t.Fatal(err)
	}
	var list map[string]any
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatal(err)
	}
	items := list["items"].([]any)
	old := map[string]any{}
	raw, _ := json.Marshal(items[0])
	_ = json.Unmarshal(raw, &old)
	old["metadata"].(map[string]any)["name"] = "web-7d4b9c6f5-evicted"
	st := old["status"].(map[string]any)
	st["phase"] = "Failed"
	for _, c := range st["containerStatuses"].([]any) {
		c.(map[string]any)["imageID"] = "docker-pullable://registry.example.com/shop/web@sha256:" + strings.Repeat("1", 64)
	}
	list["items"] = append(items, old)
	out, _ := json.Marshal(list)
	if err := os.WriteFile(exp.path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, o, _ := w.run("check", "--format", "json"); code != 0 {
		t.Fatalf("check = %d\n%s", code, o)
	}
}
