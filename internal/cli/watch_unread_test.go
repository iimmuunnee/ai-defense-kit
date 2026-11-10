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

const (
	unreadDigA = "sha256:" + "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	unreadDigB = "sha256:" + "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
)

// podEntry is one pod of a test export; an empty digest is a container whose
// image was not pulled yet.
type podEntry struct{ ns, name, ctr, image, digest, phase string }

func podsJSON(pods ...podEntry) string {
	items := []any{}
	for _, p := range pods {
		id := ""
		if p.digest != "" {
			id = "docker-pullable://" + p.image + "@" + p.digest
		}
		st := map[string]any{"containerStatuses": []any{map[string]any{"name": p.ctr, "image": p.image, "imageID": id}}}
		if p.phase != "" {
			st["phase"] = p.phase
		}
		items = append(items, map[string]any{"kind": "Pod", "metadata": map[string]any{"name": p.name, "namespace": p.ns}, "status": st})
	}
	b, _ := json.Marshal(map[string]any{"kind": "List", "items": items})
	return string(b)
}

func podsWsp(t *testing.T, opts string, body string) (*wsp, string) {
	t.Helper()
	w := newWsp(t)
	file := filepath.Join(t.TempDir(), "pods.json")
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf("targets:\n  - key: cluster\n    kind: k8s-pods\n    options:\n      file: \"%s\"\n%s", filepath.ToSlash(file), opts)
	if err := os.WriteFile(w.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return w, file
}

func baselineEntry(t *testing.T, w *wsp, key string) map[string]string {
	t.Helper()
	var b struct {
		Entries map[string]map[string]string `json:"entries"`
	}
	if err := json.Unmarshal([]byte(readFile(t, w.base)), &b); err != nil {
		t.Fatal(err)
	}
	return b.Entries[key]
}

func TestWatchInitRecordsWhatWasReadAndNamesTheRest(t *testing.T) {
	web := podEntry{"prod", "web", "app", "reg.example.com/web", unreadDigA, ""}
	pend := podEntry{"other", "stuck", "main", "reg.example.com/stuck", "", ""}
	w, file := podsWsp(t, "", podsJSON(web, pend))
	code, out, errs := w.run("init")
	if code != 0 {
		t.Fatalf("init = %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "경고") || !strings.Contains(errs, "other/pod:stuck/main") {
		t.Errorf("init did not name the unread container:\n%s", errs)
	}
	e := baselineEntry(t, w, "cluster")
	if e["image:prod/pod:web/app"] != unreadDigA {
		t.Errorf("the container that was read is missing: %v", e)
	}
	if _, has := e["image:other/pod:stuck/main"]; has {
		t.Errorf("the unread container entered the baseline: %v", e)
	}
	// check stays exit 2 while it is unread.
	code, out, errs = w.run("check", "--format", "json")
	if code != 2 || len(d3Findings(t, out)) != 0 || !strings.Contains(out, "확인 못 함") {
		t.Errorf("check while unread: code=%d\n%s\n%s", code, out, errs)
	}
	// Once it has a digest it is new to the baseline: WA-103, as it must be.
	pend.digest = unreadDigB
	if err := os.WriteFile(file, []byte(podsJSON(web, pend)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = w.run("check", "--format", "json")
	fs := d3Findings(t, out)
	if code != 1 || len(fs) != 1 || fs[0].ID != "WA-103" || !strings.Contains(fs[0].Evidence, "image:other/pod:stuck/main") {
		t.Errorf("after the digest came: code=%d\n%s", code, out)
	}
}

func TestWatchInitRefusesWhenNothingWasRead(t *testing.T) {
	w, _ := podsWsp(t, "", podsJSON(podEntry{"other", "stuck", "main", "reg.example.com/stuck", "", ""}))
	code, out, errs := w.run("init")
	if code != 2 || !strings.Contains(errs, "cluster") {
		t.Errorf("init = %d\n%s\n%s", code, out, errs)
	}
	if fileExists(w.base) {
		t.Error("a baseline was written")
	}
}

func TestWatchAcceptAdoptsWhatWasReadAndKeepsTheRest(t *testing.T) {
	web := podEntry{"prod", "web", "app", "reg.example.com/web", unreadDigA, ""}
	job := podEntry{"ops", "job", "main", "reg.example.com/job", unreadDigA, ""}
	w, file := podsWsp(t, "", podsJSON(web, job))
	mustInit(t, w)
	// A reviewed deploy, while a pod elsewhere has not pulled its image.
	web.digest = unreadDigB
	job.digest = ""
	if err := os.WriteFile(file, []byte(podsJSON(web, job)), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := w.run("check", "--format", "json"); code != 1 {
		t.Fatalf("check = %d", code)
	}
	code, out, errs := w.run("accept", "cluster", "--note", "검토한 배포", "--expect", "image:prod/pod:web/app="+unreadDigB)
	if code != 0 {
		t.Fatalf("accept = %d\n%s\n%s", code, out, errs)
	}
	e := baselineEntry(t, w, "cluster")
	if e["image:prod/pod:web/app"] != unreadDigB {
		t.Errorf("the read value was not adopted: %v", e)
	}
	if e["image:ops/pod:job/main"] != unreadDigA || e["registry:ops/pod:job/main"] == "" {
		t.Errorf("the old value of the unread container was not kept: %v", e)
	}
	if !strings.Contains(errs, "image:ops/pod:job/main") || !strings.Contains(errs, "그대로") {
		t.Errorf("accept did not say what it kept:\n%s", errs)
	}
	var h historyEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(readFile(t, w.history))), &h); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.Changes {
		if strings.Contains(c.Field, "ops/pod:job") {
			t.Errorf("the history shows a change of a kept field: %+v", c)
		}
	}
	// Still unread, and now clean of findings.
	code, out, _ = w.run("check", "--format", "json")
	if code != 2 || len(d3Findings(t, out)) != 0 {
		t.Errorf("check after accept: code=%d\n%s", code, out)
	}
	// A second accept has nothing to adopt, but still says what is unread.
	code, out, errs = w.run("accept", "cluster", "--note", "다시")
	if code != 0 || !strings.Contains(errs, "image:ops/pod:job/main") {
		t.Errorf("second accept = %d\n%s\n%s", code, out, errs)
	}
	// A value that was not read cannot be vouched for.
	before := readFile(t, w.base)
	code, _, errs = w.run("accept", "cluster", "--note", "x", "--expect", "image:ops/pod:job/main="+unreadDigA)
	if code != 2 || readFile(t, w.base) != before {
		t.Errorf("--expect on an unread field: code=%d\n%s", code, errs)
	}
}

func TestWatchUnreadStaleOrOtherPartialIsStillRefused(t *testing.T) {
	web := podEntry{"prod", "web", "app", "reg.example.com/web", unreadDigA, ""}
	job := podEntry{"ops", "job", "main", "reg.example.com/job", "", ""}
	w, file := podsWsp(t, "", podsJSON(web, job))
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := w.run("init"); code != 2 || fileExists(w.base) {
		t.Errorf("init on a stale export = %d\n%s", code, errs)
	}
	if err := os.Chtimes(file, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	mustInit(t, w)
	before := readFile(t, w.base)
	web.digest = unreadDigB
	if err := os.WriteFile(file, []byte(podsJSON(web, job)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := w.run("accept", "cluster", "--note", "x"); code != 2 || readFile(t, w.base) != before {
		t.Errorf("accept on a stale export = %d\n%s", code, errs)
	}
}
