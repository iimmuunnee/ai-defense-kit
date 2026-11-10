package watch

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const (
	d3Dir    = "../../testdata/drills/d3"
	podsCan  = "synthetic-canary-value-do-not-print"
	dgA      = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dgB      = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	dgC      = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	podsKey  = "cluster"
	podsReg  = "registry.example.com"
	podsWeb  = podsReg + "/shop/web:1.4.2"
	podsNext = podsReg + "/shop/web:1.4.3"
)

var podsNow = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

// pj is one container status of a test pod: name, image and imageID.
type pj struct{ name, image, imageID string }

// tp is a pod for the in-memory lists of these tests.
type tp struct {
	ns, name   string
	ownerKind  string
	ownerName  string
	hash       string
	ctrs       []pj
	inits      []pj
	ephs       []pj
	noMetadata bool
	phase      string
}

func (p tp) json() map[string]any {
	st := func(l []pj) []any {
		var out []any
		for _, c := range l {
			out = append(out, map[string]any{"name": c.name, "image": c.image, "imageID": c.imageID,
				"state": map[string]any{"running": map[string]any{"message": podsCan}}})
		}
		return out
	}
	labels := map[string]any{"app": "x", "owner-note": podsCan}
	if p.hash != "" {
		labels["pod-template-hash"] = p.hash
	}
	meta := map[string]any{"name": p.name, "namespace": p.ns, "labels": labels}
	if p.ownerKind != "" {
		meta["ownerReferences"] = []any{map[string]any{"kind": p.ownerKind, "name": p.ownerName, "controller": true}}
	}
	status := map[string]any{"containerStatuses": st(p.ctrs)}
	if p.phase != "" {
		status["phase"] = p.phase
	}
	if p.inits != nil {
		status["initContainerStatuses"] = st(p.inits)
	}
	if p.ephs != nil {
		status["ephemeralContainerStatuses"] = st(p.ephs)
	}
	spec := map[string]any{"containers": []any{map[string]any{"name": "c", "env": []any{map[string]any{"name": "T", "value": podsCan}}, "args": []any{podsCan}}}}
	return map[string]any{"kind": "Pod", "metadata": meta, "spec": spec, "status": status}
}

func podList(pods ...tp) string {
	items := []any{}
	for _, p := range pods {
		items = append(items, p.json())
	}
	b, _ := json.Marshal(map[string]any{"kind": "List", "apiVersion": "v1", "items": items})
	return string(b)
}

func rsPod(name, hash string, c ...pj) tp {
	return tp{ns: "default", name: name, ownerKind: "ReplicaSet", ownerName: "web-" + hash, hash: hash, ctrs: c}
}

func ctr(name, image, digest string) pj {
	return pj{name: name, image: image, imageID: "docker-pullable://" + strings.Split(image, ":")[0] + "@" + digest}
}

// podsFile writes body and gives it a modification time age before podsNow.
func podsFile(t *testing.T, body string, age time.Duration) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pods.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	mt := podsNow.Add(-age)
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatal(err)
	}
	return p
}

func podsTarget(file string, extra map[string]any) Target {
	opts := map[string]any{"file": file}
	for k, v := range extra {
		opts[k] = v
	}
	return Target{Key: podsKey, Kind: kindPods, Options: opts}
}

func observePods(t Target) (Observation, error) {
	return NewPodsObserver(func() time.Time { return podsNow }).Observe(context.Background(), t)
}

func mustPods(t *testing.T, body string, extra map[string]any) (Target, Observation) {
	t.Helper()
	tg := podsTarget(podsFile(t, body, time.Hour), extra)
	obs, err := observePods(tg)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	return tg, obs
}

func TestPodsDigest(t *testing.T) {
	file := filepath.Join(d3Dir, "pods.base.json")
	if err := os.Chtimes(file, podsNow, podsNow); err != nil {
		t.Fatal(err)
	}
	obs, err := observePods(podsTarget(file, nil))
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	for _, k := range []string{"image:default/deployment:web/web", "image:default/statefulset:db/db", "image:default/statefulset:db/init-perms", "image:kube-system/daemonset:node-agent/agent"} {
		if v := obs[k]; !strings.HasPrefix(v, "sha256:") || len(v) != len("sha256:")+64 {
			t.Errorf("%s = %q, want a sha256 digest", k, v)
		}
	}
	if obs["file"] != filepath.ToSlash(file) {
		t.Errorf("file = %q, want the path cleaned, with forward slashes", obs["file"])
	}
	if obs["registry:default/deployment:web/web"] != podsReg {
		t.Errorf("registry = %q", obs["registry:default/deployment:web/web"])
	}
	for k, v := range obs {
		if strings.Contains(k+v, podsCan) {
			t.Errorf("a value from the pod spec reached the observation: %s=%s", k, v)
		}
	}
	// Two replicas, one digest: one value, no comma.
	if strings.Contains(obs["image:default/deployment:web/web"], ",") {
		t.Errorf("replicas with one digest gave %q", obs["image:default/deployment:web/web"])
	}
}

func TestPodsWorkloadNames(t *testing.T) {
	d := ctr("c", podsWeb, dgA)
	cases := []struct {
		name string
		pod  tp
		want string
	}{
		{"replicaset with hash label", tp{ns: "n", name: "web-5c8d7f9b4-xyz12", ownerKind: "ReplicaSet", ownerName: "web-5c8d7f9b4", hash: "5c8d7f9b4", ctrs: []pj{d}}, "image:n/deployment:web/c"},
		{"replicaset without label keeps its name", tp{ns: "n", name: "web-5c8d7f9b4-xyz12", ownerKind: "ReplicaSet", ownerName: "web-5c8d7f9b4", ctrs: []pj{d}}, "image:n/replicaset:web-5c8d7f9b4/c"},
		{"label that is not the suffix keeps the name", tp{ns: "n", name: "p", ownerKind: "ReplicaSet", ownerName: "web-5c8d7f9b4", hash: "other", ctrs: []pj{d}}, "image:n/replicaset:web-5c8d7f9b4/c"},
		{"statefulset", tp{ns: "n", name: "db-0", ownerKind: "StatefulSet", ownerName: "db", ctrs: []pj{d}}, "image:n/statefulset:db/c"},
		{"daemonset", tp{ns: "n", name: "agent-x7k2p", ownerKind: "DaemonSet", ownerName: "agent", ctrs: []pj{d}}, "image:n/daemonset:agent/c"},
		{"job", tp{ns: "n", name: "report-29-abcde", ownerKind: "Job", ownerName: "report-29", ctrs: []pj{d}}, "image:n/job:report-29/c"},
		{"no owner uses the pod name", tp{ns: "n", name: "scratch", ctrs: []pj{d}}, "image:n/pod:scratch/c"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, obs := mustPods(t, podList(c.pod), nil)
			if obs[c.want] != dgA {
				t.Errorf("fields = %v, want %s", obs, c.want)
			}
		})
	}
}

func TestPodsStatusKinds(t *testing.T) {
	p := rsPod("web-1-a", "1", ctr("web", podsWeb, dgA))
	p.inits = []pj{ctr("setup", podsWeb, dgB)}
	p.ephs = []pj{ctr("debugger", "docker.io/library/busybox:1.36", dgC)}
	_, obs := mustPods(t, podList(p), nil)
	if obs["image:default/deployment:web/web"] != dgA || obs["image:default/deployment:web/setup"] != dgB || obs["image:default/deployment:web/debugger"] != dgC {
		t.Errorf("obs = %v", obs)
	}
	if obs["registry:default/deployment:web/debugger"] != "docker.io" {
		t.Errorf("debugger registry = %q", obs["registry:default/deployment:web/debugger"])
	}
}

func TestReplicaNoise(t *testing.T) {
	d := ctr("web", podsWeb, dgA)
	_, a := mustPods(t, podList(rsPod("web-111-aaaaa", "111", d), rsPod("web-111-bbbbb", "111", d)), nil)
	_, b := mustPods(t, podList(rsPod("web-222-ccccc", "222", d), rsPod("web-222-ddddd", "222", d), rsPod("web-222-eeeee", "222", d)), nil)
	// Only the identity (file) differs: the temp paths are different files.
	delete(a, "file")
	delete(b, "file")
	if ch := Diff(podsKey, a, b); len(ch) != 0 {
		t.Errorf("new pod names and a new replica set gave changes: %v", ch)
	}
}

func TestPodsFixtureRollingRestart(t *testing.T) {
	read := func(name string) Observation {
		p := filepath.Join(d3Dir, name)
		if err := os.Chtimes(p, podsNow, podsNow); err != nil {
			t.Fatal(err)
		}
		o, err := observePods(podsTarget(p, nil))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		o["file"] = "pods.json"
		return o
	}
	if ch := Diff(podsKey, read("pods.base.json"), read("pods.rolled.json")); len(ch) != 0 {
		t.Errorf("rolling restart gave changes: %v", ch)
	}
	if ch := Diff(podsKey, read("pods.base.json"), read("pods.digest-changed.json")); len(ch) != 1 || ch[0].Field != "image:default/deployment:web/web" {
		t.Errorf("digest change gave %v", ch)
	}
}

func TestPodsRolloutMixedDigests(t *testing.T) {
	// Pods listed in two orders: the same value.
	p1, p2 := rsPod("web-1-a", "1", ctr("web", podsWeb, dgB)), rsPod("web-2-b", "2", ctr("web", podsNext, dgA))
	_, x := mustPods(t, podList(p1, p2), nil)
	_, y := mustPods(t, podList(p2, p1, p2), nil)
	want := dgA + "," + dgB
	if x["image:default/deployment:web/web"] != want || y["image:default/deployment:web/web"] != want {
		t.Errorf("mixed digests = %q and %q, want %q", x["image:default/deployment:web/web"], y["image:default/deployment:web/web"], want)
	}
}

func TestPodsPendingReplicaUsesTheDigest(t *testing.T) {
	ready := rsPod("web-1-a", "1", ctr("web", podsWeb, dgA))
	pending := rsPod("web-1-b", "1", pj{name: "web", image: podsWeb, imageID: ""})
	_, obs := mustPods(t, podList(ready, pending), nil)
	if obs["image:default/deployment:web/web"] != dgA {
		t.Errorf("obs = %v", obs)
	}
}

func TestPodsImageIDForms(t *testing.T) {
	hex := strings.Repeat("ab12", 16)
	cases := map[string]string{
		"docker-pullable://reg.example.com/a@sha256:" + hex: "sha256:" + hex,
		"reg.example.com/a@sha256:" + hex:                   "sha256:" + hex,
		"docker://sha256:" + hex:                            "sha256:" + hex,
		"sha256:" + hex:                                     "sha256:" + hex,
		"containerd://reg.example.com/a:tag@sha256:" + hex:  "sha256:" + hex,
		"":                               "",
		"reg.example.com/a:1.4":          "",
		"sha256:" + hex[:63]:             "",
		"sha256:" + strings.ToUpper(hex): "",
		"sha256:" + hex + "0":            "",
		"docker-pullable://reg.example.com/a@sha512:" + hex: "",
	}
	for in, want := range cases {
		if got := digestOf(in); got != want {
			t.Errorf("digestOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPodsUnreadContainerIsPartial(t *testing.T) {
	good := rsPod("web-1-a", "1", ctr("web", podsWeb, dgA))
	bad := tp{ns: "default", name: "job-x", ownerKind: "Job", ownerName: "job", ctrs: []pj{{name: "main", image: "reg.example.com/job:latest", imageID: ""}}}
	tg := podsTarget(podsFile(t, podList(good, bad), time.Hour), nil)
	obs, err := observePods(tg)
	if obs != nil {
		t.Errorf("obs = %v, want nil with a PartialError", obs)
	}
	var pe PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want PartialError", err)
	}
	if pe.Obs["image:default/deployment:web/web"] != dgA {
		t.Errorf("the container that was read is missing: %v", pe.Obs)
	}
	for k, v := range pe.Obs {
		if strings.Contains(k, "default/job:job/main") || strings.Contains(v, "latest") {
			t.Errorf("the unread container or its tag entered the observation: %s=%s", k, v)
		}
	}
	if errors.Is(err, ErrStale) {
		t.Errorf("an unread container is not a stale export: %v", err)
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Errorf("error does not say why: %v", err)
	}
	// The unread container is not a removal.
	base := Baseline{Entries: map[string]Observation{podsKey: {"file": filepath.ToSlash(tg.Options["file"].(string)), "image:default/deployment:web/web": dgA, "registry:default/deployment:web/web": podsReg, "image:default/job:job/main": dgB}}}
	o := Compare(base, nil, map[string]error{podsKey: err}, Config{Targets: []Target{tg}})
	if len(o.Changes) != 0 {
		t.Errorf("changes = %v", o.Changes)
	}
	if o.Unverified[podsKey] == "" {
		t.Errorf("an unread container must leave the target unverified")
	}
}

func TestRegistryOf(t *testing.T) {
	cases := map[string]string{
		"nginx":                           "docker.io",
		"nginx:1.25":                      "docker.io",
		"library/nginx":                   "docker.io",
		"docker.io/library/nginx:1.25":    "docker.io",
		"team/app:1":                      "docker.io",
		"Registry.Example.com/team/app:1": "registry.example.com",
		"registry.example.com:5000/team/app@" + dgA: "registry.example.com:5000",
		"localhost/app":                     "localhost",
		"localhost:5000/app":                "localhost:5000",
		"ghcr.io/org/app:1":                 "ghcr.io",
		"sha256:" + strings.Repeat("a", 64): unknownRegistry,
		"":                                  unknownRegistry,
		"bad host/app":                      unknownRegistry,
	}
	for in, want := range cases {
		if got := registryOf(in); got != want {
			t.Errorf("registryOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPodsBadInput(t *testing.T) {
	good := podList(rsPod("web-1-a", "1", ctr("web", podsWeb, dgA)))
	one, _ := json.Marshal(rsPod("web-1-a", "1", ctr("web", podsWeb, dgA)).json())
	cases := map[string]string{
		"empty file":        "",
		"truncated":         good[:len(good)/2],
		"not json":          "<html>",
		"single pod":        string(one),
		"kind not List":     `{"kind":"Deployment","items":[]}`,
		"items not Pod":     `{"kind":"List","items":[{"kind":"Service","metadata":{"name":"a","namespace":"b"}}]}`,
		"item without kind": `{"kind":"List","items":[{"metadata":{"name":"a","namespace":"b"}}]}`,
		"no items":          `{"kind":"List"}`,
		"items null":        `{"kind":"List","items":null}`,
		"items object":      `{"kind":"List","items":{}}`,
		"array on top":      `[]`,
		"trailing data":     good + good,
		"pod without name":  `{"kind":"List","items":[{"kind":"Pod","metadata":{"namespace":"b"}}]}`,
		"pod without ns":    `{"kind":"List","items":[{"kind":"Pod","metadata":{"name":"b"}}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			obs, err := observePods(podsTarget(podsFile(t, body, time.Hour), nil))
			if err == nil {
				t.Fatalf("no error; obs = %v", obs)
			}
			var pe PartialError
			if errors.As(err, &pe) {
				t.Errorf("a wrong shape is a plain error, not partial: %v", err)
			}
			if strings.Contains(err.Error(), podsCan) {
				t.Errorf("error holds a value from the file: %v", err)
			}
		})
	}
	t.Run("single pod error says what to export", func(t *testing.T) {
		_, err := observePods(podsTarget(podsFile(t, string(one), time.Hour), nil))
		if err == nil || !strings.Contains(err.Error(), "kubectl get pods -A -o json") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestStaleExportMissingOrBroken(t *testing.T) {
	if _, err := observePods(podsTarget(filepath.Join(t.TempDir(), "none.json"), nil)); err == nil {
		t.Error("a missing file read as success")
	}
	if _, err := observePods(podsTarget(t.TempDir(), nil)); err == nil {
		t.Error("a directory read as success")
	}
}

func TestPodsEmptyItems(t *testing.T) {
	tg := podsTarget(podsFile(t, `{"kind":"List","apiVersion":"v1","items":[]}`, time.Hour), nil)
	obs, err := observePods(tg)
	if err != nil {
		t.Fatalf("an empty list is valid at check: %v", err)
	}
	if len(obs) != 1 || obs["file"] == "" {
		t.Errorf("obs = %v, want only the identity", obs)
	}
	err = CheckInitial(tg, obs)
	if err == nil || !strings.Contains(err.Error(), podsKey) {
		t.Errorf("CheckInitial = %v, want a refusal naming the key", err)
	}
	// At check it reads as every workload removed.
	base := Baseline{Entries: map[string]Observation{podsKey: {"file": obs["file"], "image:default/deployment:web/web": dgA, "registry:default/deployment:web/web": podsReg}}}
	o := Compare(base, map[string]Observation{podsKey: obs}, nil, Config{Targets: []Target{tg}})
	fs := Findings(o, Config{Targets: []Target{tg}}, nil)
	if len(fs) != 1 || fs[0].ID != "WA-103" || fs[0].Severity != finding.High {
		t.Fatalf("findings = %+v", fs)
	}
	if !strings.Contains(fs[0].Title, "사라") && !strings.Contains(fs[0].Title, "보이지") {
		t.Errorf("a removed container must be worded as removed: %q", fs[0].Title)
	}
}

func TestPodsOptions(t *testing.T) {
	bad := []map[string]any{
		{},
		{"file": ""},
		{"file": 3},
		{"file": "p.json", "kubeconfig": "x"},
		{"file": "p.json", "max_age": "soon"},
		{"file": "p.json", "max_age": "-1h"},
		{"file": "p.json", "max_age": 5},
		{"file": "p.json", "allowed_registries": "docker.io"},
		{"file": "p.json", "allowed_registries": []any{""}},
		{"file": "p.json", "allowed_registries": []any{"a/b"}},
		{"file": "p.json", "allowed_registries": []any{"https://reg.example.com"}},
		{"file": "p.json", "allowed_registries": []any{7}},
	}
	for i, o := range bad {
		if err := validatePodsOptions(o); err == nil {
			t.Errorf("case %d: %v was accepted", i, o)
		}
	}
	good := []map[string]any{
		{"file": "p.json"},
		{"file": "p.json", "max_age": "0"},
		{"file": "p.json", "max_age": "36h", "allowed_registries": []any{"registry.example.com", "Docker.IO", "localhost:5000"}},
	}
	for i, o := range good {
		if err := validatePodsOptions(o); err != nil {
			t.Errorf("case %d: %v", i, err)
		}
	}
	err := validatePodsOptions(map[string]any{"file": "p.json", "kubeconfig": "x"})
	if err == nil || strings.Contains(err.Error(), "x\"") {
		t.Logf("err = %v", err)
	}
}

func TestPodsLoadConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	write := func(s string) {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("targets:\n  - key: c\n    kind: k8s-pods\n    options:\n      file: pods.json\n      allowed_registries: [registry.example.com]\n      max_age: 12h\n")
	if _, err := LoadConfig(p); err != nil {
		t.Errorf("valid config: %v", err)
	}
	write("targets:\n  - key: c\n    kind: k8s-pods\n    options:\n      file: pods.json\n      kubectl: get\n")
	if _, err := LoadConfig(p); err == nil {
		t.Error("an unknown option was accepted")
	}
}

// podsFindings compares cur with base for one target and returns the findings.
func podsFindings(tg Target, base, cur Observation, curErr error) ([]finding.Finding, Outcome) {
	cfg := Config{Targets: []Target{tg}}
	b := Baseline{Entries: map[string]Observation{podsKey: base}}
	var o Outcome
	if curErr != nil {
		o = Compare(b, nil, map[string]error{podsKey: curErr}, cfg)
	} else {
		o = Compare(b, map[string]Observation{podsKey: cur}, nil, cfg)
	}
	return Findings(o, cfg, nil), o
}

func TestUnknownRegistry(t *testing.T) {
	web := rsPod("web-1-a", "1", ctr("web", podsWeb, dgA))
	extra := rsPod("web-1-a", "1", ctr("web", podsWeb, dgA))
	extra.ephs = []pj{ctr("debugger", "docker.io/library/busybox:1.36", dgB)}
	allow := map[string]any{"allowed_registries": []any{podsReg}}

	tg, base := mustPods(t, podList(web), allow)
	_, cur := mustPods(t, podList(extra), allow)
	cur["file"] = base["file"]
	fs, o := podsFindings(tg, base, cur, nil)
	if len(fs) != 1 {
		t.Fatalf("findings = %+v (changes %v)", fs, o.Changes)
	}
	f := fs[0]
	if f.ID != "WA-103" || f.Severity != finding.High || f.Confidence != finding.Certain || f.Location != podsKey {
		t.Errorf("finding = %+v", f)
	}
	text := f.Title + " " + f.Evidence
	if !strings.Contains(text, "허용 목록 밖") || !strings.Contains(text, "docker.io") || !strings.Contains(text, "image:default/deployment:web/debugger") {
		t.Errorf("text lacks the outside-list wording: %s", text)
	}
	if strings.Contains(text, podsCan) {
		t.Error("a value from the pod spec reached a finding")
	}

	// The same change with the registry on the list.
	allow2 := map[string]any{"allowed_registries": []any{podsReg, "DOCKER.io"}}
	tg2 := podsTarget(tg.Options["file"].(string), allow2)
	fs, _ = podsFindings(tg2, base, cur, nil)
	if len(fs) != 1 || fs[0].ID != "WA-103" || !strings.Contains(fs[0].Title+fs[0].Evidence, "허용 목록 안") {
		t.Errorf("inside the list: %+v", fs)
	}
	// Without a list nothing is said about it.
	tg3 := podsTarget(tg.Options["file"].(string), nil)
	fs, _ = podsFindings(tg3, base, cur, nil)
	if len(fs) != 1 || fs[0].ID != "WA-103" || strings.Contains(fs[0].Title+fs[0].Evidence, "허용 목록") {
		t.Errorf("no list: %+v", fs)
	}
}

func TestPodsDigestChangeIsWA103(t *testing.T) {
	allow := map[string]any{"allowed_registries": []any{podsReg}}
	tg, base := mustPods(t, podList(rsPod("web-1-a", "1", ctr("web", podsWeb, dgA))), allow)
	_, cur := mustPods(t, podList(rsPod("web-1-a", "1", ctr("web", podsNext, dgB))), allow)
	cur["file"] = base["file"]
	fs, _ := podsFindings(tg, base, cur, nil)
	if len(fs) != 1 || fs[0].ID != "WA-103" || fs[0].Severity != finding.High {
		t.Fatalf("findings = %+v", fs)
	}
	if !strings.Contains(fs[0].Title+fs[0].Evidence, "허용 목록 안") || !strings.Contains(fs[0].Evidence, dgA) || !strings.Contains(fs[0].Evidence, dgB) {
		t.Errorf("evidence = %q / %q", fs[0].Title, fs[0].Evidence)
	}
}

func TestPodsRegistryOnlyChange(t *testing.T) {
	tg, base := mustPods(t, podList(rsPod("web-1-a", "1", ctr("web", podsWeb, dgA))), nil)
	_, cur := mustPods(t, podList(rsPod("web-1-a", "1", ctr("web", "mirror.example.net/shop/web:1.4.2", dgA))), nil)
	cur["file"] = base["file"]
	fs, _ := podsFindings(tg, base, cur, nil)
	if len(fs) != 1 || fs[0].ID != "WA-103" {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestPodsRemovedContainer(t *testing.T) {
	two := podList(rsPod("web-1-a", "1", ctr("web", podsWeb, dgA)), tp{ns: "default", name: "db-0", ownerKind: "StatefulSet", ownerName: "db", ctrs: []pj{ctr("db", podsWeb, dgB)}})
	tg, base := mustPods(t, two, nil)
	_, cur := mustPods(t, podList(rsPod("web-1-a", "1", ctr("web", podsWeb, dgA))), nil)
	cur["file"] = base["file"]
	fs, _ := podsFindings(tg, base, cur, nil)
	if len(fs) != 1 || fs[0].ID != "WA-103" || fs[0].Severity != finding.High {
		t.Fatalf("findings = %+v", fs)
	}
	if !strings.Contains(fs[0].Title, "사라") && !strings.Contains(fs[0].Title, "보이지") {
		t.Errorf("not worded as removed: %q", fs[0].Title)
	}
}

func TestPodsFileChangeIsWA007(t *testing.T) {
	tg, base := mustPods(t, podList(rsPod("web-1-a", "1", ctr("web", podsWeb, dgA))), nil)
	cur := Observation{}
	for k, v := range base {
		cur[k] = v
	}
	cur["file"] = "other.json"
	fs, _ := podsFindings(tg, base, cur, nil)
	if len(fs) != 1 || fs[0].ID != "WA-007" {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestPodsStaleExport(t *testing.T) {
	body := podList(rsPod("web-1-a", "1", ctr("web", podsWeb, dgA)))
	fresh := podsTarget(podsFile(t, body, time.Hour), nil)
	if _, err := observePods(fresh); err != nil {
		t.Fatalf("an hour-old export with the default limit: %v", err)
	}

	cur := podList(rsPod("web-1-a", "1", ctr("web", podsNext, dgB)))
	oldFile := podsFile(t, cur, 30*time.Hour)
	tg := podsTarget(oldFile, nil)
	obs, err := observePods(tg)
	var pe PartialError
	if obs != nil || !errors.As(err, &pe) || !errors.Is(err, ErrStale) {
		t.Fatalf("obs=%v err=%v, want PartialError wrapping ErrStale", obs, err)
	}
	if pe.Obs["image:default/deployment:web/web"] != dgB {
		t.Errorf("the fields that were read are gone: %v", pe.Obs)
	}
	if strings.Contains(err.Error(), "노드") {
		t.Errorf("an export file is not a node: %v", err)
	}

	_, base := mustPods(t, body, nil)
	base["file"] = pe.Obs["file"]
	fs, o := podsFindings(tg, base, nil, err)
	if len(fs) != 1 || fs[0].ID != "WA-103" || fs[0].Severity != finding.High {
		t.Fatalf("findings = %+v", fs)
	}
	if fs[0].Confidence != finding.Suspect {
		t.Errorf("confidence = %v, want Suspect", fs[0].Confidence)
	}
	if !slices.Contains(o.Stale, podsKey) || o.Unverified[podsKey] == "" {
		t.Errorf("outcome = %+v", o)
	}
	text := fs[0].Title + fs[0].Evidence
	if strings.Contains(text, "노드") || !strings.Contains(text, "내보내") {
		t.Errorf("the stale wording must fit an export file: %s", text)
	}

	// max_age: "0" turns it off, and a longer limit accepts the file.
	for _, v := range []string{"0", "48h"} {
		if _, err := observePods(podsTarget(oldFile, map[string]any{"max_age": v})); err != nil {
			t.Errorf("max_age %s: %v", v, err)
		}
	}
	// A shorter limit rejects an hour-old file.
	if _, err := observePods(podsTarget(podsFile(t, body, time.Hour), map[string]any{"max_age": "30m"})); !errors.Is(err, ErrStale) {
		t.Errorf("max_age 30m: %v", err)
	}
}

func TestPodsFutureFileIsUnverified(t *testing.T) {
	body := podList(rsPod("web-1-a", "1", ctr("web", podsWeb, dgA)))
	p := podsFile(t, body, 0)
	future := podsNow.Add(2 * time.Hour)
	if err := os.Chtimes(p, future, future); err != nil {
		t.Fatal(err)
	}
	obs, err := observePods(podsTarget(p, map[string]any{"max_age": "0"}))
	var pe PartialError
	if obs != nil || !errors.As(err, &pe) || errors.Is(err, ErrStale) {
		t.Fatalf("obs=%v err=%v, want a PartialError that is not ErrStale", obs, err)
	}
	if pe.Obs["image:default/deployment:web/web"] != dgA {
		t.Errorf("pe.Obs = %v", pe.Obs)
	}
	// A small skew is fine.
	soon := podsNow.Add(time.Minute)
	if err := os.Chtimes(p, soon, soon); err != nil {
		t.Fatal(err)
	}
	if _, err := observePods(podsTarget(p, nil)); err != nil {
		t.Errorf("one minute ahead: %v", err)
	}
}

func TestPodsStaleAndUnreadTogether(t *testing.T) {
	bad := tp{ns: "default", name: "x", ctrs: []pj{{name: "c", image: podsWeb}}}
	p := podsFile(t, podList(rsPod("web-1-a", "1", ctr("web", podsWeb, dgA)), bad), 48*time.Hour)
	_, err := observePods(podsTarget(p, nil))
	if !errors.Is(err, ErrStale) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Errorf("the unread container is not mentioned: %v", err)
	}
}

func TestEVMStaleWordingUnchanged(t *testing.T) {
	cfg := Config{Targets: []Target{{Key: "w", Kind: kindEVM}}}
	b := Baseline{Entries: map[string]Observation{"w": {"delegate": ""}}}
	err := PartialError{Obs: Observation{"delegate": "0x00000000000000000000000000000000000000aa"}, Err: staleError{msg: "RPC 1: 최신 블록이 오래되었습니다"}}
	o := Compare(b, nil, map[string]error{"w": err}, cfg)
	fs := Findings(o, cfg, nil)
	if len(fs) != 1 || !strings.Contains(fs[0].Title, "노드 멈춤 의심") || !strings.Contains(fs[0].Evidence, "노드 상태를 먼저 확인하세요") {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestOutsideAllowedRegistries(t *testing.T) {
	allow := map[string]any{"allowed_registries": []any{podsReg}}
	tg, obs := mustPods(t, podList(
		rsPod("web-1-a", "1", ctr("web", podsWeb, dgA)),
		tp{ns: "ops", name: "dbg", ctrs: []pj{ctr("sh", "docker.io/library/busybox:1", dgB)}},
	), allow)
	got := OutsideAllowedRegistries(tg, obs, nil)
	if len(got) != 1 || !strings.Contains(got[0], "ops/pod:dbg/sh") || !strings.Contains(got[0], "docker.io") {
		t.Errorf("got %v", got)
	}
	if got := OutsideAllowedRegistries(tg, obs, map[string]bool{"image:ops/pod:dbg/sh": true}); len(got) != 0 {
		t.Errorf("a container that changed is reported as a finding, not a note: %v", got)
	}
	tg2 := podsTarget(tg.Options["file"].(string), nil)
	if got := OutsideAllowedRegistries(tg2, obs, nil); len(got) != 0 {
		t.Errorf("without a list there is nothing outside it: %v", got)
	}
	if got := OutsideAllowedRegistries(Target{Kind: kindEVM}, Observation{}, nil); len(got) != 0 {
		t.Errorf("other kinds: %v", got)
	}
}

func phased(p tp, phase string) tp { p.phase = phase; return p }

func TestPodsTerminalPhases(t *testing.T) {
	live := phased(rsPod("web-1-bbb", "1", ctr("app", podsNext, dgB)), "Running")
	t.Run("failed beside running is ignored", func(t *testing.T) {
		old := phased(rsPod("web-1-aaa", "1", ctr("app", podsWeb, dgA)), "Failed")
		_, obs := mustPods(t, podList(old, live), nil)
		if obs["image:default/deployment:web/app"] != dgB {
			t.Errorf("obs = %v, want only the live digest", obs)
		}
	})
	t.Run("evicted without a digest beside a live one is not partial", func(t *testing.T) {
		old := phased(rsPod("web-1-aaa", "1", pj{name: "app", image: podsWeb}), "Failed")
		_, obs := mustPods(t, podList(old, live), nil)
		if obs["image:default/deployment:web/app"] != dgB {
			t.Errorf("obs = %v", obs)
		}
	})
	t.Run("succeeded-only job is recorded", func(t *testing.T) {
		job := phased(tp{ns: "ops", name: "deploy-x-abc", ownerKind: "Job", ownerName: "deploy-x", ctrs: []pj{ctr("run", podsWeb, dgC)}}, "Succeeded")
		_, obs := mustPods(t, podList(job), nil)
		if obs["image:ops/job:deploy-x/run"] != dgC {
			t.Errorf("obs = %v", obs)
		}
	})
	t.Run("failed-only workload is recorded", func(t *testing.T) {
		_, obs := mustPods(t, podList(phased(rsPod("web-1-aaa", "1", ctr("app", podsWeb, dgA)), "Failed")), nil)
		if obs["image:default/deployment:web/app"] != dgA {
			t.Errorf("obs = %v", obs)
		}
	})
	t.Run("no phase counts as live", func(t *testing.T) {
		old := phased(rsPod("web-1-aaa", "1", ctr("app", podsWeb, dgA)), "Failed")
		_, obs := mustPods(t, podList(old, rsPod("web-1-bbb", "1", ctr("app", podsNext, dgB))), nil)
		if obs["image:default/deployment:web/app"] != dgB {
			t.Errorf("obs = %v", obs)
		}
	})
	t.Run("live without digest does not fall back to a finished pod", func(t *testing.T) {
		old := phased(rsPod("web-1-aaa", "1", ctr("app", podsWeb, dgA)), "Failed")
		pend := phased(rsPod("web-1-bbb", "1", pj{name: "app", image: podsNext}), "Pending")
		tg := podsTarget(podsFile(t, podList(old, pend), time.Hour), nil)
		_, err := observePods(tg)
		var pe PartialError
		if !errors.As(err, &pe) || pe.Obs["image:default/deployment:web/app"] != "" {
			t.Errorf("err = %v", err)
		}
	})
}

func TestOutcomeObservedIsGeneric(t *testing.T) {
	tg := Target{Key: "r", Kind: kindRepo}
	b := Baseline{Entries: map[string]Observation{"r": {"root": "."}}}
	cfg := Config{Targets: []Target{tg}}
	o := Compare(b, map[string]Observation{"r": {"root": "."}}, nil, cfg)
	if o.Observed["r"]["root"] != "." {
		t.Errorf("Observed = %v", o.Observed)
	}
	o = Compare(b, nil, map[string]error{"r": PartialError{Obs: Observation{"root": "."}, Err: errors.New("x")}}, cfg)
	if o.Observed["r"]["root"] != "." {
		t.Errorf("partial Observed = %v", o.Observed)
	}
}
