package watch

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const podsEvil = "evil.example.net"

func jobPod(ns, owner, pod, phase string, c ...pj) tp {
	return phased(tp{ns: ns, name: pod, ownerKind: "Job", ownerName: owner, ctrs: c}, phase)
}

// Workloads of different kinds never share a field, whatever their names.
func TestPodsKindsNeverMerge(t *testing.T) {
	dep := phased(rsPod("web-5c8d7f9b4-a", "5c8d7f9b4", ctr("web", podsWeb, dgA)), "Running")
	t.Run("a job with a numeric suffix beside a deployment", func(t *testing.T) {
		job := jobPod("default", "web-12345678", "web-12345678-x", "Succeeded", ctr("web", podsEvil+"/x/web:1", dgB))
		_, obs := mustPods(t, podList(dep, job), nil)
		if obs["image:default/deployment:web/web"] != dgA {
			t.Errorf("deployment = %q, want only %s", obs["image:default/deployment:web/web"], dgA)
		}
		if obs["image:default/job:web/web"] != dgB || obs["registry:default/job:web/web"] != podsEvil {
			t.Errorf("job fields missing: %v", obs)
		}
	})
	t.Run("a job named exactly like the deployment", func(t *testing.T) {
		job := jobPod("default", "web", "web-x", "Succeeded", ctr("web", podsEvil+"/x/web:1", dgB))
		_, obs := mustPods(t, podList(dep, job), nil)
		if obs["image:default/deployment:web/web"] != dgA || obs["image:default/job:web/web"] != dgB {
			t.Errorf("obs = %v", obs)
		}
	})
	t.Run("a statefulset and a deployment of one name", func(t *testing.T) {
		sts := tp{ns: "default", name: "web-0", ownerKind: "StatefulSet", ownerName: "web", ctrs: []pj{ctr("web", podsNext, dgB)}}
		_, obs := mustPods(t, podList(dep, sts), nil)
		if obs["image:default/deployment:web/web"] != dgA || obs["image:default/statefulset:web/web"] != dgB {
			t.Errorf("obs = %v", obs)
		}
	})
	t.Run("a replicaset kept whole is not the deployment", func(t *testing.T) {
		rs := tp{ns: "default", name: "web-x", ownerKind: "ReplicaSet", ownerName: "web", ctrs: []pj{ctr("web", podsNext, dgB)}}
		_, obs := mustPods(t, podList(dep, rs), nil)
		if obs["image:default/deployment:web/web"] != dgA || obs["image:default/replicaset:web/web"] != dgB {
			t.Errorf("obs = %v", obs)
		}
	})
}

// A finished run of a Job is not dropped because another run is live.
func TestPodsJobKeepsFinishedDigests(t *testing.T) {
	t.Run("failed beside a live run, different digests", func(t *testing.T) {
		failed := jobPod("ops", "backup-99999999", "backup-99999999-a", "Failed", ctr("c", podsWeb, dgA))
		live := jobPod("ops", "backup-88888888", "backup-88888888-b", "Running", ctr("c", podsNext, dgB))
		_, obs := mustPods(t, podList(failed, live), nil)
		if got := obs["image:ops/job:backup/c"]; got != dgA+","+dgB {
			t.Errorf("value = %q, want both digests", got)
		}
	})
	t.Run("same digest is one value", func(t *testing.T) {
		a := jobPod("ops", "backup-99999999", "backup-99999999-a", "Succeeded", ctr("c", podsWeb, dgA))
		b := jobPod("ops", "backup-88888888", "backup-88888888-b", "Running", ctr("c", podsWeb, dgA))
		_, obs := mustPods(t, podList(a, b), nil)
		if got := obs["image:ops/job:backup/c"]; got != dgA {
			t.Errorf("value = %q", got)
		}
	})
	t.Run("a finished run without a digest does not count", func(t *testing.T) {
		a := jobPod("ops", "backup-99999999", "backup-99999999-a", "Failed", pj{name: "c", image: podsEvil + "/x:1"})
		b := jobPod("ops", "backup-88888888", "backup-88888888-b", "Running", ctr("c", podsWeb, dgA))
		_, obs := mustPods(t, podList(a, b), nil)
		if obs["image:ops/job:backup/c"] != dgA || obs["registry:ops/job:backup/c"] != podsReg {
			t.Errorf("obs = %v", obs)
		}
	})
	t.Run("a live run without a digest beside a finished one with a digest", func(t *testing.T) {
		a := jobPod("ops", "backup-99999999", "backup-99999999-a", "Succeeded", ctr("c", podsWeb, dgA))
		b := jobPod("ops", "backup-88888888", "backup-88888888-b", "Pending", pj{name: "c", image: podsNext})
		tg := podsTarget(podsFile(t, podList(a, b), time.Hour), nil)
		obs, err := observePods(tg)
		if err != nil {
			var pe PartialError
			if errors.As(err, &pe) {
				t.Fatalf("the workload has a digest, yet it is partial: %v", err)
			}
			t.Fatal(err)
		}
		if obs["image:ops/job:backup/c"] != dgA {
			t.Errorf("obs = %v", obs)
		}
	})
	t.Run("a finished-only job with no digest stays out", func(t *testing.T) {
		a := jobPod("ops", "backup-99999999", "backup-99999999-a", "Failed", pj{name: "c", image: podsWeb})
		_, obs := mustPods(t, podList(a), nil)
		for k := range obs {
			if strings.HasPrefix(k, "image:") {
				t.Errorf("unexpected field %s", k)
			}
		}
	})
	t.Run("other kinds still ignore finished pods beside a live one", func(t *testing.T) {
		old := phased(tp{ns: "d", name: "db-0", ownerKind: "StatefulSet", ownerName: "db", ctrs: []pj{ctr("c", podsWeb, dgA)}}, "Failed")
		live := tp{ns: "d", name: "db-1", ownerKind: "StatefulSet", ownerName: "db", ctrs: []pj{ctr("c", podsNext, dgB)}}
		_, obs := mustPods(t, podList(old, live), nil)
		if obs["image:d/statefulset:db/c"] != dgB {
			t.Errorf("obs = %v", obs)
		}
	})
}

// The allow list covers the registry of every digest in the workload, also of
// a finished Job run grouped with a clean sibling.
func TestPodsJobRunOutsideTheListIsReported(t *testing.T) {
	allow := map[string]any{"allowed_registries": []any{podsReg}}
	clean := jobPod("ops", "backup-88888888", "backup-88888888-b", "Running", ctr("c", podsWeb, dgA))
	evil := jobPod("ops", "backup-99999999", "backup-99999999-a", "Succeeded", ctr("c", podsEvil+"/x/c:1", dgB))
	tg, obs := mustPods(t, podList(clean, evil), allow)
	if got := obs["registry:ops/job:backup/c"]; got != podsEvil+","+podsReg {
		t.Fatalf("registries = %q", got)
	}
	if got := OutsideAllowedRegistries(tg, obs, nil); len(got) != 1 || !strings.Contains(got[0], podsEvil) {
		t.Errorf("OutsideAllowedRegistries = %v", got)
	}
	fs, _ := podsFindings(tg, obs, obs, nil)
	if len(fs) != 1 || fs[0].ID != "WA-103" || fs[0].Severity != finding.High || !strings.Contains(fs[0].Title+fs[0].Evidence, "허용 목록 밖") || !strings.Contains(fs[0].Evidence, podsEvil) {
		t.Errorf("findings = %+v", fs)
	}
}

func TestPodsOwnerKindIsCleanInFieldNames(t *testing.T) {
	d := ctr("c", podsWeb, dgA)
	cases := []struct{ kind, want string }{
		{"Evil/Kind\n:x ../", "image:n/evilkindx..:w/c"},
		{"Cron_Job", "image:n/cronjob:w/c"},
		{"Argo.Rollout-2", "image:n/argo.rollout-2:w/c"},
		{"Deployment", "image:n/deployment-other:w/c"},
		{"Stateful_Set", "image:n/statefulset-other:w/c"},
		{"job", "image:n/job-other:w/c"},
		{"///", "image:n/unknown:w/c"},
	}
	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			_, obs := mustPods(t, podList(tp{ns: "n", name: "p", ownerKind: c.kind, ownerName: "w", ctrs: []pj{d}}), nil)
			if obs[c.want] != dgA {
				t.Errorf("fields = %v, want %s", obs, c.want)
			}
		})
	}
}

func TestKindsAreInTheTexts(t *testing.T) {
	for _, p := range []string{"../../docs/watch.md", "../../explain/WA-103.md", "../../fixes/WA-103/watch.md"} {
		s := readText(t, p)
		if !strings.Contains(s, "<종류>:<워크로드>") {
			t.Errorf("%s lacks the field name with the kind", p)
		}
		if strings.Contains(s, "<네임스페이스>/<워크로드>/") {
			t.Errorf("%s still shows the field name without the kind", p)
		}
	}
	docs := readText(t, "../../docs/watch.md")
	for _, want := range []string{"묶이지 않습니다", "끝난 실행도", "옛 digest와 새 digest", "pod-template-hash` 라벨과 맞아"} {
		if !strings.Contains(docs, want) {
			t.Errorf("docs/watch.md lacks %q", want)
		}
	}
	if strings.Contains(docs, "digest는 쉼표로 이어지므로 숨지는 않습니다") {
		t.Error("docs/watch.md still claims grouped digests cannot hide")
	}
}
