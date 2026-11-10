package watch

import (
	"strings"
	"testing"
)

// Every run of a CronJob is a Job with a new name, and a static pod carries its
// node's name. Neither may read as a new workload.
func TestPodsWorkloadCronAndStatic(t *testing.T) {
	d := ctr("c", podsWeb, dgA)
	cases := []struct {
		name string
		pod  tp
		want string
	}{
		{"job of a cronjob, 8 digits", tp{ns: "n", name: "backup-29000100-abcde", ownerKind: "Job", ownerName: "backup-29000100", ctrs: []pj{d}}, "image:n/job:backup/c"},
		{"job of a cronjob, 10 digits", tp{ns: "n", name: "backup-2900010000-abcde", ownerKind: "Job", ownerName: "backup-2900010000", ctrs: []pj{d}}, "image:n/job:backup/c"},
		{"job with 7 digits keeps its name", tp{ns: "n", name: "backup-2900010-abcde", ownerKind: "Job", ownerName: "backup-2900010", ctrs: []pj{d}}, "image:n/job:backup-2900010/c"},
		{"job that is only digits keeps its name", tp{ns: "n", name: "29000100-abcde", ownerKind: "Job", ownerName: "29000100", ctrs: []pj{d}}, "image:n/job:29000100/c"},
		{"job with letters after the digits keeps its name", tp{ns: "n", name: "b-29000100x-abcde", ownerKind: "Job", ownerName: "b-29000100x", ctrs: []pj{d}}, "image:n/job:b-29000100x/c"},
		{"digits on another kind of owner stay", tp{ns: "n", name: "db-29000100-0", ownerKind: "StatefulSet", ownerName: "db-29000100", ctrs: []pj{d}}, "image:n/statefulset:db-29000100/c"},
		{"static pod loses its node", tp{ns: "kube-system", name: "kube-apiserver-node-1", ownerKind: "Node", ownerName: "node-1", ctrs: []pj{d}}, "image:kube-system/node:kube-apiserver/c"},
		{"pod of a node without the suffix keeps the pod name", tp{ns: "kube-system", name: "etcd", ownerKind: "Node", ownerName: "node-1", ctrs: []pj{d}}, "image:kube-system/node:etcd/c"},
		{"pod named just like its node keeps the pod name", tp{ns: "kube-system", name: "node-1", ownerKind: "Node", ownerName: "node-1", ctrs: []pj{d}}, "image:kube-system/node:node-1/c"},
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

func TestPodsCronJobRunsAreOneWorkload(t *testing.T) {
	run := func(job, pod string) tp {
		return phased(tp{ns: "ops", name: pod, ownerKind: "Job", ownerName: job, ctrs: []pj{ctr("c", podsWeb, dgA)}}, "Succeeded")
	}
	_, a := mustPods(t, podList(run("backup-29000100", "backup-29000100-aaaaa")), nil)
	_, b := mustPods(t, podList(run("backup-29000105", "backup-29000105-bbbbb")), nil)
	b["file"] = a["file"]
	if ch := Diff("k", a, b); len(ch) != 0 {
		t.Errorf("a new run of the same CronJob with the same digest reads as %v", ch)
	}
	// The same image on another node is the same static pod.
	static := func(node string) tp {
		return tp{ns: "kube-system", name: "kube-proxy-" + node, ownerKind: "Node", ownerName: node, ctrs: []pj{ctr("c", podsWeb, dgA)}}
	}
	_, s := mustPods(t, podList(static("node-1"), static("node-2")), nil)
	if s["image:kube-system/node:kube-proxy/c"] != dgA {
		t.Errorf("static pods = %v", s)
	}
}

func TestCronJobLimitIsInTheTexts(t *testing.T) {
	for _, p := range []string{"../../docs/watch.md", "../../explain/WA-103.md"} {
		s := readText(t, p)
		for _, want := range []string{"CronJob", "8자리"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s lacks %q", p, want)
			}
		}
	}
	if s := readText(t, "../../docs/watch.md"); !strings.Contains(s, "같은 묶음") {
		t.Error("docs/watch.md does not say that a Job really named with such digits is grouped with its siblings")
	}
}
