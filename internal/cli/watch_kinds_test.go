package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// kindPod is a pod with one owner, for exports that tell kinds apart.
func kindPod(ns, name, ownerKind, ownerName, hash, phase, ctr, image, digest string) map[string]any {
	labels := map[string]any{}
	if hash != "" {
		labels["pod-template-hash"] = hash
	}
	return map[string]any{"kind": "Pod", "metadata": map[string]any{
		"name": name, "namespace": ns, "labels": labels,
		"ownerReferences": []any{map[string]any{"kind": ownerKind, "name": ownerName, "controller": true}},
	}, "status": map[string]any{"phase": phase, "containerStatuses": []any{map[string]any{
		"name": ctr, "image": image, "imageID": "docker-pullable://" + image + "@" + digest}}}}
}

func kindList(t *testing.T, pods ...map[string]any) string {
	t.Helper()
	items := []any{}
	for _, p := range pods {
		items = append(items, p)
	}
	b, err := json.Marshal(map[string]any{"kind": "List", "items": items})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A finished Job from outside the allow list, named like the live deployment,
// must not vanish into it.
func TestWatchFinishedJobNamedLikeADeploymentIsReported(t *testing.T) {
	dep := kindPod("default", "web-5c8d7f9b4-a", "ReplicaSet", "web-5c8d7f9b4", "5c8d7f9b4", "Running", "web", "registry.example.com/web:1", unreadDigA)
	w, file := podsWsp(t, "      allowed_registries: [\"registry.example.com\"]\n", kindList(t, dep))
	mustInit(t, w)
	if code, out, _ := w.run("check", "--format", "json"); code != 0 {
		t.Fatalf("baseline: code=%d\n%s", code, out)
	}
	for _, job := range []string{"web-12345678", "web"} {
		evil := kindPod("default", job+"-xyz", "Job", job, "", "Succeeded", "web", "evil.example.net/x/web:1", unreadDigB)
		if err := os.WriteFile(file, []byte(kindList(t, dep, evil)), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, errs := w.run("check", "--format", "json")
		fs := d3Findings(t, out)
		if code != 1 || len(fs) == 0 || fs[0].ID != "WA-103" || !strings.Contains(fs[0].Evidence, "default/job:web/web") {
			t.Errorf("job %s: code=%d\n%s\n%s", job, code, out, errs)
		}
	}
}
