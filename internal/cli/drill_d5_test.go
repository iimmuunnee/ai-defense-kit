package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const d5Dir = "../../testdata/drills/d5"

// 훈련 D5: 받은 과제 저장소의 .vscode/tasks.json이 폴더를 열면 명령을 돌리게 해 둔다.
// 예제의 명령은 echo뿐이다. 기존 AR 규칙이 이를 알리는지 본다.
func TestDrillD5(t *testing.T) {
	for _, extra := range [][]string{nil, {"--untrusted"}} {
		fs, se := scanFakeAssignment(t, d5Dir, extra...)
		var ar []string
		for _, f := range fs {
			if strings.HasPrefix(f.ID, "AR-") {
				ar = append(ar, f.ID)
				if !strings.Contains(f.Evidence, "echo adk-drill-d5") {
					t.Errorf("%v: evidence does not show the command: %q", extra, f.Evidence)
				}
			}
		}
		if len(ar) != 1 || ar[0] != "AR-001" {
			t.Errorf("%v: AR findings = %v, want [AR-001]\n%s", extra, ar, se)
		}
	}
}

// 받은 저장소가 자기 .adkignore로 이 결과를 숨겨도, --untrusted로 점검하면 나온다.
func TestDrillD5HiddenByOwnIgnoreFile(t *testing.T) {
	app := filepath.Join(t.TempDir(), "app")
	copyTree(t, d5Dir, app)
	tmp := t.TempDir()
	if code, _, se := runCLI(t, "scan", app, "--format", "json", "--out", tmp, "--offline"); code == 2 {
		t.Fatalf("exit 2: %s", se)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "adk-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct {
			ID          string `json:"id"`
			Fingerprint string `json:"fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	fp := ""
	for _, f := range rep.Findings {
		if f.ID == "AR-001" {
			fp = f.Fingerprint
		}
	}
	if fp == "" {
		t.Fatalf("no AR-001 in report: %s", b)
	}
	if err := os.WriteFile(filepath.Join(app, ".adkignore"), []byte(fp+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, se := scanFakeAssignment(t, app)
	for _, f := range fs {
		if f.ID == "AR-001" {
			t.Errorf("default scan should hide AR-001")
		}
	}
	if !strings.Contains(se, "숨겼습니다") {
		t.Errorf("no hidden-finding warning:\n%s", se)
	}
	fs, _ = scanFakeAssignment(t, app, "--untrusted")
	found := false
	for _, f := range fs {
		found = found || f.ID == "AR-001"
	}
	if !found {
		t.Errorf("--untrusted lacks AR-001: %+v", fs)
	}
}
