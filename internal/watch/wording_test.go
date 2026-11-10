package watch

import (
	"strings"
	"testing"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

// M7: a pod that finished is not running.
func TestNewContainerTitleDoesNotSayItIsRunning(t *testing.T) {
	tg := podsTarget("p.json", nil)
	base := Observation{"file": "p.json"}
	cur := Observation{"file": "p.json", "image:ops/job/c": dgA, "registry:ops/job/c": podsReg}
	fs, _ := podsFindings(tg, base, cur, nil)
	if len(fs) != 1 || strings.Contains(fs[0].Title, "실행 중") || !strings.Contains(fs[0].Title, "목록에 나타났습니다") {
		t.Errorf("findings = %+v", fs)
	}
	if s := readText(t, "../../explain/WA-103.md"); strings.Contains(s, "새 컨테이너가 실행 중이라는 뜻") {
		t.Error("explain/WA-103.md says a new entry is running")
	}
}

// M8: a change of the flag word alone is not proof that the signers changed.
func TestFlagsChangeIsWordedAsWhatItIs(t *testing.T) {
	tg := Target{Key: "x", Kind: kindXRPL, Options: map[string]any{"address": "r"}}
	cfg := Config{Targets: []Target{tg}}
	o := Outcome{Changes: []Change{{Key: "x", Field: "flags", Old: "0", New: "1048576"}}}
	fs := Findings(o, cfg, nil)
	if len(fs) != 1 || fs[0].ID != "WA-002" || fs[0].Severity != finding.Critical {
		t.Fatalf("findings = %+v", fs)
	}
	if !strings.Contains(fs[0].Evidence, "0x00000000") || !strings.Contains(fs[0].Evidence, "0x00100000") || !strings.Contains(fs[0].Evidence, "1048576") {
		t.Errorf("evidence = %q", fs[0].Evidence)
	}
	for _, want := range []string{"무해", "lsfDisableMaster", "0x00100000"} {
		if !strings.Contains(fs[0].Title, want) {
			t.Errorf("title lacks %q: %s", want, fs[0].Title)
		}
	}
	if strings.Contains(fs[0].Title, "서명 권한") {
		t.Errorf("title still claims the signing authority changed: %s", fs[0].Title)
	}
	// A value that is not a number is shown as it is.
	o = Outcome{Changes: []Change{{Key: "x", Field: "flags", Old: "", New: "abc"}}}
	if fs := Findings(o, cfg, nil); len(fs) != 1 || !strings.Contains(fs[0].Evidence, "(없음) -> abc") {
		t.Errorf("findings = %+v", fs)
	}
	// The fields of signing authority keep their wording.
	o = Outcome{Changes: []Change{{Key: "x", Field: "regular_key", Old: "", New: "r2"}}}
	if fs := Findings(o, cfg, nil); len(fs) != 1 || !strings.Contains(fs[0].Title, "서명 권한") {
		t.Errorf("findings = %+v", fs)
	}
	for _, p := range []string{"../../explain/WA-002.md", "../../fixes/WA-002/watch.md"} {
		s := readText(t, p)
		for _, want := range []string{"무해", "lsfDisableMaster", "0x00100000"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s lacks %q", p, want)
			}
		}
	}
}

// M9: the text says what this tool reads, not how XRPL is.
func TestXRPLAuthorityTextIsAboutWhatIsRead(t *testing.T) {
	if s := readText(t, "../../explain/WA-002.md"); strings.Contains(s, "세 곳에서 정해집니다") || !strings.Contains(s, "이 도구가 읽는") {
		t.Errorf("explain/WA-002.md still states it as absolute")
	}
	if s := readText(t, "../../docs/watch.md"); !strings.Contains(s, "다른 위임 방식") {
		t.Error("docs/watch.md does not say other XRPL delegation mechanisms are not read")
	}
}

// M10, M13: the documents say what is true.
func TestWatchDocsStatements(t *testing.T) {
	s := readText(t, "../../docs/watch.md")
	for _, want := range []string{
		"연결하는 곳은 설정에 적은 곳뿐입니다",
		"오래된 내보내기 파일에서 읽은 대상",
		"내보내기 파일 하나와 대상 하나",
		"내보내지 않은 네임스페이스는 감시하지 않습니다",
		"`evm-wallet` 대상의 기준값에는 주소",
		"내보내는 주기에 가깝게",
		"실행한 폴더 기준",
		"`adk-watch` User-Agent",
		"`limit: 400`",
		"최대 20쪽",
		"`file`은 정리해서",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("docs/watch.md lacks %q", want)
		}
	}
	for _, bad := range []string{
		"RPC 주소로만 연결합니다",
		"모든 대상의 기준값에는",
		"-n <네임스페이스>",
		"최대 5쪽",
		"10진수로만",
	} {
		if strings.Contains(s, bad) {
			t.Errorf("docs/watch.md still says %q", bad)
		}
	}
}

// M14: two spellings of one path are one identity.
func TestPodsFileIdentityIsCleaned(t *testing.T) {
	body := podList(rsPod("web-1-a", "1", ctr("web", podsWeb, dgA)))
	file := podsFile(t, body, 0)
	t.Chdir(strings.TrimSuffix(file, "pods.json"))
	_, a := func() (Target, Observation) {
		obs, err := observePods(podsTarget("./pods.json", nil))
		if err != nil {
			t.Fatal(err)
		}
		return Target{}, obs
	}()
	obs, err := observePods(podsTarget("pods.json", nil))
	if err != nil {
		t.Fatal(err)
	}
	if a["file"] != obs["file"] || obs["file"] != "pods.json" {
		t.Errorf("./pods.json -> %q, pods.json -> %q", a["file"], obs["file"])
	}
}

// M14: a page read over plain http can be changed on the way.
func TestPlainHTTPPage(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://shop.example.com/", true},
		{"https://shop.example.com/", false},
		{"http://127.0.0.1:8080/", false},
		{"http://localhost/", false},
	}
	for _, c := range cases {
		tg := webTarget(map[string]any{"url": c.url + "?token=abcdef123"})
		if got := PlainHTTPPage(tg); got != c.want {
			t.Errorf("%s: %v", c.url, got)
		}
	}
	if PlainHTTPPage(Target{Kind: kindRepo, Options: map[string]any{"url": "http://x/"}}) {
		t.Error("other kinds have no page")
	}
}

// The server is asked for pages of 400, and up to 20 are followed.
func TestXRPLAccountObjectsLimit(t *testing.T) {
	if maxSignerPages != 20 {
		t.Errorf("maxSignerPages = %d", maxSignerPages)
	}
	acct := xAddr(1)
	n := newXNode(acct)
	n.pages = [][]xlist{{{quorum: 1, signers: []xsigner{{xAddr(40), 1}}}}, {}}
	xmust(t, xopts(acct), n.server(t).URL)
	asked := 0
	for _, r := range n.reqs {
		if r["method"] != "account_objects" {
			continue
		}
		asked++
		params := r["params"].(map[string]any)
		if limit, _ := params["limit"].(float64); limit != 400 {
			t.Errorf("limit = %v", params["limit"])
		}
	}
	if asked != 2 {
		t.Errorf("asked %d pages", asked)
	}
}
