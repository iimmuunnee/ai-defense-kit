package cicd

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
)

const (
	// maxVisits bounds the nodes looked at in one file, so a file made of
	// aliases that expand into each other cannot take the scan hostage.
	maxVisits = 500000
	maxDepth  = 32
	// maxTriggerVisits bounds the nodes looked at in the on: value.
	maxTriggerVisits = 10000
)

// hit is one thing found. key tells it apart from the others in the same file
// and never holds a value from the file.
type hit struct {
	id         string
	line       int
	severity   finding.Severity
	confidence finding.Confidence
	title      string
	evidence   string
	key        string
}

const (
	titleKey      = "장기 클라우드 키를 워크플로에 직접 넣은 설정"
	titleUnpinned = "커밋 해시로 고정하지 않은 액션"
	titleWriteAll = "GITHUB_TOKEN에 모든 쓰기 권한(write-all)을 준 설정"
	titleNoPerms  = "permissions를 지정하지 않은 워크플로"
	titlePRT      = "pull_request_target에서 PR의 코드를 내려받는 체크아웃"
	titleUnread   = "읽지 못했거나 일부만 보여 주는 워크플로 파일"
)

var (
	sha1Ref    = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	sha256Ref  = regexp.MustCompile(`@sha256:[0-9a-fA-F]{64}$`)
	bracketed  = regexp.MustCompile(`\[\s*['"]([^'"]*)['"]\s*\]`)
	space      = regexp.MustCompile(`\s+`)
	secretsRef = regexp.MustCompile(`(?i)\bsecrets\b`) // secrets.X, secrets['X'], toJSON(secrets)
)

// Names of the keys that hold long-lived cloud credentials, lower case.
var (
	awsEnvKeys  = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}
	awsWithKeys = []string{"aws-access-key-id", "aws-secret-access-key"}
)

type analyzer struct {
	budget   int
	exceeded bool
	hits     []hit
	// missingDone: the file was already reported for lacking permissions.
	missingDone bool
}

// spend takes one visit from the budget; false means the budget is gone.
func (a *analyzer) spend() bool {
	if a.budget <= 0 {
		a.exceeded = true
		return false
	}
	a.budget--
	return true
}

// deref follows aliases to the node they stand for.
func (a *analyzer) deref(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < maxDepth; i++ {
		n = n.Alias
	}
	if n != nil && n.Kind == yaml.AliasNode {
		return nil
	}
	return n
}

type pair struct{ key, val *yaml.Node }

// pairs lists the entries of a mapping, merge keys (<<) expanded. An entry
// written in the mapping itself wins over a merged one.
func (a *analyzer) pairs(n *yaml.Node, depth int) []pair {
	n = a.deref(n)
	if n == nil || n.Kind != yaml.MappingNode || depth > maxDepth {
		return nil
	}
	var out []pair
	var merges []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		if !a.spend() {
			return out
		}
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind == yaml.ScalarNode && k.Tag == "!!merge" {
			merges = append(merges, v)
			continue
		}
		out = append(out, pair{k, v})
	}
	for _, m := range merges {
		m = a.deref(m)
		if m == nil {
			continue
		}
		var from []*yaml.Node
		switch m.Kind {
		case yaml.MappingNode:
			from = []*yaml.Node{m}
		case yaml.SequenceNode:
			from = m.Content
		}
		for _, f := range from {
			for _, p := range a.pairs(f, depth+1) {
				dup := false
				for _, q := range out {
					if q.key.Value == p.key.Value {
						dup = true
						break
					}
				}
				if !dup {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// get finds an entry by key, ignoring case.
func (a *analyzer) get(ps []pair, name string) (pair, bool) {
	for _, p := range ps {
		if p.key.Kind == yaml.ScalarNode && strings.EqualFold(p.key.Value, name) {
			return p, true
		}
	}
	return pair{}, false
}

// items lists the elements of a sequence.
func (a *analyzer) items(n *yaml.Node) []*yaml.Node {
	n = a.deref(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

// text is the string a scalar holds, trimmed; ok is false for anything else.
func (a *analyzer) text(n *yaml.Node) (string, bool) {
	n = a.deref(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	return strings.TrimSpace(n.Value), true
}

// empty reports a missing, null or empty value: no key is set there.
func (a *analyzer) empty(n *yaml.Node) bool {
	n = a.deref(n)
	if n == nil {
		return true
	}
	if n.Kind == yaml.ScalarNode {
		return n.ShortTag() == "!!null" || strings.TrimSpace(n.Value) == ""
	}
	return false
}

// isOnKey: the workflow trigger key. YAML 1.1 reads an unquoted on as the
// boolean true, so that is accepted too.
func isOnKey(k *yaml.Node) bool {
	if k.Kind != yaml.ScalarNode {
		return false
	}
	return strings.EqualFold(k.Value, "on") || (k.ShortTag() == "!!bool" && strings.EqualFold(k.Value, "true"))
}

// hasEvent reports that the on: value names the event, as a string, a list or
// a map.
func (a *analyzer) hasEvent(on *yaml.Node, event string, depth int, left *int) bool {
	if depth > maxDepth {
		return false
	}
	// The trigger has its own allowance, so a bomb there cannot use up the
	// budget the jobs need.
	if *left--; *left < 0 {
		a.exceeded = true
		return false
	}
	on = a.deref(on)
	if on == nil {
		return false
	}
	switch on.Kind {
	case yaml.ScalarNode:
		return strings.EqualFold(strings.TrimSpace(on.Value), event)
	case yaml.SequenceNode:
		for _, it := range on.Content {
			if a.hasEvent(it, event, depth+1, left) {
				return true
			}
		}
	case yaml.MappingNode:
		for _, p := range a.pairs(on, 0) {
			if p.key.Kind == yaml.ScalarNode && strings.EqualFold(strings.TrimSpace(p.key.Value), event) {
				return true
			}
		}
	}
	return false
}

func (a *analyzer) add(h hit) { a.hits = append(a.hits, h) }

// document reads one workflow.
func (a *analyzer) document(doc *yaml.Node) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return
	}
	top := a.pairs(doc.Content[0], 0)
	if len(top) == 0 {
		return
	}

	prt := false
	allowance := maxTriggerVisits
	for _, p := range top {
		if isOnKey(p.key) && a.hasEvent(p.val, "pull_request_target", 0, &allowance) {
			prt = true
		}
	}

	topHasPerms := false
	if p, ok := a.get(top, "permissions"); ok {
		topHasPerms = true
		a.permissions(p.val, "워크플로", "workflow")
	}
	if p, ok := a.get(top, "env"); ok {
		a.envKeys(p.val, "워크플로 env", "workflow/env")
	}

	jobsPair, ok := a.get(top, "jobs")
	if !ok {
		return
	}
	jobs := a.pairs(jobsPair.val, 0)
	allJobsHavePerms := len(jobs) > 0
	for _, j := range jobs {
		jp := a.pairs(j.val, 0)
		if _, has := a.get(jp, "permissions"); !has {
			allJobsHavePerms = false
		}
		a.job(j.key.Value, jp, prt)
	}
	if len(jobs) > 0 && !topHasPerms && !allJobsHavePerms && !a.missingDone {
		a.missingDone = true
		a.add(hit{
			id: "CI-003", line: jobsPair.key.Line, severity: finding.Info, confidence: finding.Suspect, title: titleNoPerms,
			evidence: "permissions를 워크플로 전체에도, 모든 작업에도 지정하지 않았습니다",
			key:      "missing",
		})
	}
}

func (a *analyzer) job(name string, jp []pair, prt bool) {
	if p, ok := a.get(jp, "permissions"); ok {
		a.permissions(p.val, fmt.Sprintf("작업 %s", shown(name)), "job:"+name)
	}
	if p, ok := a.get(jp, "uses"); ok { // a reusable workflow
		a.uses(p.val, "job:"+name+"/uses")
	}
	if p, ok := a.get(jp, "env"); ok {
		a.envKeys(p.val, fmt.Sprintf("작업 %s env", shown(name)), "job:"+name+"/env")
	}
	if p, ok := a.get(jp, "container"); ok { // the string form has no env
		if ce, ok := a.get(a.pairs(p.val, 0), "env"); ok {
			a.envKeys(ce.val, fmt.Sprintf("작업 %s container env", shown(name)), "job:"+name+"/container/env")
		}
	}
	if p, ok := a.get(jp, "services"); ok {
		for _, s := range a.pairs(p.val, 0) {
			if se, ok := a.get(a.pairs(s.val, 0), "env"); ok {
				a.envKeys(se.val, fmt.Sprintf("작업 %s services.%s env", shown(name), shown(s.key.Value)), "job:"+name+"/services/"+s.key.Value+"/env")
			}
		}
	}
	sp, ok := a.get(jp, "steps")
	if !ok {
		return
	}
	for i, st := range a.items(sp.val) {
		if !a.spend() {
			return
		}
		a.step(name, i+1, a.pairs(st, 0), prt)
	}
}

func (a *analyzer) step(job string, n int, sp []pair, prt bool) {
	where := fmt.Sprintf("작업 %s 단계 %d", shown(job), n)
	base := fmt.Sprintf("job:%s/step:%d", job, n)

	var action string // lower-case action name of uses, without the ref
	if p, ok := a.get(sp, "uses"); ok {
		a.uses(p.val, base+"/uses")
		if s, ok := a.text(p.val); ok {
			action = strings.ToLower(strings.SplitN(s, "@", 2)[0])
		}
	}
	if p, ok := a.get(sp, "with"); ok {
		with := a.pairs(p.val, 0)
		for _, name := range awsWithKeys {
			a.credKey(with, name, strings.ToLower(name), where+" with", base+"/with")
		}
		switch action {
		case "google-github-actions/auth":
			a.credKey(with, "credentials_json", "credentials_json", where+" with", base+"/with")
		case "azure/login":
			a.credKey(with, "creds", "creds", where+" with", base+"/with")
		}
		if prt && action == "actions/checkout" {
			if r, ok := a.get(with, "ref"); ok {
				a.checkout(sp, r.val, where, base)
			}
		}
	}
	if p, ok := a.get(sp, "env"); ok {
		a.envKeys(p.val, where+" env", base+"/env")
	}
}

// credKey reports key (matched ignoring case) when it is set to something.
// The name is written as canon; the value is not looked at beyond being empty.
func (a *analyzer) credKey(ps []pair, key, canon, scope, scopeKey string) {
	p, ok := a.get(ps, key)
	if !ok || a.empty(p.val) {
		return
	}
	sev, conf, note := finding.High, finding.Certain, ""
	if a.expressionWithoutSecrets(p.val) {
		// Often a temporary credential from an earlier step, so only a suspicion.
		sev, conf, note = finding.Medium, finding.Suspect, ", secrets가 아닌 식"
	}
	a.add(hit{
		id: "CI-001", line: p.key.Line, severity: sev, confidence: conf, title: titleKey,
		evidence: fmt.Sprintf("%s (%s%s)", canon, scope, note),
		key:      scopeKey + "/" + canon,
	})
}

func (a *analyzer) envKeys(env *yaml.Node, scope, scopeKey string) {
	ps := a.pairs(env, 0)
	for _, name := range awsEnvKeys {
		a.credKey(ps, name, name, scope, scopeKey)
	}
}

func (a *analyzer) permissions(n *yaml.Node, scope, scopeKey string) {
	n = a.deref(n)
	if n == nil {
		return
	}
	if s, ok := a.text(n); ok && strings.EqualFold(s, "write-all") {
		a.add(hit{
			id: "CI-003", line: n.Line, severity: finding.High, confidence: finding.Certain, title: titleWriteAll,
			evidence: fmt.Sprintf("permissions: write-all (%s)", scope),
			key:      scopeKey + "/write-all",
		})
	}
}

// uses checks a step's or a job's uses value.
func (a *analyzer) uses(n *yaml.Node, scopeKey string) {
	n = a.deref(n)
	s, ok := a.text(n)
	if !ok || s == "" {
		return
	}
	sev, flagged := unpinned(s)
	if !flagged {
		return
	}
	a.add(hit{
		id: "CI-002", line: n.Line, severity: sev, confidence: finding.Certain, title: titleUnpinned,
		evidence: shown(s),
		key:      scopeKey + "\x00" + s,
	})
}

// unpinned decides whether a uses value is open to a moved tag or branch, and
// how serious that is.
func unpinned(s string) (finding.Severity, bool) {
	if s == "." || strings.HasPrefix(s, "./") { // a folder of this repository
		return 0, false
	}
	if strings.HasPrefix(strings.ToLower(s), "docker://") {
		return finding.Medium, !sha256Ref.MatchString(s)
	}
	name, ref, _ := strings.Cut(s, "@")
	if sha1Ref.MatchString(ref) {
		return 0, false
	}
	owner, _, _ := strings.Cut(name, "/")
	switch strings.ToLower(owner) {
	case "actions", "github":
		return finding.Low, true
	}
	return finding.Medium, true
}

// checkout reports an actions/checkout under pull_request_target whose ref
// points at the pull request. Only a fixed phrase is shown, not the ref.
func (a *analyzer) checkout(sp []pair, ref *yaml.Node, where, base string) {
	s, ok := a.text(ref)
	if !ok {
		return
	}
	what := prRef(s)
	if what == "" {
		return
	}
	line := ref.Line
	if p, ok := a.get(sp, "uses"); ok {
		if u := a.deref(p.val); u != nil {
			line = u.Line
		}
	}
	a.add(hit{
		id: "CI-004", line: line, severity: finding.Critical, confidence: finding.Suspect, title: titlePRT,
		evidence: fmt.Sprintf("pull_request_target 워크플로의 actions/checkout이 ref로 %s를 씁니다 (%s)", what, where),
		key:      base + "/checkout",
	})
}

// prRef names the pull request reference found in a checkout ref, or "".
func prRef(ref string) string {
	s := strings.ToLower(ref)
	s = bracketed.ReplaceAllString(s, ".$1")
	s = space.ReplaceAllString(s, "")
	switch {
	case strings.Contains(s, "github.event.pull_request.head"):
		return "github.event.pull_request.head"
	case strings.Contains(s, "github.event.pull_request.merge_commit_sha"):
		return "github.event.pull_request.merge_commit_sha"
	case strings.Contains(s, "github.head_ref"):
		return "github.head_ref"
	case strings.Contains(s, "refs/pull/") && strings.Contains(s, "github.event"):
		return "refs/pull/ (github.event로 만든 PR 번호)"
	}
	return ""
}

// expressionWithoutSecrets: the value is a ${{ }} expression that does not read
// secrets. Only this yes-or-no leaves the function; the text is never kept.
func (a *analyzer) expressionWithoutSecrets(n *yaml.Node) bool {
	s, ok := a.text(n)
	return ok && strings.Contains(s, "${{") && !secretsRef.MatchString(s)
}
