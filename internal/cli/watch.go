package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/mapping"
	"github.com/iimmuunnee/ai-defense-kit/internal/report"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

const (
	defaultWatchConfig   = "adk-watch.yaml"
	defaultWatchBaseline = "adk-watch-baseline.json"
	watchHistoryFile     = "adk-watch-history.jsonl"
	watchEventsFile      = "adk-watch-events.jsonl"
	watchCheckName       = "watch"

	// defaultTargetTimeout is how long one target may take. A judgement call,
	// not measured on real targets.
	defaultTargetTimeout = 2 * time.Minute
	// watchUsageText adds what only watch takes. usageText is what scan and
	// assets print, and stays as it is.
	watchUsageText = usageText + "  adk watch의 대상별 제한 시간: [--target-timeout <시간>] (기본 2m)\n"

	singleRPCNote = watch.SingleRPCNote
)

// Tests replace these so that --every needs no real clock.
var (
	watchNow   = time.Now
	watchAfter = time.After
)

// watchObservers lists the observers, one per target kind.
func watchObservers(allowEnvProxy bool) []watch.Observer {
	return []watch.Observer{
		watch.NewEVMObserver(watch.EnvClients(allowEnvProxy)),
		watch.NewXRPLObserver(watch.EnvClients(allowEnvProxy)),
		watch.NewWebObserver(allowEnvProxy),
		watch.NewRepoObserver(),
		watch.NewPodsObserver(func() time.Time { return watchNow() }),
	}
}

type watchOptions struct {
	config, baseline string
	pin              string
	failOn           finding.Severity
	failNone         bool // --fail-on none
	formats          []string
	outDir           string
	every            time.Duration
	note             string
	expects          []string
	allowEnvProxy    bool
	targetTimeout    time.Duration
}

// failSeverity is the --fail-on threshold; nil means --fail-on none.
func (o watchOptions) failSeverity() *finding.Severity {
	if o.failNone {
		return nil
	}
	return &o.failOn
}

func (o watchOptions) historyPath() string {
	return filepath.Join(filepath.Dir(o.baseline), watchHistoryFile)
}

func (o watchOptions) eventsPath() string {
	return filepath.Join(filepath.Dir(o.baseline), watchEventsFile)
}

func runWatch(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, watchUsageText)
		return 0
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "watch 하위 명령을 지정하세요: init, check, accept")
		fmt.Fprint(stderr, watchUsageText)
		return 2
	}
	sub := args[0]
	if sub != "init" && sub != "check" && sub != "accept" {
		fmt.Fprintf(stderr, "알 수 없는 watch 하위 명령입니다: %s (init, check, accept 중 하나)\n", sub)
		fmt.Fprint(stderr, watchUsageText)
		return 2
	}

	fl := flag.NewFlagSet("watch "+sub, flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	var (
		config   = fl.String("config", defaultWatchConfig, "")
		baseline = fl.String("baseline", defaultWatchBaseline, "")
		format   = fl.String("format", "md", "")
		outDir   = fl.String("out", "", "")
		failOn   = fl.String("fail-on", "high", "")
		pin      = fl.String("baseline-sha256", "", "")
		every    = fl.String("every", "", "")
		note     = fl.String("note", "", "")
		proxy    = fl.Bool("allow-env-proxy", false, "")
		timeout  = fl.String("target-timeout", defaultTargetTimeout.String(), "")
		expects  expectFlag
	)
	fl.Var(&expects, "expect", "")
	positional, code, ok := parseArgs(fl, args[1:], stdout, stderr)
	if !ok {
		return code
	}
	opt := watchOptions{config: *config, baseline: *baseline, pin: *pin, outDir: *outDir, note: *note, expects: expects, allowEnvProxy: *proxy}

	d, err := time.ParseDuration(strings.TrimSpace(*timeout))
	if err != nil || d <= 0 {
		fmt.Fprintf(stderr, "--target-timeout 값이 올바르지 않습니다: %q (2m, 30s처럼 0보다 큰 시간이어야 합니다)\n", *timeout)
		return 2
	}
	opt.targetTimeout = d

	everySet, pinSet := false, false
	fl.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "every":
			everySet = true
		case "baseline-sha256":
			pinSet = true
		}
	})
	if pinSet && strings.TrimSpace(*pin) == "" {
		// An unset shell variable must not turn the comparison off.
		fmt.Fprintln(stderr, "--baseline-sha256 값이 비어 있습니다. 값을 담은 셸 변수가 설정되어 있는지 확인하세요.")
		return 2
	}
	if len(expects) > 0 && sub != "accept" {
		fmt.Fprintln(stderr, "--expect는 accept에서만 쓸 수 있습니다.")
		return 2
	}
	if everySet {
		if sub != "check" {
			fmt.Fprintln(stderr, "--every는 check에서만 쓸 수 있습니다.")
			return 2
		}
		d, err := time.ParseDuration(strings.TrimSpace(*every))
		if err != nil || d <= 0 {
			fmt.Fprintf(stderr, "--every 값이 올바르지 않습니다: %q (1m, 30s처럼 0보다 큰 시간이어야 합니다)\n", *every)
			return 2
		}
		opt.every = d
	}

	switch sub {
	case "check":
		formats, ok := outputFormats(*format, *outDir, stderr)
		if !ok {
			return 2
		}
		if slices.Contains(formats, "sarif") {
			fmt.Fprintln(stderr, "adk watch 결과는 파일 위치가 아니라 대상 이름이라 SARIF로 낼 수 없습니다. --format md,json을 쓰세요.")
			return 2
		}
		opt.formats = formats
		sev, err := ParseFailOn(*failOn)
		if err != nil {
			fmt.Fprintln(stderr, err)
			fmt.Fprint(stderr, watchUsageText)
			return 2
		}
		opt.failNone = sev == nil
		if sev != nil {
			opt.failOn = *sev
		}
		if len(positional) != 0 {
			fmt.Fprintln(stderr, "check에는 위치 인자가 필요하지 않습니다.")
			return 2
		}
	case "init":
		if len(positional) != 0 {
			fmt.Fprintln(stderr, "init에는 위치 인자가 필요하지 않습니다.")
			return 2
		}
	case "accept":
		if len(positional) != 1 {
			fmt.Fprintln(stderr, "받아들일 대상의 key를 하나만 지정하세요: adk watch accept <key> --note \"사유\"")
			return 2
		}
	}
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, msgCancelled)
		return 2
	}

	cfg, err := watch.LoadConfig(opt.config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if len(cfg.Targets) == 0 {
		fmt.Fprintf(stderr, "설정 파일에 감시 대상이 없습니다: %s\n", opt.config)
		return 2
	}
	sc := newScrubber(secretStrings(cfg)...)

	switch sub {
	case "init":
		return watchInit(ctx, cfg, opt, sc, stdout, stderr)
	case "accept":
		return watchAccept(ctx, cfg, opt, positional[0], sc, stdout, stderr)
	}
	return watchCheck(ctx, cfg, opt, sc, stdout, stderr)
}

// secretStrings returns the values the output must not hold: the webhook address
// and what each target's config says is secret.
func secretStrings(cfg watch.Config) []string {
	out := []string{os.Getenv(webhookEnv)}
	for _, t := range cfg.Targets {
		out = append(out, watch.TargetSecrets(t)...)
	}
	return out
}

// collect observes the targets. A target with no observer, an error or no
// observation is in failed, never in cur. A partial observation stays inside
// its error: Compare finds it there.
func collect(ctx context.Context, targets []watch.Target, sc *scrubber, opt watchOptions) (map[string]watch.Observation, map[string]error) {
	return collectWith(ctx, watchObservers(opt.allowEnvProxy), targets, sc, opt.targetTimeout)
}

// targetGrace is how long after its deadline a target may still hand back what
// it read. An observer that ignores its context costs this much more, no more.
var targetGrace = 2 * time.Second

// timedOutError is the reason of a target past --target-timeout. The text does
// not repeat the standard library's; the error still unwraps to what the
// observer returned, so what it read is compared.
type timedOutError struct {
	limit time.Duration
	err   error
}

func (e timedOutError) Error() string {
	return fmt.Sprintf("제한 시간(%s, --target-timeout) 안에 다 읽지 못했습니다. 대상이 응답하지 않거나 너무 느릴 수 있습니다", e.limit)
}
func (e timedOutError) Unwrap() error { return e.err }

// observeWithin runs one Observe under the deadline. It runs apart so that an
// observer stuck where a context cannot reach it (a hung file system) does not
// hold up the targets after it. Such a goroutine ends with its call.
func observeWithin(ctx context.Context, obs watch.Observer, t watch.Target, timeout time.Duration) (watch.Observation, error) {
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		o   watch.Observation
		err error
	}
	done := make(chan result, 1)
	go func() {
		o, err := obs.Observe(tctx, t)
		done <- result{o, err}
	}()
	var r result
	select {
	case r = <-done:
	case <-tctx.Done():
		select {
		case r = <-done:
		case <-time.After(targetGrace):
			r.err = tctx.Err()
		}
	}
	if r.err != nil && ctx.Err() == nil && errors.Is(tctx.Err(), context.DeadlineExceeded) {
		return nil, timedOutError{limit: timeout, err: r.err}
	}
	return r.o, r.err
}

func collectWith(ctx context.Context, observers []watch.Observer, targets []watch.Target, sc *scrubber, timeout time.Duration) (map[string]watch.Observation, map[string]error) {
	byKind := map[string]watch.Observer{}
	for _, o := range observers {
		byKind[o.Kind()] = o
	}
	cur := map[string]watch.Observation{}
	failed := map[string]error{}
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		obs, ok := byKind[t.Kind]
		if !ok {
			failed[t.Key] = fmt.Errorf("이 종류(%s)를 읽는 관측기가 없습니다", t.Kind)
			continue
		}
		o, err := observeWithin(ctx, obs, t, timeout)
		switch {
		case err != nil:
			failed[t.Key] = sc.err(err)
		case o == nil:
			failed[t.Key] = errors.New("관측 결과가 없습니다")
		default:
			cur[t.Key] = o
		}
	}
	return cur, failed
}

func watchInit(ctx context.Context, cfg watch.Config, opt watchOptions, sc *scrubber, stdout, stderr io.Writer) int {
	if _, err := os.Lstat(opt.baseline); err == nil || !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(stderr, "기준값 파일이 이미 있어 덮어쓰지 않습니다: %s\n"+
			"값이 달라진 대상을 받아들이려면 `adk watch accept <key> --note \"사유\"`를 쓰세요. 처음부터 다시 만들려면 이 파일을 다른 곳으로 옮긴 뒤 init을 다시 실행하세요.\n", opt.baseline)
		return 2
	}
	cur, failed := collect(ctx, cfg.Targets, sc, opt)
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, msgCancelled)
		return 2
	}
	// Containers that have not pulled their image do not hold back the rest of
	// the cluster. They are named below, and appear as new once they are read.
	unread := map[string][]string{}
	for k, err := range failed {
		if obs, names, ok := watch.SomeUnread(err); ok {
			cur[k], unread[k] = obs, names
			delete(failed, k)
		}
	}
	if len(failed) > 0 {
		fmt.Fprintln(stderr, "다 읽지 못한 대상이 있어 기준값을 만들지 않았습니다.")
		for _, k := range sortedKeys(failed) {
			if miss := watch.CrossCheckMissing(failed[k]); len(miss) > 0 {
				fmt.Fprintf(stderr, "  - %s: %s 응답이 없어 한쪽 값만으로는 기준값을 만들지 않습니다. 모든 RPC가 답하는지 확인한 뒤 다시 실행하세요\n", report.SafeText(k), rpcNumbers(miss))
				continue
			}
			fmt.Fprintf(stderr, "  - %s: 확인 못 함: %s\n", report.SafeText(k), report.SafeText(failed[k].Error()))
		}
		return 2
	}
	var implausible []string
	for _, t := range cfg.Targets {
		if err := watch.CheckInitial(t, cur[t.Key]); err != nil {
			implausible = append(implausible, err.Error())
		}
	}
	if len(implausible) > 0 {
		fmt.Fprintln(stderr, "기준값을 만들지 않았습니다.")
		for _, why := range implausible {
			fmt.Fprintf(stderr, "  - %s\n", report.SafeText(why))
		}
		return 2
	}
	sum, err := watch.NewBaseline(watchNow(), cur).Save(opt.baseline)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	for _, t := range cfg.Targets {
		for _, n := range targetNotes(t) {
			fmt.Fprintf(stderr, "경고: %s: %s\n", report.SafeText(t.Key), n)
		}
		warnBaseline(t, cur[t.Key], stderr)
		if names := unread[t.Key]; len(names) > 0 {
			fmt.Fprintf(stderr, "경고: %s: 컨테이너 %d개는 digest를 읽지 못해 기준값에 넣지 않았습니다: %s. 나중에 digest가 읽히면 새 항목(WA-103)으로 나옵니다. 그때까지 check는 종료 코드 2입니다.\n",
				report.SafeText(t.Key), len(names), report.SafeText(sc.clean(strings.Join(names, ", "))))
		}
	}
	fmt.Fprintf(stdout, "기준값을 저장했습니다: %s (대상 %d개)\nSHA-256: %s\n", opt.baseline, len(cur), sum)
	fmt.Fprintln(stdout, "이 SHA-256을 기준값 파일과 따로 적어 두세요(다른 기기나 문서). 기준값 파일이 몰래 바뀌었는지는 `adk watch check --baseline-sha256 <값>`으로 확인할 수 있습니다.")
	return 0
}

// rpcNumbers words RPC positions, such as "RPC 2, RPC 3". Positions only.
func rpcNumbers(n []int) string {
	parts := make([]string, len(n))
	for i, v := range n {
		parts[i] = fmt.Sprintf("RPC %d", v)
	}
	return strings.Join(parts, ", ")
}

func targetNotes(t watch.Target) []string { return watch.TargetNotes(t) }

// warnBaseline says what is worth knowing about what init or accept took in.
// Names in it can come from the target, so the whole text is cleaned.
func warnBaseline(t watch.Target, obs watch.Observation, stderr io.Writer) {
	for _, n := range watch.BaselineWarnings(t, obs) {
		fmt.Fprintf(stderr, "경고: %s: %s\n", report.SafeText(t.Key), report.SafeText(n))
	}
}

// evaluation is one comparison of the world with the baseline.
type evaluation struct {
	outcome  watch.Outcome
	findings []finding.Finding
	checks   []checker.CheckStatus
	sig      string
	code     int
	// baselineBad: the baseline could not be loaded, so nothing was compared.
	baselineBad bool
}

func evaluate(ctx context.Context, cfg watch.Config, base watch.Baseline, opt watchOptions, sc *scrubber) evaluation {
	cur, failed := collect(ctx, cfg.Targets, sc, opt)
	o := watch.Compare(base, cur, failed, cfg)
	fs := watch.Findings(o, cfg, aidefensekit.Data)

	checks := []checker.CheckStatus{{Name: watchCheckName, Status: checker.StatusOK}}
	isNew := map[string]bool{}
	for _, k := range o.NewTargets {
		isNew[k] = true
	}
	verified := 0
	for _, t := range cfg.Targets {
		st := checker.CheckStatus{Name: watchCheckName + "/" + t.Key, Status: checker.StatusOK}
		switch {
		case o.Unverified[t.Key] != "":
			st.Status = checker.StatusFailed
			st.Error = "확인 못 함: " + o.Unverified[t.Key]
		case isNew[t.Key]:
			st.Status = checker.StatusFailed
			st.Error = "기준값에 없는 새 대상입니다. 확인한 뒤 `adk watch accept " + t.Key + " --note \"사유\"`로 추가하세요"
		default:
			verified++
		}
		// Read from o.Observed: a partial read is not in cur.
		st.Notes = append(targetNotes(t), watch.ReportNotes(t, o.Observed[t.Key], o.Changes)...)
		checks = append(checks, st)
	}
	if verified == 0 {
		checks[0].Status = checker.StatusFailed
		checks[0].Error = "확인 못 함: 기준값과 완전히 확인한 대상이 하나도 없습니다"
	}
	for _, k := range o.RemovedTargets {
		checks = append(checks, checker.CheckStatus{Name: watchCheckName + "/" + k, Status: checker.StatusFailed,
			Error: "설정에서 빠졌지만 기준값에 남아 있습니다. 뜻한 변경이면 `adk watch accept " + k + " --note \"사유\"`로 기준값에서 지우세요"})
	}
	return evaluation{outcome: o, findings: fs, checks: checks, sig: signature(o), code: watch.ExitCodeFor(o, fs, opt.failSeverity())}
}

// signature is a stable text for the state an Outcome describes. --every
// reports again only when it changes. An unverified target counts by its key
// and class (disagreement or not), not by the reason's text: an RPC whose
// error keeps changing is one state, not a new alert each round.
func signature(o watch.Outcome) string {
	var lines []string
	for _, c := range o.Changes {
		lines = append(lines, "C\x00"+c.Key+"\x00"+c.Field+"\x00"+c.Old+"\x00"+c.New)
	}
	for _, im := range o.Outside {
		lines = append(lines, "O\x00"+im.Key+"\x00"+im.Name+"\x00"+im.Registries)
	}
	for _, k := range sortedKeys(o.Unverified) {
		lines = append(lines, "U\x00"+k)
	}
	for _, k := range o.Disagreed {
		lines = append(lines, "D\x00"+k)
	}
	for _, k := range o.Stale {
		lines = append(lines, "S\x00"+k)
	}
	for _, k := range o.NewTargets {
		lines = append(lines, "N\x00"+k)
	}
	for _, k := range o.RemovedTargets {
		lines = append(lines, "R\x00"+k)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// writeWatchReport writes the report and reports whether it could.
func writeWatchReport(ev evaluation, opt watchOptions, stdout, stderr io.Writer) bool {
	catalog, err := mapping.Load(aidefensekit.Data)
	if err != nil {
		fmt.Fprintf(stderr, "국내 기준 파일을 불러오지 못했습니다: %v\n", err)
		return false
	}
	mapSet, err := mappingData(aidefensekit.Data, report.OriginBuiltin, catalog)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return false
	}
	findings := append([]finding.Finding(nil), ev.findings...)
	for _, w := range catalog.Attach(findings) {
		fmt.Fprintf(stderr, "경고: %s\n", w)
	}
	rc := finishReport(func() report.Report {
		return report.Report{
			Target:         opt.config,
			ScannedAt:      watchNow(),
			ToolVersion:    toolVersion(),
			TargetName:     filepath.Base(opt.config),
			GitDirty:       report.DirtyUnknown,
			Data:           report.DataVersions{Mappings: mapSet},
			PrivatePaths:   scanPrivatePaths("", "", opt.config, opt.baseline),
			NoIgnoreAdvice: true,
		}
	}, findings, ev.checks, ".", outputOptions{formats: opt.formats, outDir: opt.outDir, noIgnore: true, alwaysReport: true}, stdout, stderr)
	return rc != 2
}

// watchEvent is one line of the events file, which keeps the states that
// --every passed through after its reports have been overwritten. It holds
// no value read from a target, no RPC address and no secret.
type watchEvent struct {
	Time          string   `json:"time"`
	Code          int      `json:"code"`
	FindingIDs    []string `json:"finding_ids"`
	TargetKeys    []string `json:"target_keys"`
	BaselineError bool     `json:"baseline_error,omitempty"`
}

func newWatchEvent(ev evaluation) watchEvent {
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, f := range ev.findings {
		ids[f.ID] = true
		keys[f.Location] = true
	}
	for k := range ev.outcome.Unverified {
		keys[k] = true
	}
	for _, k := range append(slices.Clone(ev.outcome.NewTargets), ev.outcome.RemovedTargets...) {
		keys[k] = true
	}
	return watchEvent{
		Time: watchNow().UTC().Format(time.RFC3339), Code: ev.code, BaselineError: ev.baselineBad,
		FindingIDs: sortedKeys(ids), TargetKeys: sortedKeys(keys),
	}
}

func watchCheck(ctx context.Context, cfg watch.Config, opt watchOptions, sc *scrubber, stdout, stderr io.Writer) int {
	base, err := watch.LoadBaseline(opt.baseline, opt.pin)
	if err != nil {
		fmt.Fprintf(stderr, "기준값을 확인하지 못했습니다: %v\n처음이라면 `adk watch init`으로 기준값을 만드세요.\n", err)
		return 2
	}
	if opt.every <= 0 {
		ev := evaluate(ctx, cfg, base, opt, sc)
		if ctx.Err() != nil {
			fmt.Fprintln(stderr, msgCancelled)
			return 2
		}
		code := ev.code
		if !writeWatchReport(ev, opt, stdout, stderr) {
			code = worse(code, 2)
		}
		if worthSending(ev.outcome, ev.findings, ev.baselineBad) {
			sendWebhook(ctx, ev, opt.allowEnvProxy, stderr)
		}
		return code
	}

	// The state last reported, logged and sent. Each is tried again every
	// round until it has worked for the state the world is in now.
	const none = "\x00none"
	reported, logged, sent := none, none, none
	worst, rounds := 0, 0
	// Stopped before any round finished: nothing was verified, so it is not 0.
	stopped := func() int {
		fmt.Fprintln(stderr, msgCancelled)
		if rounds == 0 {
			return 2
		}
		return worst
	}
	for {
		if ctx.Err() != nil {
			return stopped()
		}
		// The baseline is read again each round: accept may have changed it.
		var ev evaluation
		base, err := watch.LoadBaseline(opt.baseline, opt.pin)
		if err != nil {
			ev = badBaseline(err)
		} else {
			ev = evaluate(ctx, cfg, base, opt, sc)
			if ctx.Err() != nil {
				return stopped()
			}
		}
		code := ev.code
		if reported != ev.sig {
			if writeWatchReport(ev, opt, stdout, stderr) {
				reported = ev.sig
			} else {
				code = worse(code, 2)
			}
		}
		if logged != ev.sig {
			if err := appendJSONL(opt.eventsPath(), newWatchEvent(ev)); err != nil {
				fmt.Fprintf(stderr, "경고: 상태 변화를 기록 파일에 쓰지 못했습니다: %v\n", err)
				code = worse(code, 2)
			} else {
				logged = ev.sig
			}
		}
		if sent != ev.sig {
			// The first round is not a change: a clean start has nothing to say.
			quietStart := sent == none && !worthSending(ev.outcome, ev.findings, ev.baselineBad)
			if quietStart || sendWebhook(ctx, ev, opt.allowEnvProxy, stderr) {
				sent = ev.sig
			}
		}
		worst = worse(worst, code)
		rounds++
		select {
		case <-ctx.Done():
		case <-watchAfter(opt.every):
		}
	}
}

// worse picks the worst exit code: 1 beats 2 beats 0.
func worse(a, b int) int {
	if a == 1 || b == 1 {
		return 1
	}
	return max(a, b)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// badBaseline is the state "the baseline cannot be used": no target is
// compared, which is as much a state change as a finding. The text is fixed
// so that the same breakage is the same state from round to round.
func badBaseline(err error) evaluation {
	const why = "기준값 파일을 쓸 수 없습니다 (읽지 못했거나, 깨졌거나, 지정한 SHA-256과 다릅니다)"
	return evaluation{
		checks: []checker.CheckStatus{
			{Name: watchCheckName, Status: checker.StatusFailed, Error: "확인 못 함: 기준값과 비교한 대상이 하나도 없습니다"},
			{Name: watchCheckName + "/기준값", Status: checker.StatusFailed, Error: "확인 못 함: " + why + ": " + err.Error()},
		},
		sig: "baseline-bad\x00" + why, code: 2, baselineBad: true,
	}
}
