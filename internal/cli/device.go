package cli

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/device"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/mapping"
	"github.com/iimmuunnee/ai-defense-kit/internal/report"
	"github.com/iimmuunnee/ai-defense-kit/internal/watch"
)

const (
	deviceCheckName = "device"
	deviceTarget    = "이 컴퓨터"
	// deviceBaselineRel is the default baseline, under the home folder.
	deviceBaselineRel  = ".adk/device-baseline.json"
	deviceHistoryFile  = "adk-device-history.jsonl"
	deviceWindowsNote  = "Windows에서는 도구 실행 파일과 자동 실행 지점을 비교하지 않습니다. 토큰 저장 점검만 했습니다."
	deviceWindowsShort = "Windows에서는 도구 실행 파일과 자동 실행 지점을 비교하지 않아 받아들일 것이 없습니다."
	// deviceUsageText adds what only device takes.
	deviceUsageText = usageText + `
adk device: 이 컴퓨터에 배포 토큰(kubeconfig, Docker, AWS 장기 키, gh)이 저장되어 있는지 읽기만 해서 확인합니다.
  값은 출력하지 않고, 네트워크에 연결하지 않습니다.
  adk device init    토큰 점검과 함께 개발 도구(pyenv, brew, python, python3, node, npm, git, docker, kubectl,
                     aws, gh)의 실행 파일과 자동 실행 지점(LaunchAgents, systemd 사용자 서비스, 크론, 셸 시작 파일)을
                     기준값(~/.adk/device-baseline.json)에 기록합니다. 이미 있으면 덮어쓰지 않습니다.
  adk device check   토큰 점검과 함께 기준값과 비교합니다(DV-101, DV-102, DV-103). init 때 이미 있던 토큰은
                     결과에 적지만 종료 코드에는 반영하지 않고, 그 뒤에 새로 생긴 토큰만 반영합니다.
  adk device accept <key>... --note "사유"   확인한 변경을 기준값에 반영하고 기록 파일에 남깁니다.
  Windows에서는 init과 check가 토큰 점검만 합니다.
  adk device wallets [--dir <폴더>]... [--skip <경로>]...   지갑을 훔치는 프로그램이 이 컴퓨터에서 가져갈 수 있는 것을 위치만 목록으로
                     보여 줍니다: 글 파일에 적힌 시드 문구로 보이는 것(DV-201), 브라우저의 지갑 확장 프로그램
                     저장소(DV-202), 데스크톱 지갑의 키 저장 위치(DV-203, DV-204). 값, 낱말, 낱말 수는 출력하지
                     않습니다. Windows, macOS, Linux에서 모두 됩니다. 결과에 없는 것은 "찾아본 범위 안에서 없음"입니다.
  --dir <폴더>   wallets에서 시드 문구를 더 찾아볼 폴더입니다. 여러 번 쓸 수 있습니다. 링크나 정션이면
                 따라가지 않으므로 실제 위치를 주세요.
  --skip <경로>  wallets에서 보지 않을 파일이나 폴더입니다. 여러 번 쓸 수 있습니다. 확인을 마친 파일(문서의
                 예시 문구, 시험용 키 파일)이나 파일이 너무 많은 폴더를 뺄 때 씁니다. 뺀 경로는 리포트의 참고에
                 적습니다.
  --home <폴더>  홈 폴더 대신 이 폴더를 봅니다(시험용). 이때는 환경 변수(KUBECONFIG, DOCKER_CONFIG,
                 AWS_SHARED_CREDENTIALS_FILE, AWS_CONFIG_FILE, AWS_ACCESS_KEY_ID, GH_CONFIG_DIR,
                 XDG_CONFIG_HOME, APPDATA, PATH, HOMEBREW_PREFIX, PYENV_ROOT, NVM_DIR, FNM_DIR)를 읽지 않고 그 폴더 안의 기본 위치만
                 봅니다. /etc, /Library 같은 시스템 위치와 사용자 크론(crontab -l)도 보지 않습니다.
  --path <PATH>  도구를 찾을 PATH 목록입니다. 기본은 init에서 지금 셸의 PATH, check와 accept에서 기준값에
                 기록한 PATH입니다. 기준값의 PATH를 바꾸려면 accept env:PATH --path "$PATH"를 쓰세요.
  종료 코드: 0 문제 없음, 1 --fail-on(기본 high) 이상 발견, 2 있는 파일을 읽지 못함(확인 못 함). 둘 다면 1.
  init도 같은 규칙을 따르며, 읽지 못한 항목이 있거나 토큰이 있어도 기준값은 저장합니다.
`
)

// deviceHomeEnv is the environment the check sees under --home: none of the
// real one, so a test never reads this machine's credentials. Tests replace it.
var deviceHomeEnv = func(string) string { return "" }

// deviceGOOS is runtime.GOOS; tests change it to check the Windows behaviour.
var deviceGOOS = runtime.GOOS

// deviceRun is what one device command was asked to do.
type deviceRun struct {
	sub     string
	home    string
	homeSet bool
	env     func(string) string
	path    string
	// pathSet: --path was given. shellPath is the PATH of the shell adk runs in.
	pathSet   bool
	shellPath string
	// shellDiffers: the tools were looked up in the baseline's PATH, and the
	// shell's PATH is another one.
	shellDiffers bool
	baseline     string
	pin          string
	note         string
	formats      []string
	outDir       string
	failOn       *finding.Severity // nil: --fail-on none
}

func (r deviceRun) options() device.Options {
	o := device.Options{Home: r.home, Path: r.path, Getenv: r.env}
	if !r.homeSet {
		// Only a real run reads the system places and runs crontab.
		o.SysRoot = string(filepath.Separator)
		o.Crontab = device.UserCrontab
	} else if deviceHomeCrontab != nil {
		o.Crontab = deviceHomeCrontab
	}
	return o
}

// deviceHomeCrontab stands in for `crontab -l` under --home. It is nil except
// in tests: under --home no external command runs.
var deviceHomeCrontab func(context.Context) ([]byte, bool, error)

func (r deviceRun) shown(p string) string { return device.Display(r.home, p) }

func runDevice(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, deviceUsageText)
		return 0
	}
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		if sub != "init" && sub != "check" && sub != "accept" && sub != "wallets" {
			fmt.Fprintf(stderr, "알 수 없는 device 하위 명령입니다: %s (init, check, accept, wallets 중 하나)\n", report.SafeText(sub))
			fmt.Fprint(stderr, deviceUsageText)
			return 2
		}
		args = args[1:]
	}

	fl := flag.NewFlagSet("device", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	var (
		format   = fl.String("format", "md", "")
		outDir   = fl.String("out", "", "")
		failOn   = fl.String("fail-on", "high", "")
		home     = fl.String("home", "", "")
		path     = fl.String("path", "", "")
		baseline = fl.String("baseline", "", "")
		pin      = fl.String("baseline-sha256", "", "")
		note     = fl.String("note", "", "")
		dirs     stringList
		skips    stringList
	)
	fl.Var(&dirs, "dir", "")
	fl.Var(&skips, "skip", "")
	positional, code, ok := parseArgs(fl, args, stdout, stderr)
	if !ok {
		if code == 0 {
			// parseArgs printed the shared usage; device has its own.
			fmt.Fprint(stdout, deviceUsageText[len(usageText):])
		}
		return code
	}
	set := map[string]bool{}
	fl.Visit(func(f *flag.Flag) { set[f.Name] = true })

	for _, n := range []string{"dir", "skip"} {
		if set[n] && sub != "wallets" {
			fmt.Fprintf(stderr, "--%s는 adk device wallets에서만 쓸 수 있습니다.\n", n)
			return 2
		}
	}
	switch {
	case sub == "" || sub == "wallets":
		for _, n := range []string{"path", "baseline", "baseline-sha256", "note"} {
			if set[n] {
				fmt.Fprintf(stderr, "--%s는 adk device init, check, accept에서만 쓸 수 있습니다.\n", n)
				return 2
			}
		}
		if len(positional) != 0 {
			fmt.Fprintf(stderr, "device에는 위치 인자가 필요하지 않습니다: %s\n", report.SafeText(positional[0]))
			return 2
		}
	case sub == "accept":
		if len(positional) == 0 {
			fmt.Fprintln(stderr, "받아들일 key를 지정하세요: adk device accept <key>... --note \"사유\"")
			return 2
		}
	default:
		if set["note"] {
			fmt.Fprintln(stderr, "--note는 accept에서만 쓸 수 있습니다.")
			return 2
		}
		if len(positional) != 0 {
			fmt.Fprintf(stderr, "%s에는 위치 인자가 필요하지 않습니다.\n", sub)
			return 2
		}
	}
	if sub == "init" && set["baseline-sha256"] {
		fmt.Fprintln(stderr, "--baseline-sha256는 check와 accept에서만 쓸 수 있습니다.")
		return 2
	}
	if set["baseline-sha256"] && strings.TrimSpace(*pin) == "" {
		// An unset shell variable must not turn the comparison off.
		fmt.Fprintln(stderr, "--baseline-sha256 값이 비어 있습니다. 값을 담은 셸 변수가 설정되어 있는지 확인하세요.")
		return 2
	}
	formats, ok := outputFormats(*format, *outDir, stderr)
	if !ok {
		return 2
	}
	sev, err := ParseFailOn(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, deviceUsageText)
		return 2
	}

	run := deviceRun{sub: sub, home: *home, homeSet: set["home"], env: os.Getenv, pin: *pin, note: *note, formats: formats, outDir: *outDir, failOn: sev}
	if run.homeSet {
		st, err := os.Stat(run.home)
		if strings.TrimSpace(run.home) == "" || err != nil || !st.IsDir() {
			fmt.Fprintf(stderr, "--home 폴더를 찾을 수 없습니다: %s\n", run.home)
			return 2
		}
		run.env = deviceHomeEnv
	} else if run.home, err = os.UserHomeDir(); err != nil {
		fmt.Fprintln(stderr, "홈 폴더를 확인하지 못했습니다. --home으로 지정하세요.")
		return 2
	}
	run.shellPath = run.env("PATH")
	run.path, run.pathSet = run.shellPath, set["path"]
	if run.pathSet {
		run.path = *path
	}
	run.baseline = filepath.Join(run.home, filepath.FromSlash(deviceBaselineRel))
	if set["baseline"] {
		if strings.TrimSpace(*baseline) == "" {
			fmt.Fprintln(stderr, "--baseline 값이 비어 있습니다.")
			return 2
		}
		run.baseline = *baseline
	}
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, msgCancelled)
		return 2
	}

	switch {
	case sub == "wallets":
		return deviceWallets(ctx, run, dirs, skips, stdout, stderr)
	case sub == "accept":
		return deviceAccept(ctx, run, positional, stdout, stderr)
	case sub == "init" && deviceGOOS != "windows":
		if _, err := os.Lstat(run.baseline); err == nil || !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(stderr, "기준값 파일이 이미 있어 덮어쓰지 않습니다: %s\n"+
				"달라진 항목을 받아들이려면 `adk device accept <key> --note \"사유\"`를 쓰세요. 처음부터 다시 만들려면 이 파일을 다른 곳으로 옮긴 뒤 init을 다시 실행하세요.\n", run.shown(run.baseline))
			return 2
		}
	}

	findings, unread := device.CheckTokens(run.home, run.env)
	// exempt: fingerprints shown but not counted toward the exit code.
	exempt := map[string]bool{}
	checks := []checker.CheckStatus{{Name: deviceCheckName, Status: checker.StatusOK}}
	if len(findings) == 0 {
		if note := nothingThereNote(run.home, run.env); note != "" {
			checks[0].Notes = append(checks[0].Notes, note)
		}
	}
	for _, u := range unread {
		checks = append(checks, checker.CheckStatus{Name: deviceCheckName, Status: checker.StatusFailed, Error: "확인 못 함: " + u})
	}
	if sub == "" {
		return deviceReport(run, findings, checks, len(unread) > 0, nil, stdout, stderr)
	}
	if deviceGOOS == "windows" {
		checks[0].Notes = append(checks[0].Notes, deviceWindowsNote)
		fmt.Fprintln(stderr, "참고: "+deviceWindowsNote)
		return deviceReport(run, findings, checks, len(unread) > 0, nil, stdout, stderr)
	}

	var base watch.Baseline
	var shellUnread bool
	if sub == "check" {
		var err error
		if base, err = watch.LoadBaseline(run.baseline, run.pin); err != nil {
			fmt.Fprintf(stderr, "기준값을 확인하지 못했습니다: %v\n처음이라면 `adk device init`으로 기준값을 만드세요.\n", err)
			return 2
		}
		if note := run.useBaselinePath(base); note != "" {
			checks[0].Notes = append(checks[0].Notes, note)
		}
	}
	snap := device.Observe(ctx, run.options())
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, msgCancelled)
		return 2
	}
	if sub == "init" {
		if len(snap.Unread) > 0 {
			// What could not be read is recorded as such: check reports it
			// as not verified until it can be read, and as a change then.
			checks[0].Notes = append(checks[0].Notes, "읽지 못한 항목은 '읽지 못함'으로 기준값에 기록했습니다. 읽을 수 있게 될 때까지 check는 그 항목을 확인 못 함(종료 코드 2)으로 두고, 읽을 수 있게 되면 바뀐 것으로 알립니다.")
		}
		if err := os.MkdirAll(filepath.Dir(run.baseline), 0o700); err != nil {
			fmt.Fprintf(stderr, "기준값 폴더를 만들 수 없습니다: %s\n", run.shown(filepath.Dir(run.baseline)))
			return 2
		}
		entries := withTokens(snap.Entries, findings)
		entries[device.PathKey] = device.PathEntry(run.home, run.path)
		sum, err := watch.NewBaseline(time.Now(), entries).Save(run.baseline)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		tools, points, tokens := countKeys(entries)
		saved := fmt.Sprintf("기준값을 저장했습니다: %s (도구 %d개, 자동 실행 지점 %d개, 저장된 토큰 위치 %d개)", run.shown(run.baseline), tools, points, tokens)
		if tokens > 0 {
			checks[0].Notes = append(checks[0].Notes, "저장된 토큰의 위치(파일과 항목 이름, 값은 적지 않음)를 기준값에 기록했습니다. 다음 check부터는 기준값에 없던 토큰만 종료 코드에 반영합니다.")
		}
		fmt.Fprintf(stderr, "%s\nSHA-256: %s\n", saved, sum)
		fmt.Fprintln(stderr, "이 SHA-256을 기준값 파일과 따로 적어 두세요(다른 기기나 문서). 기준값 파일이 몰래 바뀌었는지는 `adk device check --baseline-sha256 <값>`으로 확인할 수 있습니다.")
		checks[0].Notes = append(checks[0].Notes, saved+" SHA-256: "+sum)
		findings = append(findings, device.InitFindings(snap, run.options())...)
	} else {
		device.Reconcile(&snap, base.Entries)
		// A credential stored when the baseline was made is still shown, but
		// only one that is not in it counts toward the exit code.
		var newTokens []string
		for i, f := range findings {
			k := device.TokenKey(f)
			if k == "" {
				continue
			}
			if _, ok := base.Entries[k]; ok {
				findings[i].Title += " (기준값에 있던 항목)"
				exempt[f.Fingerprint] = true
			} else {
				newTokens = append(newTokens, k)
			}
		}
		// A baselined credential no longer found: until its removal is
		// accepted, one stored again at the same place is not counted.
		current := device.TokenEntries(findings)
		var gone []string
		for _, k := range sortedKeys(base.Entries) {
			if _, ok := current[k]; strings.HasPrefix(k, device.TokenPrefix) && !ok && !tokenFileUnread(base.Entries[k]["file"], unread) {
				gone = append(gone, k)
			}
		}
		if len(gone) > 0 {
			checks[0].Notes = append(checks[0].Notes, fmt.Sprintf("기준값에 있던 토큰 %d개를 이제 찾지 못했습니다: %s. 지운 것이 맞으면 accept로 기준값에서 빼세요. 빼기 전에는 같은 위치에 다시 저장된 토큰이 종료 코드에 반영되지 않습니다.", len(gone), shellQuoteAll(gone)))
		}
		changes := device.Compare(base.Entries, snap, run.options())
		if run.shellDiffers {
			// The baseline's PATH alone would miss a same-name tool put ahead
			// in the shell's PATH: look there too.
			so := run.options()
			so.Path = run.shellPath
			shell := device.ObserveTools(so)
			shellChanges := device.CompareShell(base.Entries, snap, shell, run.options())
			if keys := acceptKeys(shellChanges); len(keys) > 0 {
				checks[0].Notes = append(checks[0].Notes, "지금 셸의 PATH에서 먼저 실행되는 도구가 기준값과 다릅니다. 확인한 뒤 뜻한 변경이면 그 PATH와 함께 반영하세요: adk device accept env:PATH "+shellQuoteAll(keys)+" --path \"$PATH\" --note \"사유\"")
			}
			for _, k := range sortedKeys(shell.Unread) {
				shellUnread = true
				checks = append(checks, checker.CheckStatus{Name: deviceCheckName, Status: checker.StatusFailed, Error: "확인 못 함(지금 셸의 PATH): " + k + ": " + shell.Unread[k]})
			}
			findings = append(findings, shellChanges...)
		}
		tools, points, _ := countKeys(snap.Entries)
		checks[0].Notes = append(checks[0].Notes, fmt.Sprintf("도구 %d개, 자동 실행 지점 %d개를 기준값(%s)과 비교했습니다.", tools, points, run.shown(run.baseline)))
		if len(exempt) > 0 {
			checks[0].Notes = append(checks[0].Notes, fmt.Sprintf("기준값에 있던 저장된 토큰 %d개는 결과에 적지만 종료 코드에는 반영하지 않았습니다.", len(exempt)))
		}
		if keys := append(append(acceptKeys(changes), newTokens...), gone...); len(keys) > 0 {
			checks[0].Notes = append(checks[0].Notes, "확인한 뒤 뜻한 변경이면 기준값에 반영하세요: adk device accept "+shellQuoteAll(keys)+" --note \"사유\"")
		}
		findings = append(findings, changes...)
	}
	for _, k := range sortedKeys(snap.Unread) {
		checks = append(checks, checker.CheckStatus{Name: deviceCheckName, Status: checker.StatusFailed, Error: "확인 못 함: " + k + ": " + snap.Unread[k]})
	}
	return deviceReport(run, findings, checks, len(unread) > 0 || len(snap.Unread) > 0 || shellUnread, exempt, stdout, stderr)
}

// stringList is a flag that can be given more than once.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// deviceWallets lists what a program that steals wallets could take from
// this computer. It writes no baseline: one look, one list.
func deviceWallets(ctx context.Context, run deviceRun, dirs, skips []string, stdout, stderr io.Writer) int {
	for i, d := range dirs {
		abs, err := filepath.Abs(d)
		if st, serr := os.Stat(d); strings.TrimSpace(d) == "" || err != nil || serr != nil || !st.IsDir() {
			fmt.Fprintf(stderr, "--dir 폴더를 찾을 수 없습니다: %s\n", report.SafeText(d))
			return 2
		}
		// A folder the user named and that cannot be searched is said so:
		// passing it by in silence would leave it unseen behind exit code 0.
		switch device.DirState(abs) {
		case device.DirPlain:
		case device.DirLink:
			fmt.Fprintf(stderr, "--dir로 준 폴더가 링크(심볼릭 링크나 정션)입니다: %s\n이 명령은 링크를 따라가지 않습니다. 링크가 가리키는 실제 위치를 --dir로 주세요.\n", report.SafeText(d))
			return 2
		case device.DirCloudOnly:
			fmt.Fprintf(stderr, "--dir로 준 폴더가 클라우드에만 있어 이 컴퓨터에 목록이 없습니다: %s\n이 명령은 내려받게 하지 않습니다. 동기화 프로그램에서 이 폴더를 이 장치에 받아 둔 뒤 다시 실행하세요.\n", report.SafeText(d))
			return 2
		default:
			fmt.Fprintf(stderr, "--dir로 준 폴더가 어떤 종류인지 알 수 없어 살펴보지 않았습니다: %s\n", report.SafeText(d))
			return 2
		}
		dirs[i] = abs
	}
	for i, s := range skips {
		abs, err := filepath.Abs(s)
		if strings.TrimSpace(s) == "" || err != nil {
			fmt.Fprintln(stderr, "--skip 값이 비어 있습니다.")
			return 2
		}
		// Typed as the report shows it: "~/" is the home folder.
		if rest, ok := strings.CutPrefix(filepath.ToSlash(s), "~/"); ok {
			abs = filepath.Join(run.home, filepath.FromSlash(rest))
		}
		skips[i] = abs
	}
	opt := device.WalletOptions{Home: run.home, Getenv: run.env, Dirs: dirs, Skip: skips}
	if !run.homeSet {
		// Only a real run asks the system where its folders are.
		opt.KnownFolders = device.KnownFolders()
	}
	res := device.CheckWallets(ctx, opt)
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, msgCancelled)
		return 2
	}
	checks := []checker.CheckStatus{{Name: deviceCheckName, Status: checker.StatusOK, Notes: res.Notes}}
	for _, u := range res.Unread {
		checks = append(checks, checker.CheckStatus{Name: deviceCheckName, Status: checker.StatusFailed, Error: "확인 못 함: " + u})
	}
	return deviceReport(run, res.Findings, checks, len(res.Unread) > 0, nil, stdout, stderr)
}

// useBaselinePath looks the tools up in the PATH the baseline recorded
// unless --path was given, and says which PATH was used.
func (r *deviceRun) useBaselinePath(base watch.Baseline) string {
	obs, ok := base.Entries[device.PathKey]
	if !ok {
		return ""
	}
	recorded := device.PathOf(r.home, obs)
	if r.pathSet {
		if device.PathEntry(r.home, r.path)["dirs"] != obs["dirs"] {
			return "--path로 준 PATH에서 도구를 찾았습니다. 기준값에 기록한 PATH와 다릅니다."
		}
		return ""
	}
	r.path = recorded
	note := "도구는 기준값에 기록한 PATH(init이나 accept env:PATH 때의 PATH)에서 찾았습니다."
	if device.PathEntry(r.home, r.shellPath)["dirs"] != obs["dirs"] {
		r.shellDiffers = true
		note += " 지금 셸의 PATH와 다릅니다. 지금 셸의 PATH에서도 찾아, 기준값과 다른 파일이 먼저 실행되면 알립니다(찾지 못한 도구는 알리지 않습니다). 지금 셸의 PATH에서 보려면 --path \"$PATH\"를 주고, 그 PATH를 기준값으로 삼으려면 `adk device accept env:PATH --path \"$PATH\" --note \"사유\"`를 쓰세요(그 PATH로 달라진 도구도 함께 받아들이세요)."
	}
	return note
}

// withTokens adds the places of the stored credentials found to entries.
func withTokens(entries map[string]watch.Observation, findings []finding.Finding) map[string]watch.Observation {
	out := maps.Clone(entries)
	if out == nil {
		out = map[string]watch.Observation{}
	}
	maps.Copy(out, device.TokenEntries(findings))
	return out
}

func countKeys(entries map[string]watch.Observation) (tools, points, tokens int) {
	for k := range entries {
		switch {
		case strings.HasPrefix(k, device.ToolPrefix):
			tools++
		case strings.HasPrefix(k, device.PersistPrefix):
			points++
		case strings.HasPrefix(k, device.TokenPrefix):
			tokens++
		}
	}
	return tools, points, tokens
}

// acceptKeys are the keys of the changes accept can take in.
func acceptKeys(fs []finding.Finding) []string {
	var keys []string
	for _, f := range fs {
		if f.ID != "DV-101" && f.ID != "DV-102" && f.ID != "DV-103" {
			continue
		}
		for _, k := range strings.Split(f.Location, ", ") {
			if !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	return keys
}

// deviceReport writes the report and returns the exit code: a finding at or
// above --fail-on wins; otherwise something that is there but was not read
// means this computer was not verified.
func deviceReport(run deviceRun, findings []finding.Finding, checks []checker.CheckStatus, unread bool, exempt map[string]bool, stdout, stderr io.Writer) int {
	catalog, err := mapping.Load(aidefensekit.Data)
	if err != nil {
		fmt.Fprintf(stderr, "국내 기준 파일을 불러오지 못했습니다: %v\n", err)
		return 2
	}
	mapSet, err := mappingData(aidefensekit.Data, report.OriginBuiltin, catalog)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	for _, w := range catalog.Attach(findings) {
		fmt.Fprintf(stderr, "경고: %s\n", w)
	}
	private := []string{run.home}
	if run.sub != "" {
		private = append(private, run.baseline)
	}
	rc := finishReport(func() report.Report {
		rep := report.Report{
			Kind:           report.KindDevice,
			Target:         deviceTarget,
			ScannedAt:      time.Now(),
			ToolVersion:    toolVersion(),
			TargetName:     deviceTarget,
			GitDirty:       report.DirtyUnknown,
			Data:           report.DataVersions{Mappings: mapSet},
			PrivatePaths:   scanPrivatePaths("", "", private...),
			NoIgnoreAdvice: true,
		}
		if bi, ok := debug.ReadBuildInfo(); ok {
			rep.Components = report.Components(bi)
		}
		return rep
	}, findings, checks, "", outputOptions{formats: run.formats, outDir: run.outDir, failOn: run.failOn, noIgnore: true, alwaysReport: true, exempt: exempt}, stdout, stderr)
	if rc == 0 && unread {
		return 2
	}
	return rc
}

// deviceAccept takes what is on this computer now for each key into the
// baseline, after writing one line per key to the history file.
func deviceAccept(ctx context.Context, run deviceRun, keys []string, stdout, stderr io.Writer) int {
	if deviceGOOS == "windows" {
		fmt.Fprintln(stderr, deviceWindowsShort)
		return 2
	}
	note := strings.TrimSpace(run.note)
	if note == "" {
		fmt.Fprintln(stderr, "--note가 필요합니다. 받아들이는 이유를 적으세요: adk device accept <key>... --note \"사유\"")
		return 2
	}
	base, err := watch.LoadBaseline(run.baseline, run.pin)
	if err != nil {
		fmt.Fprintf(stderr, "기준값을 확인하지 못했습니다: %v\n", err)
		return 2
	}
	// The tools are looked up in the baseline's PATH, as check does, unless
	// --path is given or env:PATH itself is being accepted.
	if !slices.Contains(keys, device.PathKey) {
		run.useBaselinePath(base)
	}
	snap := device.Observe(ctx, run.options())
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, msgCancelled)
		return 2
	}
	device.Reconcile(&snap, base.Entries)
	snap.Entries[device.PathKey] = device.PathEntry(run.home, run.path)
	tokenFindings, tokenUnread := device.CheckTokens(run.home, run.env)
	tokens := device.TokenEntries(tokenFindings)

	entries := maps.Clone(base.Entries)
	var changed, same []string
	byKey := map[string][]historyChange{}
	for _, k := range keys {
		// A shell may have turned "~" into the home folder.
		if p := strings.TrimPrefix(k, device.PersistPrefix); p != k && filepath.IsAbs(p) {
			k = device.PersistPrefix + device.Display(run.home, p)
		}
		if slices.Contains(changed, k) || slices.Contains(same, k) {
			continue
		}
		isToken := strings.HasPrefix(k, device.TokenPrefix)
		if !strings.HasPrefix(k, device.ToolPrefix) && !strings.HasPrefix(k, device.PersistPrefix) && !isToken && k != device.PathKey {
			fmt.Fprintf(stderr, "알 수 없는 key입니다: %s (tool:<이름>, persist:<경로>, token:<번호> <위치>, env:PATH, check 결과에 나온 그대로)\n", report.SafeText(k))
			return 2
		}
		old, inBase := base.Entries[k]
		now, inNow := snap.Entries[k]
		if isToken {
			now, inNow = tokens[k]
		}
		if device.Skipped(k, snap.Unread) || isToken && tokenFileUnread(cmp.Or(old["file"], now["file"]), tokenUnread) {
			fmt.Fprintf(stderr, "%s을(를) 지금 읽지 못해 기준값을 바꾸지 않았습니다.\n", report.SafeText(k))
			return 2
		}
		if !inBase && !inNow {
			fmt.Fprintf(stderr, "기준값에도 지금 이 컴퓨터에도 없는 key입니다: %s\n", report.SafeText(k))
			return 2
		}
		diff := watch.Diff(k, old, now)
		if len(diff) == 0 {
			same = append(same, k)
			continue
		}
		for _, c := range diff {
			byKey[k] = append(byKey[k], historyChange{Field: c.Field, Old: c.Old, New: c.New})
		}
		if inNow {
			entries[k] = now
		} else {
			delete(entries, k)
		}
		changed = append(changed, k)
	}
	for _, k := range same {
		fmt.Fprintf(stdout, "%s은(는) 이미 기준값과 같습니다. 바꾼 것이 없습니다.\n", report.SafeText(k))
	}
	if len(changed) == 0 {
		return 0
	}

	nb := base
	nb.Entries = entries
	history := filepath.Join(filepath.Dir(run.baseline), deviceHistoryFile)
	when, user := time.Now().UTC().Format(time.RFC3339), osUser()
	records := make([]historyEntry, len(changed))
	for i, k := range changed {
		records[i] = historyEntry{Time: when, OSUser: user, Key: k, Note: note, Changes: byKey[k]}
	}
	sum, ok := commitAccept(run.baseline, history, nb, records, stderr)
	if !ok {
		return 2
	}
	fmt.Fprintf(stdout, "%s을(를) 기준값에 반영했습니다. 기록: %s\nSHA-256: %s\n", report.SafeText(strings.Join(changed, ", ")), run.shown(history), sum)
	fmt.Fprintln(stdout, "반영한 값:")
	for _, k := range changed {
		for _, c := range byKey[k] {
			old, now := shownValue(c.Old), shownValue(c.New)
			if strings.HasPrefix(k, device.PersistPrefix) && c.Field == "sha256" {
				// A hash of a file that may hold tokens is never printed.
				old, now = hiddenHash(c.Old), hiddenHash(c.New)
			}
			fmt.Fprintf(stdout, "  %s %s: %s -> %s\n", report.SafeText(k), report.SafeText(c.Field), report.SafeText(old), report.SafeText(now))
		}
	}
	fmt.Fprintln(stdout, "새 SHA-256을 기준값 파일과 따로 적어 두세요.")
	return 0
}

// tokenFileUnread: the token check could not read file, or, when the key
// is in neither the baseline nor this computer, any file.
func tokenFileUnread(file string, unread []string) bool {
	for _, u := range unread {
		if file == "" || strings.HasPrefix(u, file+": ") {
			return true
		}
	}
	return false
}

// nothingThereNote says where the check looked when none of the files exist,
// so a clean result is not mistaken for a check of files that are elsewhere.
// The caller asks only when nothing was found, the environment included.
func nothingThereNote(home string, env func(string) string) string {
	var looked []string
	for _, p := range device.Places(home, env) {
		if _, err := os.Lstat(p.Path); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return ""
		}
		looked = append(looked, device.Display(home, p.Path))
	}
	return "점검할 파일이 하나도 없습니다. 찾아본 곳: " + strings.Join(looked, ", ")
}

// hiddenHash says whether there is a hash without showing it.
func hiddenHash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(없음)"
	}
	return "(값은 적지 않습니다)"
}

// shellQuoteAll joins keys as they can be typed into a POSIX shell: a key
// with a space or a shell character is put in single quotes.
func shellQuoteAll(keys []string) string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = shellQuote(k)
	}
	return strings.Join(out, " ")
}

func shellQuote(s string) string {
	plain := s != ""
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_-.:/~@+,%=", r)) {
			plain = false
			break
		}
	}
	if plain {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
