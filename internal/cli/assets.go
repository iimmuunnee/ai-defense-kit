package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"

	aidefensekit "github.com/iimmuunnee/ai-defense-kit"
	"github.com/iimmuunnee/ai-defense-kit/internal/assets"
	"github.com/iimmuunnee/ai-defense-kit/internal/assets/ctlog"
	"github.com/iimmuunnee/ai-defense-kit/internal/checker"
	"github.com/iimmuunnee/ai-defense-kit/internal/finding"
	"github.com/iimmuunnee/ai-defense-kit/internal/mapping"
	"github.com/iimmuunnee/ai-defense-kit/internal/report"
)

const projectURL = "https://github.com/iimmuunnee/ai-defense-kit"

// crtshBaseURL와 crtshBackoff는 테스트에서 crt.sh 대신 httptest 서버를 쓰기 위한 훅이다.
// 빈 값이나 nil이면 ctlog의 기본값을 쓴다.
var (
	crtshBaseURL string
	crtshBackoff func(attempt int) time.Duration
)

func userAgent() string {
	return "adk/" + toolVersion() + " (+" + projectURL + ")"
}

func runAssets(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("assets", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	var (
		format    = fl.String("format", "md", "")
		outDir    = fl.String("out", "", "")
		strict    = fl.Bool("strict", false, "")
		knownPath = fl.String("known", "", "")
		exclude   = fl.Bool("exclude-expired", false, "")
		_         = fl.Bool("offline", false, "") // 받기만 하고 거부한다
	)
	positional, code, ok := parseArgs(fl, args, stdout, stderr)
	if !ok {
		return code
	}
	offline := false
	fl.Visit(func(f *flag.Flag) {
		if f.Name == "offline" {
			offline = true
		}
	})
	if offline {
		fmt.Fprintln(stderr, "adk assets는 인터넷 조회가 필요해 --offline을 쓸 수 없습니다.")
		return 2
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "점검할 도메인을 하나만 지정하세요.")
		fmt.Fprint(stderr, usageText)
		return 2
	}
	domain, err := normalizeDomain(positional[0])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	formats, ok := outputFormats(*format, *outDir, stderr)
	if !ok {
		return 2
	}
	// A subdomain list has no file locations, so SARIF is refused before any lookup.
	if slices.Contains(formats, "sarif") {
		fmt.Fprintln(stderr, "adk assets 결과는 파일 위치가 아니라 서브도메인이라 SARIF로 낼 수 없습니다. --format md,json을 쓰세요.")
		return 2
	}

	var known *assets.Known
	if *knownPath != "" {
		k, err := assets.LoadKnown(*knownPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		known = &k
	}

	if ctx.Err() != nil {
		fmt.Fprintln(stderr, msgCancelled)
		return 2
	}
	c := assets.NewChecker(aidefensekit.Data, ctlog.Options{
		BaseURL:        crtshBaseURL,
		UserAgent:      userAgent(),
		ExcludeExpired: *exclude,
		Backoff:        crtshBackoff,
	}, known, nil)
	findings, checks := checker.RunAll(ctx, []checker.Checker{c}, checker.Target{Domain: domain}, checkerTimeout)
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, msgCancelled)
		return 2
	}

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

	finding.Sort(findings) // 모두 Info라서 이름 순이 된다
	var rows []report.AssetRow
	if anyRan(checks) {
		byName := map[string]assets.Asset{}
		for _, a := range c.Assets() {
			byName[a.Name] = a
		}
		for _, f := range findings {
			a, ok := byName[f.Location]
			if !ok {
				continue
			}
			rows = append(rows, report.AssetRow{
				Name: a.Name, Wildcard: a.Wildcard, CertCount: a.CertCount,
				FirstSeen: a.FirstSeen, LastExpiry: a.LastExpiry, StillValid: a.StillValid,
				Fingerprint: f.Fingerprint,
			})
		}
	}

	return finishReport(func() report.Report {
		return report.Report{
			Kind:        report.KindAssets,
			Target:      domain,
			ScannedAt:   time.Now(),
			ToolVersion: toolVersion(),
			KnownList:   *knownPath,
			Assets:      rows,
			// Evidence inputs. adk assets uses no rules and reads no repository.
			TargetName:   domain,
			GitDirty:     report.DirtyUnknown,
			Data:         report.DataVersions{Mappings: mapSet},
			PrivatePaths: scanPrivatePaths("", "", *knownPath),
		}
	}, findings, checks, ".", outputOptions{formats: formats, outDir: *outDir, strict: *strict}, stdout, stderr)
}

// normalizeDomain은 사용자가 넣은 도메인을 crt.sh에 보낼 형태로 정리한다.
// http(s):// 접두사, 경로·쿼리·조각, 포트, 끝 점, 앞뒤 공백을 떼고 소문자로 바꾼다.
// 와일드카드, %, IP 주소, 점이 없는 값, 호스트 이름 문법에 맞지 않는 값은 거부한다.
func normalizeDomain(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	low := strings.ToLower(s)
	for _, p := range []string{"https://", "http://"} {
		if strings.HasPrefix(low, p) {
			s = s[len(p):]
			break
		}
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("도메인이 비어 있습니다. example.com처럼 입력하세요.")
	}
	if strings.Contains(s, "*") {
		return "", fmt.Errorf("도메인에 *를 쓸 수 없습니다. 와일드카드 없이 example.com처럼 입력하세요: %q", raw)
	}
	if strings.Contains(s, "%") {
		return "", fmt.Errorf("도메인에 %%를 쓸 수 없습니다: %q", raw)
	}
	errIP := fmt.Errorf("IP 주소는 받지 않습니다. 도메인 이름을 입력하세요: %q", raw)
	if strings.HasPrefix(s, "[") || net.ParseIP(s) != nil { // [IPv6]:포트 또는 IP 그대로
		return "", errIP
	}
	host := s
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i] // 포트
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", errors.New("도메인이 비어 있습니다. example.com처럼 입력하세요.")
	}
	if net.ParseIP(host) != nil {
		return "", errIP
	}
	if !strings.Contains(host, ".") {
		return "", fmt.Errorf("도메인에 점(.)이 없습니다. example.com처럼 입력하세요: %q", raw)
	}
	if !assets.ValidHostname(host) {
		for _, r := range host {
			if r > 127 {
				return "", fmt.Errorf("올바른 도메인 이름이 아닙니다: %q. 한글 도메인은 xn-- 형태(퓨니코드)로 입력하세요", raw)
			}
		}
		return "", fmt.Errorf("올바른 도메인 이름이 아닙니다: %q", raw)
	}
	return host, nil
}
