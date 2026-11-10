package watch

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
)

const kindPods = "k8s-pods"

const (
	// defaultPodsMaxAge is how old the exported file may be before what it
	// says counts as possibly out of date. It is a judgement call that has not
	// been measured against real export schedules.
	defaultPodsMaxAge = 24 * time.Hour
	// podsClockSkew is how far ahead of now the file's modification time may
	// be before the time is distrusted.
	podsClockSkew = 5 * time.Minute

	// unknownRegistry stands for an image whose registry cannot be told from
	// its name (for example one that kubelet reports only by its digest).
	unknownRegistry = "(알 수 없음)"

	imageField    = "image:"
	registryField = "registry:"
)

var knownPodsOptions = map[string]bool{"file": true, "allowed_registries": true, "max_age": true}

// podsOptions are the checked options of a k8s-pods target.
type podsOptions struct {
	file     string // as written
	identity string // cleaned, with forward slashes
	maxAge   time.Duration
	allowed  map[string]bool // lower-case registries; empty means no restriction
}

var registryName = regexp.MustCompile(`^[a-z0-9][a-z0-9._:\-\[\]]*$`)

func parsePodsOptions(opts map[string]any) (podsOptions, error) {
	for _, k := range slices.Sorted(maps.Keys(opts)) {
		if !knownPodsOptions[k] {
			return podsOptions{}, fmt.Errorf("알 수 없는 옵션 %q입니다", k)
		}
	}
	file, ok := opts["file"].(string)
	if !ok || strings.TrimSpace(file) == "" {
		return podsOptions{}, errors.New("file 옵션에 kubectl get pods -A -o json으로 내보낸 파일의 경로를 문자열로 적어야 합니다")
	}
	file = strings.TrimSpace(file)
	p := podsOptions{file: file, identity: path.Clean(filepath.ToSlash(file)), maxAge: defaultPodsMaxAge}
	if v, set := opts["max_age"]; set {
		s, ok := v.(string)
		if !ok {
			return podsOptions{}, errors.New(`max_age: "24h"처럼 따옴표로 감싼 시간 문자열이어야 합니다 ("0"이면 끕니다)`)
		}
		d, err := time.ParseDuration(strings.TrimSpace(s))
		if err != nil || d < 0 {
			return podsOptions{}, errors.New(`max_age: "24h"처럼 0 이상의 시간이어야 합니다 ("0"이면 끕니다)`)
		}
		p.maxAge = d
	}
	list, err := stringList("allowed_registries", opts["allowed_registries"])
	if err != nil {
		return podsOptions{}, err
	}
	for i, r := range list {
		r = strings.ToLower(strings.TrimSpace(r))
		if !registryName.MatchString(r) {
			return podsOptions{}, fmt.Errorf("allowed_registries의 %d번째: registry.example.com이나 localhost:5000처럼 호스트(와 포트)만 적어야 합니다", i+1)
		}
		if p.allowed == nil {
			p.allowed = map[string]bool{}
		}
		p.allowed[r] = true
	}
	return p, nil
}

func validatePodsOptions(opts map[string]any) error {
	_, err := parsePodsOptions(opts)
	return err
}

// podsAllowed returns the allowed registries of a k8s-pods target, empty when
// there is no restriction.
func podsAllowed(t Target) map[string]bool {
	if t.Kind != kindPods {
		return nil
	}
	p, err := parsePodsOptions(t.Options)
	if err != nil {
		return nil
	}
	return p.allowed
}

type podsObserver struct {
	now  func() time.Time
	open func(string) (*os.File, error) // nil means os.Open
}

// NewPodsObserver returns the observer for kind "k8s-pods". It reads one file
// that the user exported with kubectl; it runs nothing and connects nowhere.
// now is the clock the age of the file is judged by.
func NewPodsObserver(now func() time.Time) Observer {
	if now == nil {
		now = time.Now
	}
	return &podsObserver{now: now}
}

func (*podsObserver) Kind() string { return kindPods }

// The fields of a pod that are read. Nothing of the spec is decoded: env
// values and args can hold secrets.
type podOwner struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller *bool  `json:"controller"`
}

type podStatus struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	ImageID string `json:"imageID"`
}

type podDoc struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Labels    struct {
			Hash string `json:"pod-template-hash"`
		} `json:"labels"`
		OwnerReferences []podOwner `json:"ownerReferences"`
	} `json:"metadata"`
	Status struct {
		Phase               string      `json:"phase"`
		Containers          []podStatus `json:"containerStatuses"`
		InitContainers      []podStatus `json:"initContainerStatuses"`
		EphemeralContainers []podStatus `json:"ephemeralContainerStatuses"`
	} `json:"status"`
}

// podsAgg collects what the replicas of one container say. job marks a
// container of a Job, whose finished runs always count.
type podsAgg struct {
	live, finished podsSet
	job            bool
}

// podsSet is what some pods say about a container.
type podsSet struct {
	seen                bool
	digests, registries map[string]bool
}

func (s *podsSet) add(image, imageID string) {
	if !s.seen {
		s.seen = true
		s.digests, s.registries = map[string]bool{}, map[string]bool{}
	}
	s.registries[registryOf(image)] = true
	if d := digestOf(imageID); d != "" {
		s.digests[d] = true
	}
}

// mergeSets is the union of what two sets of pods say.
func mergeSets(a, b podsSet) podsSet {
	out := podsSet{seen: a.seen || b.seen, digests: map[string]bool{}, registries: map[string]bool{}}
	for _, s := range []podsSet{a, b} {
		maps.Copy(out.digests, s.digests)
		maps.Copy(out.registries, s.registries)
	}
	return out
}

// value is what counts for the container. Pods that finished (phase Failed or
// Succeeded: evicted or left over from an old rollout) count only when no pod
// of that container is in another phase. The runs of a Job are the exception:
// a finished run did run its image, so every run counts, live or finished.
func (a *podsAgg) value() podsSet {
	if a.job {
		return mergeSets(a.live, a.finished)
	}
	if a.live.seen {
		return a.live
	}
	return a.finished
}

const exportHint = "kubectl get pods -A -o json 으로 내보낸 파일이어야 합니다"

func shapeError(msg string) error {
	return fmt.Errorf("파드 목록 파일을 읽을 수 없습니다: %s. %s", msg, exportHint)
}

func (o *podsObserver) Observe(ctx context.Context, t Target) (Observation, error) {
	opts, err := parsePodsOptions(t.Options)
	if err != nil {
		return nil, err
	}
	notRegular := errors.New("file이 일반 파일이 아닙니다. kubectl get pods -A -o json 의 결과를 담은 파일을 가리켜야 합니다")
	cannotOpen := errors.New("파드 목록 파일을 열 수 없습니다. file 경로와 권한을 확인하세요")
	// Before opening: opening a FIFO waits for a writer, on and on.
	st, err := os.Stat(opts.file)
	if err != nil {
		return nil, cannotOpen
	}
	if !st.Mode().IsRegular() {
		return nil, notRegular
	}
	open := o.open
	if open == nil {
		open = os.Open
	}
	f, err := open(opts.file)
	if err != nil {
		return nil, cannotOpen
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errors.New("파드 목록 파일의 정보를 읽지 못했습니다")
	}
	if !info.Mode().IsRegular() {
		return nil, notRegular
	}

	aggs, err := readPods(ctx, f)
	if err != nil {
		return nil, err
	}

	obs := Observation{"file": opts.identity}
	var unread []string
	for _, k := range slices.Sorted(maps.Keys(aggs)) {
		a := aggs[k].value()
		if len(a.digests) == 0 {
			// Finished and never pulled: it ran no image, so there is nothing to
			// read. Left in, one such pod would keep the target at exit 2 for good.
			if !aggs[k].live.seen {
				continue
			}
			unread = append(unread, k)
			continue
		}
		obs[imageField+k] = strings.Join(slices.Sorted(maps.Keys(a.digests)), ",")
		obs[registryField+k] = strings.Join(slices.Sorted(maps.Keys(a.registries)), ",")
	}

	var problems []string
	stale := false
	now, mtime := o.now(), info.ModTime()
	switch {
	case mtime.After(now.Add(podsClockSkew)):
		problems = append(problems, "파일 수정 시각이 지금보다 앞서 있어 얼마나 오래된 내보내기인지 알 수 없습니다. 이 기기의 시계와 파일 시각을 확인하세요")
	case opts.maxAge > 0 && now.Sub(mtime) > opts.maxAge:
		stale = true
		problems = append(problems, fmt.Sprintf("내보낸 파일이 오래되었습니다(수정 시각이 %s 전, max_age %s)", now.Sub(mtime).Round(time.Minute), opts.maxAge))
	}
	if len(unread) > 0 {
		shown := unread[:min(len(unread), 3)]
		msg := fmt.Sprintf("컨테이너 %d개는 imageID에 sha256 digest가 없어 확인하지 못했습니다(예: %s)", len(unread), strings.Join(shown, ", "))
		if len(unread) > len(shown) {
			msg += " 등"
		}
		problems = append(problems, msg)
	}
	if len(problems) == 0 {
		return obs, nil
	}
	msg := strings.Join(problems, "; ")
	switch {
	case stale:
		return nil, PartialError{Obs: obs, Err: staleError{msg: msg}}
	case len(problems) == 1 && len(unread) > 0:
		return nil, PartialError{Obs: obs, Err: someUnreadError{msg: msg, names: unread}}
	}
	return nil, PartialError{Obs: obs, Err: errors.New(msg)}
}

// readPods streams the file once. It accepts only the List that
// `kubectl get pods -A -o json` writes.
func readPods(ctx context.Context, r io.Reader) (map[string]*podsAgg, error) {
	dec := json.NewDecoder(bufio.NewReader(ctxReader{ctx, r}))
	bad := func() error {
		// A read stopped by the deadline is not a broken file.
		if err := ctx.Err(); err != nil {
			return err
		}
		return shapeError(fmt.Sprintf("JSON이 아니거나 중간에 끊긴 파일입니다(바이트 %d 근처)", dec.InputOffset()))
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, bad()
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, shapeError("맨 위가 객체가 아닙니다")
	}
	aggs := map[string]*podsAgg{}
	var kind string
	sawKind, sawItems := false, false
	for dec.More() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		kt, err := dec.Token()
		if err != nil {
			return nil, bad()
		}
		key, _ := kt.(string)
		switch key {
		case "kind":
			if sawKind {
				return nil, shapeError("kind가 두 번 있습니다")
			}
			sawKind = true
			if err := dec.Decode(&kind); err != nil {
				return nil, shapeError("kind가 문자열이 아닙니다")
			}
		case "items":
			if sawItems {
				return nil, shapeError("items가 두 번 있습니다")
			}
			sawItems = true
			if err := readItems(ctx, dec, aggs); err != nil {
				return nil, err
			}
		default:
			if err := skipValue(dec); err != nil {
				return nil, bad()
			}
		}
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, bad()
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, shapeError("목록 뒤에 다른 내용이 더 있습니다")
	}
	switch {
	case kind == "Pod":
		return nil, shapeError("파드 하나만 담은 파일(kubectl get pod <이름> -o json)은 받지 않습니다")
	case kind != "List":
		return nil, shapeError("kind가 List가 아닙니다")
	case !sawItems:
		return nil, shapeError("items가 없습니다")
	}
	return aggs, nil
}

func readItems(ctx context.Context, dec *json.Decoder, aggs map[string]*podsAgg) error {
	bad := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return shapeError(fmt.Sprintf("JSON이 아니거나 중간에 끊긴 파일이거나 파드 형식이 아닙니다(바이트 %d 근처)", dec.InputOffset()))
	}
	tok, err := dec.Token()
	if err != nil {
		return bad()
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return shapeError("items가 목록이 아닙니다")
	}
	for dec.More() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var p podDoc
		if err := dec.Decode(&p); err != nil {
			return bad()
		}
		if p.Kind != "Pod" {
			return shapeError("items에 Pod가 아닌 항목이 있습니다")
		}
		if p.Metadata.Name == "" || p.Metadata.Namespace == "" {
			return shapeError("이름이나 네임스페이스가 없는 파드가 있습니다")
		}
		kind, name := workloadOf(p)
		workload := kind + ":" + name
		// An unknown or missing phase counts as live.
		finished := p.Status.Phase == "Failed" || p.Status.Phase == "Succeeded"
		for _, group := range [][]podStatus{p.Status.Containers, p.Status.InitContainers, p.Status.EphemeralContainers} {
			for _, c := range group {
				if c.Name == "" {
					return shapeError("이름이 없는 컨테이너 상태가 있습니다")
				}
				k := p.Metadata.Namespace + "/" + workload + "/" + c.Name
				a := aggs[k]
				if a == nil {
					a = &podsAgg{job: kind == "job"}
					aggs[k] = a
				}
				if finished && a.job && digestOf(c.ImageID) == "" {
					// A run that finished without ever pulling an image ran nothing.
					continue
				}
				if finished {
					a.finished.add(c.Image, c.ImageID)
				} else {
					a.live.add(c.Image, c.ImageID)
				}
			}
		}
	}
	if _, err := dec.Token(); err != nil { // the closing bracket
		return bad()
	}
	return nil
}

// skipValue consumes one JSON value without keeping it.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			default:
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

// workloadOf names the workload a pod belongs to, so that pod names, which
// change on every restart, do not. It returns the kind of the workload, lower
// case, and its name; workloads of different kinds are never one workload, so
// a Job cannot hide in a Deployment of the same name. A ReplicaSet loses its
// template hash (kind "deployment") when the pod's own pod-template-hash label
// says what it is; without that label the ReplicaSet's name is kept whole
// (kind "replicaset") rather than guessed at. A Job loses the number a CronJob
// gives each run, and a static pod the name of its node: both change while the
// workload does not. Only ownerReferences are used for that.
func workloadOf(p podDoc) (kind, name string) {
	var owner *podOwner
	for i := range p.Metadata.OwnerReferences {
		o := &p.Metadata.OwnerReferences[i]
		if o.Name == "" {
			continue
		}
		if o.Controller != nil && *o.Controller {
			owner = o
			break
		}
		if owner == nil {
			owner = o
		}
	}
	if owner == nil {
		return "pod", p.Metadata.Name
	}
	switch owner.Kind {
	case "ReplicaSet":
		if h := p.Metadata.Labels.Hash; h != "" && len(owner.Name) > len(h)+1 && strings.HasSuffix(owner.Name, "-"+h) {
			return "deployment", strings.TrimSuffix(owner.Name, "-"+h)
		}
		return "replicaset", owner.Name
	case "StatefulSet":
		return "statefulset", owner.Name
	case "DaemonSet":
		return "daemonset", owner.Name
	case "Job":
		if loc := cronRunSuffix.FindStringIndex(owner.Name); loc != nil && loc[0] > 0 {
			return "job", owner.Name[:loc[0]]
		}
		return "job", owner.Name
	case "Node":
		// The node's name says where it runs, not what it is.
		if base, ok := strings.CutSuffix(p.Metadata.Name, "-"+owner.Name); ok && base != "" {
			return "node", base
		}
		return "node", p.Metadata.Name
	}
	return otherKind(owner.Kind), owner.Name
}

// otherKind is the field-name form of an owner kind that has no rule of its
// own: lower case, with everything outside [a-z0-9.-] removed, so that an
// export cannot shape field names with it. The result never equals a kind
// that has a rule (a kind spelled differently must not merge into it), and is
// never empty.
func otherKind(kind string) string {
	k := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		}
		return -1
	}, strings.ToLower(kind))
	switch k {
	case "":
		return "unknown"
	case "deployment", "replicaset", "statefulset", "daemonset", "job", "node", "pod", "unknown":
		return k + "-other"
	}
	return k
}

// cronRunSuffix is what a CronJob adds to the name of each Job it starts.
var cronRunSuffix = regexp.MustCompile(`-[0-9]{8,}$`)

var digestRe = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// digestOf returns the sha256:<64 hex> inside an imageID, whatever prefix the
// container runtime put before it (docker-pullable://, a repository path).
// The tag of an image is never a digest: without one it returns "".
func digestOf(imageID string) string {
	locs := digestRe.FindAllStringIndex(imageID, -1)
	for i := len(locs) - 1; i >= 0; i-- {
		s, e := locs[i][0], locs[i][1]
		if e < len(imageID) && isAlnum(imageID[e]) {
			continue
		}
		if s > 0 && isAlnum(imageID[s-1]) {
			continue
		}
		return imageID[s:e]
	}
	return ""
}

// registryOf returns the registry an image name points at. The first path
// segment is a registry only if it holds a dot or a colon or is localhost;
// otherwise the image is on docker.io.
func registryOf(image string) string {
	img := strings.TrimSpace(image)
	if i := strings.Index(img, "@"); i >= 0 {
		img = img[:i]
	}
	if img == "" || strings.IndexFunc(img, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return unknownRegistry
	}
	first, _, hasSlash := strings.Cut(img, "/")
	if !hasSlash {
		if strings.HasPrefix(img, "sha256:") {
			return unknownRegistry
		}
		return "docker.io"
	}
	reg := "docker.io"
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		reg = strings.ToLower(first)
	}
	if !registryName.MatchString(reg) {
		return unknownRegistry
	}
	return reg
}

// checkInitialPods refuses an export with no container in it: a wrong file
// would read as every workload removed, or as clean, forever.
func checkInitialPods(t Target, obs Observation) error {
	for k := range obs {
		if strings.HasPrefix(k, imageField) {
			return nil
		}
	}
	return fmt.Errorf("대상 %s: file에서 읽을 수 있는 컨테이너를 하나도 찾지 못했습니다. 목록이 비었거나 파일이 잘못되었을 수 있습니다", t.Key)
}

// outsideImages finds what was observed from outside each target's allow list,
// partial reads included. A container whose image or registry changed is left
// out: its change is the finding, and says so. The allow list is the approval,
// so what the baseline holds does not matter, and accept cannot clear this.
func outsideImages(cfg Config, o Outcome) []OutsideImage {
	changed := map[string]bool{}
	for _, c := range o.Changes {
		if name, ok := strings.CutPrefix(c.Field, imageField); ok {
			changed[c.Key+"\x00"+name] = true
		} else if name, ok := strings.CutPrefix(c.Field, registryField); ok {
			changed[c.Key+"\x00"+name] = true
		}
	}
	var out []OutsideImage
	for _, t := range cfg.Targets {
		allowed := podsAllowed(t)
		if len(allowed) == 0 {
			continue
		}
		obs := o.Observed[t.Key]
		for _, f := range slices.Sorted(maps.Keys(obs)) {
			name, ok := strings.CutPrefix(f, registryField)
			if !ok || changed[t.Key+"\x00"+name] {
				continue
			}
			if outside := registriesOutside(obs[f], allowed); len(outside) > 0 {
				out = append(out, OutsideImage{Key: t.Key, Name: name, Registries: strings.Join(outside, ",")})
			}
		}
	}
	slices.SortFunc(out, func(a, b OutsideImage) int {
		if c := strings.Compare(a.Key, b.Key); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

// OutsideAllowedRegistries lists the containers of a k8s-pods observation
// whose image comes from a registry outside allowed_registries, as
// "namespace/kind:workload/container (registry)". Fields named in skip (for example
// ones that changed and are already a finding) are left out. With no
// allowed_registries nothing is outside.
func OutsideAllowedRegistries(t Target, obs Observation, skip map[string]bool) []string {
	allowed := podsAllowed(t)
	if len(allowed) == 0 {
		return nil
	}
	var out []string
	for _, f := range slices.Sorted(maps.Keys(obs)) {
		name, ok := strings.CutPrefix(f, registryField)
		if !ok || skip[f] || skip[imageField+name] {
			continue
		}
		if outside := registriesOutside(obs[f], allowed); len(outside) > 0 {
			out = append(out, name+" ("+strings.Join(outside, ",")+")")
		}
	}
	return out
}

// registriesOutside returns the registries of a comma-joined value that are
// not in allowed.
func registriesOutside(joined string, allowed map[string]bool) []string {
	var out []string
	for _, r := range strings.Split(joined, ",") {
		if r != "" && !allowed[r] {
			out = append(out, r)
		}
	}
	return out
}
