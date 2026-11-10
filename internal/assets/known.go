package assets

import (
	"fmt"
	"os"
	"strings"
)

// Known은 운영자가 아는 이름 목록이다.
type Known struct {
	exact    map[string]bool
	wildcard map[string]bool // "*.x" 항목의 x
}

// LoadKnown은 --known 파일을 읽는다. '#' 주석, 빈 줄, BOM, CRLF를 처리하고 소문자로 바꾼다.
// 줄 끝 주석은 공백(스페이스나 탭) 뒤의 '#'부터다.
// 도메인 문법에 맞지 않는 줄은 줄 번호와 함께 오류로 돌려준다.
func LoadKnown(path string) (Known, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Known{}, fmt.Errorf("알려진 목록 파일을 읽지 못했습니다: %w", err)
	}
	k := Known{exact: map[string]bool{}, wildcard: map[string]bool{}}
	text := strings.TrimPrefix(string(data), "\ufeff")
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(stripComment(strings.TrimSuffix(line, "\r")))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(line), ".")
		wild := strings.HasPrefix(name, "*.")
		if wild {
			name = name[2:]
		}
		if !validHostname(name) {
			return Known{}, fmt.Errorf("%s:%d: 올바른 도메인 이름이 아닙니다: %q", path, i+1, line)
		}
		if wild {
			k.wildcard[name] = true
		} else {
			k.exact[name] = true
		}
	}
	return k, nil
}

// stripComment는 줄 맨 앞이나 공백 뒤의 '#'부터 줄 끝까지를 지운다.
func stripComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
}

// Has는 name을 아는 이름으로 볼 수 있는지 돌려준다.
// "*.x" 항목은 x 아래의 모든 이름을 덮지만 x 자신은 덮지 않는다.
func (k Known) Has(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if k.exact[name] {
		return true
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '.' && k.wildcard[name[i+1:]] {
			return true
		}
	}
	return false
}

// Unknown은 알려진 목록에 없는 자산만 순서를 유지해 돌려준다.
// "*.x" 인증서로만 본 이름 x(Wildcard)는 목록에 "*.x"가 있으면 아는 것으로 본다.
func Unknown(assets []Asset, k Known) []Asset {
	out := []Asset{}
	for _, a := range assets {
		if a.Wildcard && k.wildcard[strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a.Name)), ".")] {
			continue
		}
		if !k.Has(a.Name) {
			out = append(out, a)
		}
	}
	return out
}
