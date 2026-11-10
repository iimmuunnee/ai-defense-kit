package report

import "testing"

// adk의 문구는 한국어라 경로 앞뒤에 조사나 단어가 바로 붙을 수 있다.
func TestScrubHidesPathNextToHangul(t *testing.T) {
	const winRoot = `D:\work\dev\proj`
	cases := []struct {
		name, root string
		others     []string
		in, want   string
	}{
		{"뒤에 조사, 역슬래시", winRoot, nil, `D:\work\dev\proj에서 실패`, `.에서 실패`},
		{"뒤에 조사, 슬래시", winRoot, nil, `D:/work/dev/proj에서 실패`, `.에서 실패`},
		{"뒤에 조사, Unix", "/home/me/proj", nil, `/home/me/proj에서`, `.에서`},
		{"앞에 한글", winRoot, nil, `경로D:\work\dev\proj\a`, `경로.\a`},
		{"앞부분이 빠진 형태 뒤에 조사", winRoot, nil, `work/dev/proj에서`, `.에서`},
		{"앞부분이 빠진 형태 앞에 한글", winRoot, nil, `파일work/dev/proj/a`, `파일./a`},
		{"다른 경로 뒤에 조사", "", []string{`D:\db`}, `D:\db를 열지 못함`, `<경로>를 열지 못함`},
		{"한글 폴더 이름 뒤에 조사", `D:\내 프로젝트\앱`, nil, `D:\내 프로젝트\앱에서`, `.에서`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Scrub(c.in, c.root, c.others); got != c.want {
				t.Errorf("Scrub(%q) = %q, 기대값 %q", c.in, got, c.want)
			}
		})
	}
}

func TestScrubHidesPathBeforeDots(t *testing.T) {
	const root = `D:\work\dev\proj`
	cases := []struct{ in, want string }{
		{`D:\work\dev\proj...`, `....`},
		{`D:\work\dev\proj..\x`, `...\x`},
	}
	for _, c := range cases {
		if got := Scrub(c.in, root, nil); got != c.want {
			t.Errorf("Scrub(%q) = %q, 기대값 %q", c.in, got, c.want)
		}
	}
}

// 영문 이름이 이어지는 경우는 여전히 다른 이름이므로 건드리지 않는다.
func TestScrubKeepsLatinNameBoundaries(t *testing.T) {
	const root = "/home/me/proj"
	for _, in := range []string{
		"/home/me/proj2/a",
		"/home/me/proj_backup/a",
		"/home/me/proj-old/a",
		"/home/me/proj.bak/a",
	} {
		if got := Scrub(in, root, nil); got != in {
			t.Errorf("Scrub(%q) = %q, 그대로여야 함", in, got)
		}
	}
}
