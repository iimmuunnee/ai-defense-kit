package watch

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func unreadJob(name string) tp {
	return tp{ns: "ops", name: name + "-x", ownerKind: "Job", ownerName: name, ctrs: []pj{{name: "main", image: "reg.example.com/job:latest"}}}
}

func TestPodsSomeUnreadIsItsOwnClass(t *testing.T) {
	good := rsPod("web-1-a", "1", ctr("web", podsWeb, dgA))
	tg := podsTarget(podsFile(t, podList(good, unreadJob("job-a"), unreadJob("job-b"), unreadJob("job-c"), unreadJob("job-d")), time.Hour), nil)
	_, err := observePods(tg)
	if !errors.Is(err, ErrSomeUnread) {
		t.Fatalf("err = %v, want ErrSomeUnread", err)
	}
	obs, names, ok := SomeUnread(err)
	if !ok || obs["image:default/deployment:web/web"] != dgA {
		t.Fatalf("SomeUnread: obs=%v ok=%v", obs, ok)
	}
	// All the names, also those the short error text leaves out.
	want := []string{"ops/job:job-a/main", "ops/job:job-b/main", "ops/job:job-c/main", "ops/job:job-d/main"}
	if !slices.Equal(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}

	t.Run("a stale export stays stale", func(t *testing.T) {
		tg := podsTarget(podsFile(t, podList(good, unreadJob("job-a")), 48*time.Hour), nil)
		_, err := observePods(tg)
		if !errors.Is(err, ErrStale) || errors.Is(err, ErrSomeUnread) {
			t.Errorf("err = %v", err)
		}
		if _, _, ok := SomeUnread(err); ok {
			t.Error("a stale export was offered for adoption")
		}
	})
	t.Run("a file from the future is not only unread", func(t *testing.T) {
		tg := podsTarget(podsFile(t, podList(good, unreadJob("job-a")), -time.Hour), nil)
		_, err := observePods(tg)
		var pe PartialError
		if !errors.As(err, &pe) || errors.Is(err, ErrSomeUnread) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("other partial reads are not in the class", func(t *testing.T) {
		if _, _, ok := SomeUnread(PartialError{Obs: Observation{"a": "b"}, Err: errors.New("x")}); ok {
			t.Error("a generic partial read was offered for adoption")
		}
		if _, _, ok := SomeUnread(errors.New("x")); ok {
			t.Error("a plain error was offered for adoption")
		}
	})
}

// M4: a pod that finished without ever pulling ran no image.
func TestPodsFinishedWithoutDigestIsIgnored(t *testing.T) {
	good := rsPod("web-1-a", "1", ctr("web", podsWeb, dgA))
	for _, phase := range []string{"Failed", "Succeeded"} {
		t.Run(phase, func(t *testing.T) {
			left := phased(unreadJob("left"), phase)
			_, obs := mustPods(t, podList(good, left), nil)
			for k := range obs {
				if strings.Contains(k, "ops/left") {
					t.Errorf("field %s from a pod that never ran an image", k)
				}
			}
		})
	}
	// An evicted replica and a replacement that has not pulled yet: not ignored.
	t.Run("evicted replica and pending replacement stay unread", func(t *testing.T) {
		old := phased(rsPod("web-1-aaa", "1", ctr("app", podsWeb, dgA)), "Failed")
		pend := phased(rsPod("web-1-bbb", "1", pj{name: "app", image: podsNext}), "Pending")
		_, err := observePods(podsTarget(podsFile(t, podList(old, pend), time.Hour), nil))
		_, names, ok := SomeUnread(err)
		if !ok || !slices.Equal(names, []string{"default/deployment:web/app"}) {
			t.Errorf("err = %v names = %v", err, names)
		}
	})
}

// M5: opening a FIFO blocks, so what the path is must be known first.
func TestPodsChecksTheFileBeforeOpeningIt(t *testing.T) {
	dir := t.TempDir()
	opened := false
	o := &podsObserver{now: func() time.Time { return podsNow }, open: func(p string) (*os.File, error) {
		opened = true
		return os.Open(p)
	}}
	_, err := o.Observe(t.Context(), podsTarget(dir, nil))
	if err == nil || !strings.Contains(err.Error(), "일반 파일") {
		t.Errorf("err = %v", err)
	}
	if opened {
		t.Error("a path that is not a regular file was opened")
	}
}

func TestUnreadBehaviourIsDocumented(t *testing.T) {
	s := readText(t, "../../docs/watch.md")
	for _, want := range []string{"쫓겨난", "교체 파드", "digest를 읽지 못한 컨테이너", "기준값의 값을 그대로"} {
		if !strings.Contains(s, want) {
			t.Errorf("docs/watch.md lacks %q", want)
		}
	}
	for _, bad := range []string{"그 컨테이너의 파드 중 digest가 있는 것이 하나라도 있으면", "`init`과 `accept`도 거부합니다. 비어 있는 값을"} {
		if strings.Contains(s, bad) {
			t.Errorf("docs/watch.md still says %q", bad)
		}
	}
}
