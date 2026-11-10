package watch

import "errors"

// ErrSomeUnread is wrapped by the PartialError of an observation in which some
// containers could not be read and nothing else went wrong. One pod that has
// not pulled its image says nothing about the others, so init and accept take
// what was read. Every other partial read is refused by them.
var ErrSomeUnread = errors.New("일부 컨테이너를 읽지 못했습니다")

// someUnreadError is the error of such an observation. The text is short; names
// holds every container.
type someUnreadError struct {
	msg   string
	names []string
}

func (e someUnreadError) Error() string        { return e.msg }
func (e someUnreadError) Is(target error) bool { return target == ErrSomeUnread }

// SomeUnread returns the fields read and the names of the containers not read,
// when err is an ErrSomeUnread observation.
func SomeUnread(err error) (Observation, []string, bool) {
	var pe PartialError
	var su someUnreadError
	if !errors.As(err, &pe) || !errors.As(err, &su) {
		return nil, nil, false
	}
	return pe.Obs, su.names, true
}
