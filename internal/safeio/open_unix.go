//go:build unix

package safeio

import "syscall"

// openFlags keep an append open from following a link or waiting on a FIFO
// that was swapped in after the check.
const openFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
