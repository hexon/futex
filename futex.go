// man 2 futex
package futex

import (
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type Flags uintptr

const (
	opFUTEX_WAIT            Flags = 0
	opFUTEX_WAKE            Flags = 1
	opFUTEX_REQUEUE         Flags = 3
	opFUTEX_CMP_REQUEUE     Flags = 4

	FUTEX_PRIVATE_FLAG   Flags = 128
	FUTEX_CLOCK_REALTIME Flags = 256
)

const (
	FUTEX_BITSET_MATCH_ANY uint32 = 0xffffffff
)

// Wait tests that the value at the futex word pointed to by the address uaddr
// still contains the expected value val, and if so, then sleeps waiting for a
// [Wake] operation on the futex word. The load of the value of the futex word
// is an atomic memory access (i.e., using atomic machine instructions of the
// respective architecture). This load, the comparison with the expected value,
// and starting to sleep are performed atomically and totally ordered with
// respect to other futex operations on the same futex word. If the thread
// starts to sleep, it is considered a waiter on this futex word. If the futex
// value does not match val, then the call fails immediately with the error
// EAGAIN.
//
// The purpose of the comparison with the expected value is to prevent lost
// wake-ups. If another thread changed the value of the futex word after the
// calling thread decided to block based on the prior value, and if the other
// thread executed a [Wake] operation (or similar wake-up) after the value
// change and before this [Wait] operation, then the calling thread will
// observe the value change and will not start to sleep.
//
// The timeout will be rounded up to the system clock granularity, and is
// guaranteed not to expire early. The timeout is by default measured
// according to the CLOCK_MONOTONIC clock, but, since Linux 4.5, the
// CLOCK_REALTIME clock can be selected by specifying FUTEX_CLOCK_REALTIME in
// flags. If timeout is negative, the call blocks indefinitely.
//
// Returns nil if the caller was woken up. Note that a wake-up can also be
// caused by common futex usage patterns in unrelated code that happened to
// have previously used the futex word's memory location (e.g., typical
// futex-based implementations of Pthreads mutexes can cause this under some
// conditions). Therefore, callers should always conservatively assume that a
// return value of nil can mean a spurious wake-up, and use the futex word's
// value (i.e., the user-space synchronization scheme) to decide whether to
// continue to block or not.
func Wait(uaddr *uint32, flags Flags, val uint32, timeout time.Duration) error {
	uaddr = escape(uaddr)
	futex_op := flags | opFUTEX_WAIT
	var ts *unix.Timespec
	if timeout >= 0 {
		ts = new(unix.Timespec)
		*ts = unix.NsecToTimespec(timeout.Nanoseconds())
	}
	runtime.Gosched()
	_, _, err := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(uaddr)), uintptr(futex_op), uintptr(val), uintptr(unsafe.Pointer(ts)), 0, 0)
	runtime.KeepAlive(ts)
	runtime.KeepAlive(uaddr)
	return errnoToError(err)
}

// Wake at most val of the waiters that are waiting (e.g., inside [Wait]) on
// the futex word at the address uaddr. Most commonly, numWake is specified as
// either 1 (wake up a single waiter) or math.MaxUint32 (wake up all waiters).
// No guarantee is provided about which waiters are awoken (e.g., a waiter with
// a higher scheduling priority is not guaranteed to be awoken in preference to
// a waiter with a lower priority).
//
// Returns the number of waiters that were woken up.
func Wake(uaddr *uint32, flags Flags, numWake uint32) (uint32, error) {
	uaddr = escape(uaddr)
	futex_op := flags | opFUTEX_WAKE
	r1, _, err := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(uaddr)), uintptr(futex_op), uintptr(numWake), 0, 0, 0)
	runtime.KeepAlive(uaddr)
	return uint32(r1), errnoToError(err)
}

// CmpRequeue first checks whether the location uaddr still contains the value
// cmpVal. If not, the operation fails with the error EAGAIN. Otherwise, the
// operation wakes up a maximum of numWake waiters that are waiting on the
// futex at uaddr. If there are more than numWake waiters, then the remaining
// waiters are removed from the wait queue of the source futex at uaddr and
// added to the wait queue of the target futex at uaddr2. The maxRequeue
// argument specifies an upper limit on the number of waiters that are requeued
// to the futex at uaddr2.
//
// The load from uaddr is an atomic memory access (i.e., using atomic machine
// instructions of the respective architecture). This load, the comparison with
// cmpVal, and the requeueing of any waiters are performed atomically and
// totally ordered with respect to other operations on the same futex word.
//
// Typical values to specify for numWake are 0 or 1. (Specifying math.MaxUint32
// is not useful, because it would make the [CmpRequeue] operation
// equivalent to [Wake].) The limit value specified via maxRequeue is
// typically either 1 or math.MaxUint32. (Specifying the argument as 0 is not
// useful, because it would make the [CmpRequeue] operation equivalent to
// [Wait].)
//
// Returns the number of waiters that were woken up.
func CmpRequeue(uaddr *uint32, flags Flags, numWake, maxRequeue uint32, uaddr2 *uint32, cmpVal uint32) (uint32, error) {
	uaddr = escape(uaddr)
	uaddr2 = escape(uaddr2)
	futex_op := flags | opFUTEX_CMP_REQUEUE
	r1, _, err := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(uaddr)), uintptr(futex_op), uintptr(numWake), uintptr(maxRequeue), uintptr(unsafe.Pointer(uaddr2)), uintptr(cmpVal))
	runtime.KeepAlive(uaddr)
	runtime.KeepAlive(uaddr2)
	return uint32(r1), errnoToError(err)
}

// Requeue performs the same task as [CmpRequeue] (see above), except that no
// check is made using the value in cmpVal.
func Requeue(uaddr *uint32, flags Flags, numWake, maxRequeue uint32, uaddr2 *uint32) (uint32, error) {
	uaddr = escape(uaddr)
	uaddr2 = escape(uaddr2)
	futex_op := flags | opFUTEX_REQUEUE
	r1, _, err := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(uaddr)), uintptr(futex_op), uintptr(numWake), uintptr(maxRequeue), uintptr(unsafe.Pointer(uaddr2)), 0)
	runtime.KeepAlive(uaddr)
	runtime.KeepAlive(uaddr2)
	return uint32(r1), errnoToError(err)
}

func WaitBitset(uaddr *uint32, flags Flags, val uint32, deadline time.Time, bitset uint32) error {
	uaddr = escape(uaddr)
	futex_op := flags | opFUTEX_WAIT_BITSET
	var ts *unix.Timespec
	if !deadline.IsZero() {
		ts = new(unix.Timespec)
		var err error
		*ts, err = unix.TimeToTimespec(deadline)
		if err != nil {
			return err
		}
	}
	runtime.Gosched()
	_, _, err := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(uaddr)), uintptr(futex_op), uintptr(val), uintptr(unsafe.Pointer(ts)), 0, uintptr(bitset))
	runtime.KeepAlive(ts)
	runtime.KeepAlive(uaddr)
	return errnoToError(err)
}

func WakeBitset(uaddr *uint32, flags Flags, numWake, bitset uint32) (uint32, error) {
	uaddr = escape(uaddr)
	futex_op := flags | opFUTEX_WAKE_BITSET
	r1, _, err := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(uaddr)), uintptr(futex_op), uintptr(numWake), 0, 0, uintptr(bitset))
	runtime.KeepAlive(uaddr)
	return uint32(r1), errnoToError(err)
}

var alwaysFalse bool
var escapeSink any

// escape forces x to escape to the heap.
// We always force escaping because stack pointers are dangerous because the stack might be moved.
func escape(x *uint32) *uint32 {
	if alwaysFalse {
		escapeSink = x
	}
	return x
}

// Do the interface allocations only once for common
// unix.Errno values.
var (
	errEAGAIN    error = unix.EAGAIN
	errEINTR     error = unix.EINTR
	errEINVAL    error = unix.EINVAL
	errETIMEDOUT error = unix.ETIMEDOUT
)

func errnoToError(e unix.Errno) error {
	switch e {
	case 0:
		return nil
	case unix.EAGAIN:
		return errEAGAIN
	case unix.EINTR:
		return errEINTR
	case unix.EINVAL:
		return errEINVAL
	case unix.ETIMEDOUT:
		return errETIMEDOUT
	}
	return e
}
