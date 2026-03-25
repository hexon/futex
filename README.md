# futex

[![Go Reference](https://pkg.go.dev/badge/github.com/hexon/futex.svg)](https://pkg.go.dev/github.com/hexon/futex)

This library provides functions for using Futexes. They are thin wrappers around the system call futex(2).

I'm hoping you'll only use this for cross-process communication and use the regular `sync` package if you don't need that. But I'm a README, not a cop.

I recommend you only use addresses you mmap()ed yourself, because Go might one day get a moving garbage collector.
