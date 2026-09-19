package web

import (
	"os"
	"syscall"
)

func syscallSignal0() os.Signal { return syscall.Signal(0) }
