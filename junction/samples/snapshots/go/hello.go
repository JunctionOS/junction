package main

import "C"

import (
	"fmt"
	"syscall"
)

func main() {
	fmt.Println("Hello from go world!")

	// wait for snapshot
	syscall.Kill(syscall.Getpid(), syscall.SIGSTOP)

	fmt.Println("wait over")
}
