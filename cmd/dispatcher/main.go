package main

import (
	"os"
	"os/exec"
)

func main() {
	args := append([]string{"run", "./cmd/atde", "-mode", "dispatch"}, os.Args[1:]...)
	cmd := exec.Command("go", args...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		os.Exit(1)
	}
}
