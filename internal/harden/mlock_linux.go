//go:build linux

package harden

import "golang.org/x/sys/unix"

func lockPages(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return unix.Mlock(data)
}
