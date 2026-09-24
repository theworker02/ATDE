//go:build !linux

package harden

func lockPages(data []byte) error { return nil }
