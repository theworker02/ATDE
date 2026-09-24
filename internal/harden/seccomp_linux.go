//go:build linux

package harden

import (
	"log/slog"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ApplySeccompSandbox sets NO_NEW_PRIVS, then installs a Seccomp filter that
// kills the process on execve/ptrace-family attempts (defense after RCE).
func ApplySeccompSandbox(log *slog.Logger) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}

	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		if log != nil {
			log.Info("seccomp filter skipped (unsupported arch)", "arch", runtime.GOARCH)
		}
		return nil
	}

	prog := buildKillOnDangerousSyscalls()
	_, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		0,
		uintptr(unsafe.Pointer(prog)),
	)
	if errno != 0 {
		if log != nil {
			log.Warn("full seccomp filter unavailable; NO_NEW_PRIVS set", "errno", errno)
		}
		return nil
	}
	if log != nil {
		log.Info("kernel seccomp engaged", "policy", "kill_on_execve_ptrace")
	}
	return nil
}

func buildKillOnDangerousSyscalls() *unix.SockFprog {
	const (
		auditArchX86_64  = 0xC000003E
		auditArchAARCH64 = 0xC00000B7
		nrExecveX64      = 59
		nrExecveatX64    = 322
		nrPtraceX64      = 101
		nrExecveARM64    = 221
		nrExecveatARM64  = 281
		nrPtraceARM64    = 117
		bpfLD            = 0x20
		bpfJEQ           = 0x15
		bpfRET           = 0x06
		seccompDataArch  = 4
		seccompDataNR    = 0
	)

	arch := uint32(auditArchX86_64)
	nExecve, nExecveat, nPtrace := uint32(nrExecveX64), uint32(nrExecveatX64), uint32(nrPtraceX64)
	if runtime.GOARCH == "arm64" {
		arch = auditArchAARCH64
		nExecve, nExecveat, nPtrace = nrExecveARM64, nrExecveatARM64, nrPtraceARM64
	}

	insns := []unix.SockFilter{
		{Code: bpfLD, K: seccompDataArch},
		{Code: bpfJEQ, Jt: 1, Jf: 0, K: arch},
		{Code: bpfRET, K: unix.SECCOMP_RET_KILL},
		{Code: bpfLD, K: seccompDataNR},
		{Code: bpfJEQ, Jt: 0, Jf: 1, K: nExecve},
		{Code: bpfRET, K: unix.SECCOMP_RET_KILL},
		{Code: bpfJEQ, Jt: 0, Jf: 1, K: nExecveat},
		{Code: bpfRET, K: unix.SECCOMP_RET_KILL},
		{Code: bpfJEQ, Jt: 0, Jf: 1, K: nPtrace},
		{Code: bpfRET, K: unix.SECCOMP_RET_KILL},
		{Code: bpfRET, K: unix.SECCOMP_RET_ALLOW},
	}

	// Keep filter on heap for lifetime of the process.
	heap := make([]unix.SockFilter, len(insns))
	copy(heap, insns)
	return &unix.SockFprog{
		Len:    uint16(len(heap)),
		Filter: &heap[0],
	}
}
