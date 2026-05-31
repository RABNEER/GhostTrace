//go:build windows

package windowsmon

import (
	"context"
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	th32csSnapProcess = 0x00000002
	maxPath           = 260
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW      = kernel32.NewProc("Process32FirstW")
	procProcess32NextW       = kernel32.NewProc("Process32NextW")
	procCloseHandle          = kernel32.NewProc("CloseHandle")
)

type Process struct {
	PID     uint32
	PPID    uint32
	Comm    string
	ExePath string
}

type processEntry32 struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [maxPath]uint16
}

func Snapshot(ctx context.Context) ([]Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	handle, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if handle == uintptr(syscall.InvalidHandle) || handle == 0 {
		if err != syscall.Errno(0) {
			return nil, err
		}
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed")
	}
	defer procCloseHandle.Call(handle)

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	rc, _, err := procProcess32FirstW.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if rc == 0 {
		if err != syscall.Errno(0) {
			return nil, err
		}
		return nil, fmt.Errorf("Process32FirstW failed")
	}

	out := make([]Process, 0, 256)
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		name := syscall.UTF16ToString(entry.ExeFile[:])
		out = append(out, Process{
			PID:     entry.ProcessID,
			PPID:    entry.ParentProcessID,
			Comm:    filepath.Base(name),
			ExePath: name,
		})

		rc, _, _ = procProcess32NextW.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if rc == 0 {
			break
		}
	}
	return out, nil
}
