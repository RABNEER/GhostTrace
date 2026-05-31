//go:build windows

package scanner

import (
	"context"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

const (
	processQueryInformation = 0x0400
	processVMRead           = 0x0010
	memCommit               = 0x1000
	memPrivate              = 0x20000
	pageNoAccess            = 0x01
	pageGuard               = 0x100
	pageExecute             = 0x10
	pageExecuteRead         = 0x20
	pageExecuteReadWrite    = 0x40
	pageExecuteWriteCopy    = 0x80
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess      = kernel32.NewProc("OpenProcess")
	procCloseHandle      = kernel32.NewProc("CloseHandle")
	procVirtualQueryEx   = kernel32.NewProc("VirtualQueryEx")
	procReadProcessMemory = kernel32.NewProc("ReadProcessMemory")
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionID       uint16
	_                 uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	_                 uint32
}

func (s *Scanner) scanProcessWindows(ctx context.Context, pid uint32) ([]ScanHit, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	handle, err := openWindowsProcess(pid)
	if err != nil {
		return nil, err
	}
	defer closeWindowsHandle(handle)

	hits := make([]ScanHit, 0)
	for addr := uintptr(0); ; {
		if err := ctx.Err(); err != nil {
			return hits, err
		}

		var mbi memoryBasicInformation
		rc, _, _ := procVirtualQueryEx.Call(
			handle,
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if rc == 0 {
			break
		}

		if executablePrivateRegion(mbi) {
			regionHits := s.scanWindowsRegion(ctx, handle, pid, mbi.BaseAddress, uint64(mbi.RegionSize))
			hits = append(hits, regionHits...)
		}

		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
	}
	return hits, nil
}

func (s *Scanner) scanWindowsRegion(ctx context.Context, handle uintptr, pid uint32, base uintptr, size uint64) []ScanHit {
	const chunkSize = 1 << 20
	maxPat := s.maxPatternLen()
	if maxPat == 0 || size == 0 {
		return nil
	}

	overlap := maxPat - 1
	buf := make([]byte, chunkSize+overlap)
	carry := make([]byte, 0, overlap)
	hits := make([]ScanHit, 0)

	for offset := uint64(0); offset < size; {
		if ctx.Err() != nil {
			return hits
		}

		toRead := uint64(chunkSize)
		if remaining := size - offset; remaining < toRead {
			toRead = remaining
		}
		if toRead == 0 {
			break
		}

		n, ok := readProcessMemory(handle, base+uintptr(offset), buf[len(carry):len(carry)+int(toRead)])
		if !ok || n == 0 {
			offset += toRead
			carry = carry[:0]
			continue
		}

		window := buf[:len(carry)+n]
		if len(carry) > 0 {
			copy(window[len(carry):], buf[len(carry):len(carry)+n])
			copy(window[:len(carry)], carry)
		}

		for _, pattern := range s.patterns {
			if len(pattern.Bytes) == 0 || len(window) < len(pattern.Bytes) {
				continue
			}
			if idx := ScanBytes(window, pattern.Bytes); idx >= 0 {
				hits = append(hits, ScanHit{
					PID:         pid,
					Addr:        uint64(base) + offset - uint64(len(carry)) + uint64(idx),
					PatternName: pattern.Name,
					Offset:      int64(offset) - int64(len(carry)) + idx,
				})
			}
		}

		if len(window) < overlap {
			carry = append(carry[:0], window...)
		} else {
			carry = append(carry[:0], window[len(window)-overlap:]...)
		}
		offset += uint64(n)
	}
	return hits
}

func openWindowsProcess(pid uint32) (uintptr, error) {
	handle, _, err := procOpenProcess.Call(processQueryInformation|processVMRead, 0, uintptr(pid))
	if handle == 0 {
		if err != syscall.Errno(0) {
			return 0, err
		}
		return 0, fmt.Errorf("open process %d failed", pid)
	}
	return handle, nil
}

func closeWindowsHandle(handle uintptr) {
	if handle != 0 {
		procCloseHandle.Call(handle)
	}
}

func readProcessMemory(handle uintptr, addr uintptr, out []byte) (int, bool) {
	if len(out) == 0 {
		return 0, true
	}
	var read uintptr
	rc, _, _ := procReadProcessMemory.Call(
		handle,
		addr,
		uintptr(unsafe.Pointer(&out[0])),
		uintptr(len(out)),
		uintptr(unsafe.Pointer(&read)),
	)
	return int(read), rc != 0 && read > 0
}

func executablePrivateRegion(mbi memoryBasicInformation) bool {
	if mbi.State != memCommit || mbi.Type != memPrivate {
		return false
	}
	if mbi.Protect&pageGuard != 0 || mbi.Protect&pageNoAccess != 0 {
		return false
	}
	switch mbi.Protect & 0xff {
	case pageExecute, pageExecuteRead, pageExecuteReadWrite, pageExecuteWriteCopy:
		return true
	default:
		return false
	}
}
