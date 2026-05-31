package events

import "time"

const FrameSize = 64

type EventKind uint16

const (
	EventUnknown EventKind = iota
	EventSyscall
	EventMem
	EventProcess
)

type RawEvent struct {
	Data [FrameSize]byte
}

type SyscallEvent struct {
	SyscallNr   uint32   `json:"syscall_nr"`
	PID         uint32   `json:"pid"`
	PPID        uint32   `json:"ppid"`
	Arg0        uint64   `json:"arg0"`
	Arg1        uint64   `json:"arg1"`
	Arg2        uint64   `json:"arg2"`
	TimestampNs uint64   `json:"timestamp_ns"`
	Comm        [16]byte `json:"comm"`
}

type MemEvent struct {
	PID         uint32 `json:"pid"`
	Addr        uint64 `json:"addr"`
	Len         uint64 `json:"len"`
	Prot        uint32 `json:"prot"`
	TimestampNs uint64 `json:"timestamp_ns"`
}

type ProcessEventType string

const (
	ProcessFork            ProcessEventType = "FORK"
	ProcessExec            ProcessEventType = "EXEC"
	ProcessExit            ProcessEventType = "EXIT"
	ProcessInjectSuspected ProcessEventType = "INJECT_SUSPECTED"
)

type ProcessEvent struct {
	Type         ProcessEventType `json:"type"`
	PID          uint32           `json:"pid"`
	PPID         uint32           `json:"ppid"`
	Comm         string           `json:"comm"`
	ExePath      string           `json:"exe_path"`
	TimestampNs  uint64           `json:"timestamp_ns"`
	AnomalyScore float64          `json:"anomaly_score"`
}

type Decoded struct {
	Kind    EventKind
	Syscall SyscallEvent
	Mem     MemEvent
	Process ProcessEvent
}

func UnixNanos(ns uint64) time.Time {
	if ns == 0 {
		return time.Now()
	}
	return time.Unix(0, int64(ns))
}
