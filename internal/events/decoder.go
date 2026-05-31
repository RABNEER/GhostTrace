package events

import (
	"encoding/binary"
	"errors"
	"strings"
)

var (
	ErrShortFrame   = errors.New("short event frame")
	ErrUnknownFrame = errors.New("unknown event frame type")
)

func DecodeRaw(raw RawEvent) (Decoded, error) {
	if len(raw.Data) != FrameSize {
		return Decoded{}, ErrShortFrame
	}

	kind := EventKind(binary.LittleEndian.Uint16(raw.Data[0:2]))
	switch kind {
	case EventSyscall:
		return Decoded{Kind: kind, Syscall: decodeSyscall(raw)}, nil
	case EventMem:
		return Decoded{Kind: kind, Mem: decodeMem(raw)}, nil
	case EventProcess:
		return Decoded{Kind: kind, Process: decodeProcess(raw)}, nil
	default:
		return Decoded{}, ErrUnknownFrame
	}
}

func EncodeSyscall(ev SyscallEvent) RawEvent {
	var raw RawEvent
	binary.LittleEndian.PutUint16(raw.Data[0:2], uint16(EventSyscall))
	binary.LittleEndian.PutUint16(raw.Data[2:4], FrameSize)
	binary.LittleEndian.PutUint32(raw.Data[4:8], ev.SyscallNr)
	binary.LittleEndian.PutUint32(raw.Data[8:12], ev.PID)
	binary.LittleEndian.PutUint32(raw.Data[12:16], ev.PPID)
	binary.LittleEndian.PutUint64(raw.Data[16:24], ev.Arg0)
	binary.LittleEndian.PutUint64(raw.Data[24:32], ev.Arg1)
	binary.LittleEndian.PutUint64(raw.Data[32:40], ev.Arg2)
	binary.LittleEndian.PutUint64(raw.Data[40:48], ev.TimestampNs)
	copy(raw.Data[48:64], ev.Comm[:])
	return raw
}

func EncodeMem(ev MemEvent) RawEvent {
	var raw RawEvent
	binary.LittleEndian.PutUint16(raw.Data[0:2], uint16(EventMem))
	binary.LittleEndian.PutUint16(raw.Data[2:4], FrameSize)
	binary.LittleEndian.PutUint32(raw.Data[4:8], ev.PID)
	binary.LittleEndian.PutUint32(raw.Data[8:12], ev.Prot)
	binary.LittleEndian.PutUint64(raw.Data[16:24], ev.Addr)
	binary.LittleEndian.PutUint64(raw.Data[24:32], ev.Len)
	binary.LittleEndian.PutUint64(raw.Data[32:40], ev.TimestampNs)
	return raw
}

func EncodeProcess(ev ProcessEvent) RawEvent {
	var raw RawEvent
	binary.LittleEndian.PutUint16(raw.Data[0:2], uint16(EventProcess))
	binary.LittleEndian.PutUint16(raw.Data[2:4], FrameSize)
	binary.LittleEndian.PutUint32(raw.Data[4:8], ev.PID)
	binary.LittleEndian.PutUint32(raw.Data[8:12], ev.PPID)
	binary.LittleEndian.PutUint64(raw.Data[16:24], ev.TimestampNs)
	raw.Data[24] = processTypeByte(ev.Type)
	copy(raw.Data[32:48], fixedBytes(ev.Comm, 16))
	copy(raw.Data[48:64], fixedBytes(ev.ExePath, 16))
	return raw
}

func decodeSyscall(raw RawEvent) SyscallEvent {
	var comm [16]byte
	copy(comm[:], raw.Data[48:64])
	return SyscallEvent{
		SyscallNr:   binary.LittleEndian.Uint32(raw.Data[4:8]),
		PID:         binary.LittleEndian.Uint32(raw.Data[8:12]),
		PPID:        binary.LittleEndian.Uint32(raw.Data[12:16]),
		Arg0:        binary.LittleEndian.Uint64(raw.Data[16:24]),
		Arg1:        binary.LittleEndian.Uint64(raw.Data[24:32]),
		Arg2:        binary.LittleEndian.Uint64(raw.Data[32:40]),
		TimestampNs: binary.LittleEndian.Uint64(raw.Data[40:48]),
		Comm:        comm,
	}
}

func decodeMem(raw RawEvent) MemEvent {
	return MemEvent{
		PID:         binary.LittleEndian.Uint32(raw.Data[4:8]),
		Prot:        binary.LittleEndian.Uint32(raw.Data[8:12]),
		Addr:        binary.LittleEndian.Uint64(raw.Data[16:24]),
		Len:         binary.LittleEndian.Uint64(raw.Data[24:32]),
		TimestampNs: binary.LittleEndian.Uint64(raw.Data[32:40]),
	}
}

func decodeProcess(raw RawEvent) ProcessEvent {
	return ProcessEvent{
		Type:        processTypeFromByte(raw.Data[24]),
		PID:         binary.LittleEndian.Uint32(raw.Data[4:8]),
		PPID:        binary.LittleEndian.Uint32(raw.Data[8:12]),
		TimestampNs: binary.LittleEndian.Uint64(raw.Data[16:24]),
		Comm:        trimCString(raw.Data[32:48]),
		ExePath:     trimCString(raw.Data[48:64]),
	}
}

func fixedBytes(s string, n int) []byte {
	out := make([]byte, n)
	copy(out, s)
	return out
}

func trimCString(b []byte) string {
	if idx := strings.IndexByte(string(b), 0); idx >= 0 {
		return string(b[:idx])
	}
	return string(b)
}

func processTypeByte(t ProcessEventType) byte {
	switch t {
	case ProcessFork:
		return 1
	case ProcessExec:
		return 2
	case ProcessExit:
		return 3
	case ProcessInjectSuspected:
		return 4
	default:
		return 0
	}
}

func processTypeFromByte(b byte) ProcessEventType {
	switch b {
	case 1:
		return ProcessFork
	case 2:
		return ProcessExec
	case 3:
		return ProcessExit
	case 4:
		return ProcessInjectSuspected
	default:
		return ProcessEventType("UNKNOWN")
	}
}
