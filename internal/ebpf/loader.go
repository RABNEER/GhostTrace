//go:build linux

package ebpf

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	ebpfring "github.com/cilium/ebpf/ringbuf"

	"github.com/ghosttrace/ghosttrace/internal/events"
)

//go:embed programs/trace_execve.c
var traceExecveSource string

//go:embed programs/trace_mmap.c
var traceMmapSource string

var ErrTracingUnavailable = errors.New("kernel tracing filesystem is unavailable")

type Loader struct {
	mu       sync.Mutex
	links    []link.Link
	colls    []*ebpf.Collection
	readers  []*ebpfring.Reader
	procCh   chan events.ProcessEvent
	memCh    chan events.MemEvent
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	closed   bool
}

type bpfEvent struct {
	Type uint32
	PID  uint32
	PPID uint32
	Prot uint32
	Addr uint64
	Len  uint64
	TS   uint64
	Comm [16]byte
}

func New(ctx context.Context) (*Loader, error) {
	if !tracefsAvailable() {
		return nil, ErrTracingUnavailable
	}

	ctx, cancel := context.WithCancel(ctx)
	l := &Loader{
		procCh: make(chan events.ProcessEvent, 1024),
		memCh:  make(chan events.MemEvent, 1024),
		cancel: cancel,
	}

	if err := l.loadProgram(ctx, "trace_execve", traceExecveSource, []tracepointSpec{
		{category: "syscalls", name: "sys_enter_execve", program: "trace_execve"},
		{category: "syscalls", name: "sys_exit_execve", program: "trace_execve_exit"},
	}); err != nil {
		cancel()
		_ = l.Close()
		return nil, err
	}

	if err := l.loadProgram(ctx, "trace_mmap", traceMmapSource, []tracepointSpec{
		{category: "syscalls", name: "sys_enter_mmap", program: "trace_mmap"},
		{category: "syscalls", name: "sys_enter_mprotect", program: "trace_mprotect"},
	}); err != nil {
		cancel()
		_ = l.Close()
		return nil, err
	}

	for _, reader := range l.readers {
		l.wg.Add(1)
		go l.readLoop(ctx, reader)
	}
	return l, nil
}

func (l *Loader) ProcessEvents() <-chan events.ProcessEvent {
	return l.procCh
}

func (l *Loader) MemEvents() <-chan events.MemEvent {
	return l.memCh
}

func (l *Loader) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	if l.cancel != nil {
		l.cancel()
	}
	for _, r := range l.readers {
		_ = r.Close()
	}
	l.mu.Unlock()

	l.wg.Wait()

	l.mu.Lock()
	defer l.mu.Unlock()
	var first error
	for _, ln := range l.links {
		if err := ln.Close(); err != nil && first == nil {
			first = err
		}
	}
	for _, coll := range l.colls {
		coll.Close()
	}
	close(l.procCh)
	close(l.memCh)
	return first
}

type tracepointSpec struct {
	category string
	name     string
	program  string
}

func (l *Loader) loadProgram(ctx context.Context, name, source string, specs []tracepointSpec) error {
	obj, cleanup, err := compileBPF(ctx, name, source)
	if err != nil {
		return err
	}
	defer cleanup()

	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		return fmt.Errorf("load BPF collection spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}
	l.colls = append(l.colls, coll)

	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		return fmt.Errorf("BPF object %s has no events map", name)
	}
	reader, err := ebpfring.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("open BPF ringbuf reader: %w", err)
	}
	l.readers = append(l.readers, reader)

	for _, tp := range specs {
		prog := coll.Programs[tp.program]
		if prog == nil {
			return fmt.Errorf("BPF object %s has no program %s", name, tp.program)
		}
		ln, err := link.Tracepoint(tp.category, tp.name, prog, nil)
		if err != nil {
			return fmt.Errorf("attach tracepoint %s/%s: %w", tp.category, tp.name, err)
		}
		l.links = append(l.links, ln)
	}
	return nil
}

func (l *Loader) readLoop(ctx context.Context, reader *ebpfring.Reader) {
	defer l.wg.Done()
	for {
		record, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, ebpfring.ErrClosed) {
				return
			}
			continue
		}
		ev, err := decodeBPFEvent(record.RawSample)
		if err != nil {
			continue
		}
		switch ev.Type {
		case 1:
			proc := events.ProcessEvent{
				Type:        events.ProcessExec,
				PID:         ev.PID,
				PPID:        ev.PPID,
				Comm:        trimComm(ev.Comm),
				TimestampNs: ev.TS,
			}
			select {
			case <-ctx.Done():
				return
			case l.procCh <- proc:
			}
		case 2:
			mem := events.MemEvent{
				PID:         ev.PID,
				Addr:        ev.Addr,
				Len:         ev.Len,
				Prot:        ev.Prot,
				TimestampNs: ev.TS,
			}
			select {
			case <-ctx.Done():
				return
			case l.memCh <- mem:
			}
		}
	}
}

func decodeBPFEvent(raw []byte) (bpfEvent, error) {
	var ev bpfEvent
	if len(raw) < 48 {
		return ev, fmt.Errorf("short BPF event: %d", len(raw))
	}
	r := bytes.NewReader(raw)
	if err := binary.Read(r, binary.LittleEndian, &ev); err != nil {
		return ev, err
	}
	return ev, nil
}

func compileBPF(ctx context.Context, name, source string) (string, func(), error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	dir, err := os.MkdirTemp("", "ghosttrace-bpf-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	src := filepath.Join(dir, name+".c")
	obj := filepath.Join(dir, name+".o")
	if err := os.WriteFile(src, []byte(source), 0600); err != nil {
		cleanup()
		return "", func() {}, err
	}

	cmd := exec.CommandContext(ctx, "clang", "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86", "-c", src, "-o", obj)
	out, err := cmd.CombinedOutput()
	if err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("compile %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return obj, cleanup, nil
}

func tracefsAvailable() bool {
	for _, path := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			return true
		}
	}
	return false
}

func trimComm(comm [16]byte) string {
	n := 0
	for n < len(comm) && comm[n] != 0 {
		n++
	}
	return string(comm[:n])
}
