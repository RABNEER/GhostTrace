package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrUnsupported = errors.New("process memory scanning is unsupported on this platform")

type Config struct {
	WorkerCount int
	Patterns    []Pattern
}

type Scanner struct {
	workerCount int
	patterns    []Pattern
}

type ScanHit struct {
	PID         uint32 `json:"pid"`
	Addr        uint64 `json:"addr"`
	PatternName string `json:"pattern_name"`
	Offset      int64  `json:"offset"`
}

type memoryRegion struct {
	start uint64
	end   uint64
}

func New(cfg Config) *Scanner {
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 4
	}
	if len(cfg.Patterns) == 0 {
		cfg.Patterns = DefaultPatterns
	}
	return &Scanner{workerCount: cfg.WorkerCount, patterns: cfg.Patterns}
}

func (s *Scanner) ScanProcess(ctx context.Context, pid uint32) ([]ScanHit, error) {
	if runtime.GOOS == "windows" {
		return s.scanProcessWindows(ctx, pid)
	}
	if runtime.GOOS != "linux" {
		return nil, ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	regions, err := parseExecutableAnonymousMaps(ctx, pid)
	if err != nil {
		return nil, err
	}
	if len(regions) == 0 {
		return nil, nil
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	mem, err := openFileContext(ctx, memPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", memPath, err)
	}
	defer mem.Close()

	jobs := make(chan memoryRegion)
	hits := make(chan ScanHit, len(regions))
	errs := make(chan error, s.workerCount)

	var wg sync.WaitGroup
	for i := 0; i < s.workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for region := range jobs {
				if err := s.scanRegion(ctx, mem, pid, region, hits); err != nil {
					select {
					case errs <- err:
					default:
					}
				}
			}
		}()
	}

	for _, region := range regions {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		case jobs <- region:
		}
	}
	close(jobs)
	wg.Wait()
	close(hits)

	select {
	case err := <-errs:
		return nil, err
	default:
	}

	out := make([]ScanHit, 0, len(hits))
	for hit := range hits {
		out = append(out, hit)
	}
	return out, nil
}

func (s *Scanner) scanRegion(ctx context.Context, mem *os.File, pid uint32, region memoryRegion, hits chan<- ScanHit) error {
	const chunkSize = 1 << 20
	maxPat := s.maxPatternLen()
	if maxPat == 0 {
		return nil
	}

	overlap := maxPat - 1
	buf := make([]byte, chunkSize+overlap)
	var carry []byte

	for off := region.start; off < region.end; {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := region.end - off
		readSize := uint64(chunkSize)
		if remaining < readSize {
			readSize = remaining
		}
		n, err := mem.ReadAt(buf[len(carry):len(carry)+int(readSize)], int64(off))
		if err != nil && !errors.Is(err, io.EOF) {
			return nil
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
				hits <- ScanHit{
					PID:         pid,
					Addr:        off - uint64(len(carry)) + uint64(idx),
					PatternName: pattern.Name,
					Offset:      int64(off-region.start) - int64(len(carry)) + idx,
				}
			}
		}

		if len(window) < overlap {
			carry = append(carry[:0], window...)
		} else {
			carry = append(carry[:0], window[len(window)-overlap:]...)
		}
		off += uint64(n)
		if n == 0 {
			break
		}
	}
	return nil
}

func (s *Scanner) maxPatternLen() int {
	maxLen := 0
	for _, p := range s.patterns {
		if len(p.Bytes) > maxLen {
			maxLen = len(p.Bytes)
		}
	}
	return maxLen
}

func ScanBytes(data, pattern []byte) int64 {
	if len(data) == 0 || len(pattern) == 0 || len(data) < len(pattern) {
		return -1
	}
	if off, ok := nativeScan(data, pattern); ok {
		return off
	}
	return int64(bytes.Index(data, pattern))
}

func parseExecutableAnonymousMaps(ctx context.Context, pid uint32) ([]memoryRegion, error) {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := readFileContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	lines := strings.Split(string(data), "\n")
	regions := make([]memoryRegion, 0)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		perms := fields[1]
		if !strings.Contains(perms, "x") {
			continue
		}
		if len(fields) >= 6 && fields[5] != "" && !strings.HasPrefix(fields[5], "[") {
			continue
		}
		parts := strings.SplitN(fields[0], "-", 2)
		if len(parts) != 2 {
			continue
		}
		start, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(parts[1], 16, 64)
		if err != nil || end <= start {
			continue
		}
		regions = append(regions, memoryRegion{start: start, end: end})
	}
	return regions, nil
}

func readFileContext(ctx context.Context, path string) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := os.ReadFile(path)
		ch <- result{data: data, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.data, res.err
	}
}

func openFileContext(ctx context.Context, path string) (*os.File, error) {
	type result struct {
		file *os.File
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		file, err := os.Open(path)
		ch <- result{file: file, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.file, res.err
	}
}
