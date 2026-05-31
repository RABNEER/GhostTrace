package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/ghosttrace/ghosttrace/internal/alert"
	"github.com/ghosttrace/ghosttrace/internal/config"
	"github.com/ghosttrace/ghosttrace/internal/ebpf"
	"github.com/ghosttrace/ghosttrace/internal/events"
	"github.com/ghosttrace/ghosttrace/internal/graph"
	"github.com/ghosttrace/ghosttrace/internal/hooks"
	"github.com/ghosttrace/ghosttrace/internal/ringbuf"
	"github.com/ghosttrace/ghosttrace/internal/scanner"
	"github.com/ghosttrace/ghosttrace/internal/windowsmon"
	"github.com/ghosttrace/ghosttrace/ui/tui"
)

var (
	version = "dev"
	commit  = "unknown"
)

type runOptions struct {
	configPath string
	mode       string
	noTUI      bool
	verbose    bool
	showVer    bool
}

type runtimeState struct {
	logger      *zap.Logger
	graph       *graph.ProcessGraph
	dedup       *alert.Deduplicator
	webhook     *alert.WebhookEmitter
	alertCh     chan alert.Alert
	statsCh     chan tui.Stats
	allAlertsMu sync.Mutex
	allAlerts   []alert.Alert
	eventCount  atomic.Int64
	scanHits    atomic.Int64
	stdoutMu    sync.Mutex
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	opts := runOptions{}
	cmd := &cobra.Command{
		Use:   "ghosttrace",
		Short: "GhostTrace process integrity monitor",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.showVer {
				fmt.Printf("ghosttrace %s (%s)\n", version, commit)
				return nil
			}
			return run(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.configPath, "config", "", "path to config file")
	cmd.Flags().StringVar(&opts.mode, "mode", "", "override mode: asm, ebpf, hybrid, windows")
	cmd.Flags().BoolVar(&opts.noTUI, "no-tui", false, "emit JSON alerts to stdout instead of launching the TUI")
	cmd.Flags().BoolVar(&opts.verbose, "verbose", false, "enable debug logging")
	cmd.Flags().BoolVar(&opts.showVer, "version", false, "print version and exit")
	return cmd
}

func run(parent context.Context, opts runOptions) error {
	if isRootRequiredAndMissing() {
		return errors.New("GhostTrace requires root; rerun with sudo")
	}

	loadCtx, cancelLoad := context.WithTimeout(parent, 5*time.Second)
	cfg, err := config.Load(loadCtx, opts.configPath)
	cancelLoad()
	if err != nil {
		return err
	}
	if opts.mode != "" {
		cfg.Mode = opts.mode
	} else if runtime.GOOS == "windows" && cfg.Mode == "asm" {
		cfg.Mode = "windows"
	}
	if opts.verbose {
		cfg.Log.Level = "debug"
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" && cfg.Mode != "windows" {
		return fmt.Errorf("mode %q is Linux-only on Windows; use --mode=windows", cfg.Mode)
	}
	if runtime.GOOS != "windows" && cfg.Mode == "windows" {
		return fmt.Errorf("mode %q is only available on Windows", cfg.Mode)
	}

	logger, err := newLogger(cfg)
	if err != nil {
		return err
	}
	defer logger.Sync()

	ctx, stopSignals := signal.NotifyContext(parent, shutdownSignals()...)
	defer stopSignals()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	state, err := newRuntimeState(cfg, logger, opts.noTUI)
	if err != nil {
		return err
	}
	state.webhook.Start(ctx)
	defer state.webhook.Stop()

	var wg sync.WaitGroup
	var bpfLoader *ebpf.Loader
	hooksInstalled := false

	if cfg.Mode == "asm" || cfg.Mode == "hybrid" {
		if err := hooks.InstallAll(); err != nil {
			if cfg.Mode == "asm" {
				return err
			}
			logger.Warn("native hooks unavailable; continuing with eBPF", zap.Error(err))
		} else {
			hooksInstalled = true
			logger.Info("native hooks installed")
		}
	}
	defer func() {
		if hooksInstalled {
			if err := hooks.RemoveAll(); err != nil {
				logger.Error("failed to remove native hooks", zap.Error(err))
			}
		}
	}()

	if cfg.Mode == "ebpf" || cfg.Mode == "hybrid" {
		bpfLoader, err = ebpf.New(ctx)
		if err != nil {
			if cfg.Mode == "ebpf" {
				return err
			}
			logger.Warn("eBPF unavailable", zap.Error(err))
		} else {
			defer bpfLoader.Close()
			startBPFConsumers(ctx, &wg, state, bpfLoader)
			logger.Info("eBPF telemetry started")
		}
	}

	var consumer *ringbuf.Consumer
	if cfg.Mode == "windows" {
		startWindowsMonitor(ctx, &wg, state, time.Second)
	} else {
		consumer = ringbuf.NewConsumer()
		startRingConsumer(ctx, &wg, state, consumer)
	}
	startStats(ctx, &wg, state)
	if cfg.Scan.Enabled {
		startScanner(ctx, &wg, state, cfg)
	}

	if opts.noTUI {
		wg.Add(1)
		go stdoutAlerts(ctx, &wg, state)
		<-ctx.Done()
	} else {
		if err := tui.Run(ctx, state.graph, state.alertCh, state.statsCh); err != nil {
			cancel()
			return err
		}
		cancel()
	}

	if consumer != nil {
		consumer.Close()
		drainRing(state, consumer)
	}
	wg.Wait()
	if err := exportFinalAlerts(state); err != nil {
		logger.Warn("final alert export failed", zap.Error(err))
	}
	return nil
}

func startWindowsMonitor(ctx context.Context, wg *sync.WaitGroup, state *runtimeState, interval time.Duration) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		seen := make(map[uint32]windowsmon.Process)

		poll := func() {
			processes, err := windowsmon.Snapshot(ctx)
			if err != nil {
				state.logger.Debug("windows process snapshot failed", zap.Error(err))
				return
			}

			now := uint64(time.Now().UnixNano())
			current := make(map[uint32]windowsmon.Process, len(processes))
			for _, proc := range processes {
				if proc.PID == 0 {
					continue
				}
				current[proc.PID] = proc
				prev, ok := seen[proc.PID]
				if ok && prev.PPID == proc.PPID && prev.Comm == proc.Comm {
					continue
				}
				state.eventCount.Add(1)
				for _, a := range state.graph.Update(events.ProcessEvent{
					Type:        events.ProcessExec,
					PID:         proc.PID,
					PPID:        proc.PPID,
					Comm:        proc.Comm,
					ExePath:     proc.ExePath,
					TimestampNs: now,
				}) {
					state.emitAlert(a)
				}
			}

			for pid, proc := range seen {
				if _, ok := current[pid]; ok {
					continue
				}
				state.eventCount.Add(1)
				for _, a := range state.graph.Update(events.ProcessEvent{
					Type:        events.ProcessExit,
					PID:         pid,
					PPID:        proc.PPID,
					Comm:        proc.Comm,
					ExePath:     proc.ExePath,
					TimestampNs: now,
				}) {
					state.emitAlert(a)
				}
			}
			seen = current
		}

		poll()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				poll()
			}
		}
	}()
}

func newRuntimeState(cfg config.Config, logger *zap.Logger, noTUI bool) (*runtimeState, error) {
	wh, err := alert.NewWebhookEmitter(alert.WebhookConfig{
		Enabled: cfg.Alert.Webhook.Enabled,
		URL:     cfg.Alert.Webhook.URL,
		Secret:  cfg.Alert.Webhook.HMACSecret,
		Timeout: time.Duration(cfg.Alert.Webhook.TimeoutSeconds) * time.Second,
		Buffer:  1024,
	})
	if err != nil {
		return nil, err
	}
	opts := graph.DefaultOptions()
	opts.OrphanDetection = cfg.Anomaly.OrphanDetection
	opts.HollowProcess = cfg.Anomaly.HollowProcess
	opts.SyscallSpikeMultiplier = cfg.Anomaly.SyscallSpikeMultiplier
	opts.DKOMCheckInterval = time.Duration(cfg.Anomaly.DKOMCheckIntervalMS) * time.Millisecond

	chSize := 4096
	if noTUI {
		chSize = 16384
	}
	return &runtimeState{
		logger:  logger,
		graph:   graph.NewProcessGraph(opts),
		dedup:   alert.NewDeduplicator(time.Duration(cfg.Alert.DedupWindowSeconds) * time.Second),
		webhook: wh,
		alertCh: make(chan alert.Alert, chSize),
		statsCh: make(chan tui.Stats, 16),
	}, nil
}

func startRingConsumer(ctx context.Context, wg *sync.WaitGroup, state *runtimeState, consumer *ringbuf.Consumer) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			raw, err := consumer.ReadBlocking(ctx)
			if err != nil {
				return
			}
			state.eventCount.Add(1)
			handleRawEvent(state, raw)
		}
	}()
}

func startBPFConsumers(ctx context.Context, wg *sync.WaitGroup, state *runtimeState, loader *ebpf.Loader) {
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-loader.ProcessEvents():
				if !ok {
					return
				}
				state.eventCount.Add(1)
				for _, a := range state.graph.Update(ev) {
					state.emitAlert(a)
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-loader.MemEvents():
				if !ok {
					return
				}
				state.eventCount.Add(1)
				for _, a := range state.graph.AddMemEvent(ev) {
					state.emitAlert(a)
				}
			}
		}
	}()
}

func handleRawEvent(state *runtimeState, raw events.RawEvent) {
	decoded, err := events.DecodeRaw(raw)
	if err != nil {
		state.logger.Debug("drop undecodable event", zap.Error(err))
		return
	}
	switch decoded.Kind {
	case events.EventSyscall:
		for _, a := range state.graph.AddSyscall(decoded.Syscall) {
			state.emitAlert(a)
		}
	case events.EventMem:
		for _, a := range state.graph.AddMemEvent(decoded.Mem) {
			state.emitAlert(a)
		}
	case events.EventProcess:
		for _, a := range state.graph.Update(decoded.Process) {
			state.emitAlert(a)
		}
	}
}

func startScanner(ctx context.Context, wg *sync.WaitGroup, state *runtimeState, cfg config.Config) {
	sc := scanner.New(scanner.Config{
		WorkerCount: cfg.Scan.WorkerCount,
		Patterns:    scanner.SelectPatterns(cfg.Scan.Patterns),
	})
	interval := time.Duration(cfg.Scan.IntervalMS) * time.Millisecond
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, proc := range state.graph.Snapshot() {
					hits, err := sc.ScanProcess(ctx, proc.PID)
					if err != nil && !errors.Is(err, scanner.ErrUnsupported) {
						state.logger.Debug("scan failed", zap.Uint32("pid", proc.PID), zap.Error(err))
					}
					for _, hit := range hits {
						state.scanHits.Add(1)
						state.emitAlert(alert.New(
							alert.SeverityCritical,
							alert.AlertShellcode,
							hit.PID,
							proc.Comm,
							fmt.Sprintf("matched %s at 0x%x", hit.PatternName, hit.Addr),
							95,
						))
					}
				}
			}
		}
	}()
}

func startStats(ctx context.Context, wg *sync.WaitGroup, state *runtimeState) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stats := tui.Stats{
					EventsPerSec:  int(state.eventCount.Swap(0)),
					TotalProcesses: len(state.graph.Snapshot()),
					ScanHitsToday:  int(state.scanHits.Load()),
				}
				select {
				case state.statsCh <- stats:
				default:
				}
			}
		}
	}()
}

func (s *runtimeState) emitAlert(a alert.Alert) {
	if !s.dedup.Allow(a) {
		return
	}
	s.allAlertsMu.Lock()
	s.allAlerts = append(s.allAlerts, a)
	s.allAlertsMu.Unlock()
	_ = s.webhook.Emit(a)
	select {
	case s.alertCh <- a:
	default:
		s.logger.Warn("alert channel full; dropping alert", zap.String("id", a.ID))
	}
}

func stdoutAlerts(ctx context.Context, wg *sync.WaitGroup, state *runtimeState) {
	defer wg.Done()
	enc := json.NewEncoder(os.Stdout)
	for {
		select {
		case <-ctx.Done():
			return
		case a, ok := <-state.alertCh:
			if !ok {
				return
			}
			state.stdoutMu.Lock()
			if err := enc.Encode(a); err != nil {
				state.logger.Error("write alert", zap.Error(err))
			}
			state.stdoutMu.Unlock()
		}
	}
}

func drainRing(state *runtimeState, consumer *ringbuf.Consumer) {
	for {
		raw, ok := consumer.Read()
		if !ok {
			return
		}
		handleRawEvent(state, raw)
	}
}

func exportFinalAlerts(state *runtimeState) error {
	state.allAlertsMu.Lock()
	alerts := append([]alert.Alert(nil), state.allAlerts...)
	state.allAlertsMu.Unlock()
	if len(alerts) == 0 {
		return nil
	}
	data, err := json.MarshalIndent(alerts, "", "  ")
	if err != nil {
		return err
	}
	name := fmt.Sprintf("ghosttrace_final_%s.json", time.Now().Format("20060102_150405"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return writeFileContext(ctx, filepath.Join(".", name), data, 0600)
}

func writeFileContext(ctx context.Context, path string, data []byte, perm os.FileMode) error {
	ch := make(chan error, 1)
	go func() {
		ch <- os.WriteFile(path, data, perm)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-ch:
		return err
	}
}

func newLogger(cfg config.Config) (*zap.Logger, error) {
	level := zapcore.InfoLevel
	if err := level.Set(cfg.Log.Level); err != nil {
		return nil, err
	}
	encoderCfg := zap.NewProductionEncoderConfig()
	var encoder zapcore.Encoder
	if cfg.Log.Format == "console" {
		encoder = zapcore.NewConsoleEncoder(encoderCfg)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderCfg)
	}

	syncer := zapcore.AddSync(os.Stderr)
	if cfg.Log.File != "" && runtime.GOOS == "linux" {
		if err := os.MkdirAll(filepath.Dir(cfg.Log.File), 0755); err == nil {
			if file, err := os.OpenFile(cfg.Log.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640); err == nil {
				syncer = zapcore.NewMultiWriteSyncer(syncer, zapcore.AddSync(file))
			}
		}
	}
	return zap.New(zapcore.NewCore(encoder, syncer, level), zap.AddCaller()), nil
}
