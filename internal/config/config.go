package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Mode           string        `mapstructure:"mode"`
	RingBufferSize int           `mapstructure:"ring_buffer_size"`
	Scan           ScanConfig    `mapstructure:"scan"`
	Anomaly        AnomalyConfig `mapstructure:"anomaly"`
	Alert          AlertConfig   `mapstructure:"alert"`
	Log            LogConfig     `mapstructure:"log"`
}

type ScanConfig struct {
	Enabled    bool     `mapstructure:"enabled"`
	IntervalMS int      `mapstructure:"interval_ms"`
	WorkerCount int     `mapstructure:"worker_count"`
	Patterns    []string `mapstructure:"patterns"`
}

type AnomalyConfig struct {
	OrphanDetection       bool            `mapstructure:"orphan_detection"`
	HollowProcess         bool            `mapstructure:"hollow_process"`
	SyscallSpikeMultiplier float64        `mapstructure:"syscall_spike_multiplier"`
	DKOMCheckIntervalMS   int             `mapstructure:"dkom_check_interval_ms"`
	ScoreThresholds       ScoreThresholds `mapstructure:"score_thresholds"`
}

type ScoreThresholds struct {
	Warn     float64 `mapstructure:"warn"`
	Critical float64 `mapstructure:"critical"`
}

type AlertConfig struct {
	DedupWindowSeconds int           `mapstructure:"dedup_window_seconds"`
	Webhook            WebhookConfig `mapstructure:"webhook"`
}

type WebhookConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	URL            string `mapstructure:"url"`
	HMACSecret     string `mapstructure:"hmac_secret"`
	TimeoutSeconds int    `mapstructure:"timeout_seconds"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	File   string `mapstructure:"file"`
	Format string `mapstructure:"format"`
}

func Load(ctx context.Context, path string) (Config, error) {
	v := viper.New()
	setDefaults(v)

	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("ghosttrace")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./configs")
		v.AddConfigPath("/etc/ghosttrace")
	}

	if err := readConfigContext(ctx, v); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if path != "" || !errors.As(err, &notFound) {
			return Config{}, err
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("mode", DefaultMode)
	v.SetDefault("ring_buffer_size", DefaultRingBufferSize)
	v.SetDefault("scan.enabled", true)
	v.SetDefault("scan.interval_ms", 2000)
	v.SetDefault("scan.worker_count", 4)
	v.SetDefault("scan.patterns", DefaultPatterns)
	v.SetDefault("anomaly.orphan_detection", true)
	v.SetDefault("anomaly.hollow_process", true)
	v.SetDefault("anomaly.syscall_spike_multiplier", 5.0)
	v.SetDefault("anomaly.dkom_check_interval_ms", 500)
	v.SetDefault("anomaly.score_thresholds.warn", 30)
	v.SetDefault("anomaly.score_thresholds.critical", 70)
	v.SetDefault("alert.dedup_window_seconds", 5)
	v.SetDefault("alert.webhook.timeout_seconds", 5)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.file", "/var/log/ghosttrace/ghosttrace.log")
	v.SetDefault("log.format", "json")
}

func readConfigContext(ctx context.Context, v *viper.Viper) error {
	type result struct {
		err error
	}
	ch := make(chan result, 1)
	go func() {
		ch <- result{err: v.ReadInConfig()}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case res := <-ch:
		return res.err
	}
}

func (c Config) Validate() error {
	switch c.Mode {
	case "asm", "ebpf", "hybrid", "windows":
	default:
		return fmt.Errorf("invalid mode %q", c.Mode)
	}
	if c.RingBufferSize <= 0 || c.RingBufferSize%64 != 0 {
		return fmt.Errorf("ring_buffer_size must be positive and aligned to 64")
	}
	if c.Scan.IntervalMS <= 0 {
		return fmt.Errorf("scan.interval_ms must be positive")
	}
	if c.Scan.WorkerCount <= 0 {
		return fmt.Errorf("scan.worker_count must be positive")
	}
	if c.Anomaly.SyscallSpikeMultiplier <= 1 {
		return fmt.Errorf("anomaly.syscall_spike_multiplier must be > 1")
	}
	if c.Anomaly.DKOMCheckIntervalMS <= 0 {
		return fmt.Errorf("anomaly.dkom_check_interval_ms must be positive")
	}
	if c.Alert.DedupWindowSeconds <= 0 {
		return fmt.Errorf("alert.dedup_window_seconds must be positive")
	}
	if c.Alert.Webhook.Enabled && c.Alert.Webhook.URL == "" {
		return fmt.Errorf("alert.webhook.url is required when webhook is enabled")
	}
	if c.Alert.Webhook.TimeoutSeconds <= 0 {
		return fmt.Errorf("alert.webhook.timeout_seconds must be positive")
	}
	if c.Log.Level != "debug" && c.Log.Level != "info" && c.Log.Level != "warn" && c.Log.Level != "error" {
		return fmt.Errorf("invalid log.level %q", c.Log.Level)
	}
	if c.Log.Format != "json" && c.Log.Format != "console" {
		return fmt.Errorf("invalid log.format %q", c.Log.Format)
	}
	return nil
}

func LoadWithTimeout(path string, timeout time.Duration) (Config, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return Load(ctx, path)
}

func ReadFileContext(ctx context.Context, path string) ([]byte, error) {
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
