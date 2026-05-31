package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type WebhookConfig struct {
	Enabled bool
	URL     string
	Secret  string
	Timeout time.Duration
	Buffer  int
}

type WebhookEmitter struct {
	cfg    WebhookConfig
	client *http.Client
	ch     chan Alert
	wg     sync.WaitGroup
}

func NewWebhookEmitter(cfg WebhookConfig) (*WebhookEmitter, error) {
	if !cfg.Enabled {
		cfg.Buffer = maxInt(cfg.Buffer, 1)
	}
	if cfg.Enabled && cfg.URL == "" {
		return nil, errors.New("webhook URL is required when webhook is enabled")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Buffer <= 0 {
		cfg.Buffer = 256
	}
	return &WebhookEmitter{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		ch: make(chan Alert, cfg.Buffer),
	}, nil
}

func (e *WebhookEmitter) Start(ctx context.Context) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case a, ok := <-e.ch:
				if !ok {
					return
				}
				if e.cfg.Enabled {
					e.postWithRetry(ctx, a)
				}
			}
		}
	}()
}

func (e *WebhookEmitter) Stop() {
	close(e.ch)
	e.wg.Wait()
}

func (e *WebhookEmitter) Emit(a Alert) bool {
	select {
	case e.ch <- a:
		return true
	default:
		return false
	}
}

func (e *WebhookEmitter) postWithRetry(ctx context.Context, a Alert) {
	body, err := json.Marshal(a)
	if err != nil {
		return
	}

	backoff := 100 * time.Millisecond
	for attempt := 0; attempt < 3; attempt++ {
		if err := e.post(ctx, body); err == nil {
			return
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff *= 2
	}
}

func (e *WebhookEmitter) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.cfg.Secret != "" {
		req.Header.Set("X-GhostTrace-Signature", signature(e.cfg.Secret, body))
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

func signature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
