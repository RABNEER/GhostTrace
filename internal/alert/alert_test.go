package alert

import (
	"testing"
	"time"
)

func TestDeduplicatorSuppressesWithinWindow(t *testing.T) {
	d := NewDeduplicator(50 * time.Millisecond)
	a := New(SeverityWarn, AlertDKOM, 42, "proc", "detail", 40)
	if !d.Allow(a) {
		t.Fatal("first alert should be allowed")
	}
	if d.Allow(a) {
		t.Fatal("duplicate alert should be suppressed")
	}
	time.Sleep(60 * time.Millisecond)
	if !d.Allow(a) {
		t.Fatal("alert should be allowed after window")
	}
}

func TestSeverityForScore(t *testing.T) {
	if SeverityForScore(80) != SeverityCritical {
		t.Fatal("expected critical")
	}
	if SeverityForScore(40) != SeverityWarn {
		t.Fatal("expected warn")
	}
	if SeverityForScore(10) != SeverityInfo {
		t.Fatal("expected info")
	}
}
