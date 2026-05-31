package scanner

import "testing"

func TestScanBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6}
	if got := ScanBytes(data, []byte{3, 4}); got != 2 {
		t.Fatalf("offset=%d, want 2", got)
	}
	if got := ScanBytes(data, []byte{9}); got != -1 {
		t.Fatalf("offset=%d, want -1", got)
	}
}

func TestSelectPatternsFallback(t *testing.T) {
	if got := SelectPatterns([]string{"does-not-exist"}); len(got) != len(DefaultPatterns) {
		t.Fatalf("expected default patterns")
	}
}
