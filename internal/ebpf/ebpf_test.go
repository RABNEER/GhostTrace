package ebpf

import (
	"context"
	"testing"
	"time"
)

func TestLoaderUnavailableReturnsCleanly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	loader, err := New(ctx)
	if err != nil {
		return
	}
	if loader == nil {
		t.Fatal("loader and error are both nil")
	}
	_ = loader.Close()
}
