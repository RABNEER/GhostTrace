//go:build !windows

package scanner

import "context"

func (s *Scanner) scanProcessWindows(ctx context.Context, pid uint32) ([]ScanHit, error) {
	_, _, _ = s, ctx, pid
	return nil, ErrUnsupported
}
