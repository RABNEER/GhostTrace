//go:build !linux || !amd64

package scanner

func hostHasAVX2() bool {
	return false
}
