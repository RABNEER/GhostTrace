//go:build !linux || !cgo || !amd64

package scanner

func nativeScan(data, pattern []byte) (int64, bool) {
	_, _ = data, pattern
	return -1, false
}
