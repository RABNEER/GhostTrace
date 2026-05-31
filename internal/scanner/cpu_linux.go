//go:build linux && amd64

package scanner

import (
	"os"
	"strings"
	"sync"
)

var avx2Once struct {
	sync.Once
	ok bool
}

func hostHasAVX2() bool {
	avx2Once.Do(func() {
		data, err := os.ReadFile("/proc/cpuinfo")
		if err == nil && strings.Contains(string(data), " avx2 ") {
			avx2Once.ok = true
		}
	})
	return avx2Once.ok
}
