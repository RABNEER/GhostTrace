//go:build linux && cgo && amd64

package scanner

/*
#cgo CFLAGS: -I${SRCDIR}/../../cshim
#cgo LDFLAGS: ${SRCDIR}/../../cshim/libghosttrace_shim.a
#include "shim.h"
*/
import "C"

import "unsafe"

func nativeScan(data, pattern []byte) (int64, bool) {
	if len(data) == 0 || len(pattern) == 0 || !hostHasAVX2() {
		return -1, false
	}
	rc := C.gt_scan_region(
		unsafe.Pointer(&data[0]),
		C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&pattern[0])),
		C.size_t(len(pattern)),
	)
	return int64(rc), true
}
