//go:build linux && cgo

package ringbuf

/*
#cgo CFLAGS: -I${SRCDIR}/../../cshim
#cgo LDFLAGS: ${SRCDIR}/../../cshim/libghosttrace_shim.a
#include <string.h>
#include "shim.h"
*/
import "C"

import (
	"unsafe"

	"github.com/ghosttrace/ghosttrace/internal/events"
)

func nativeRead(out *events.RawEvent) bool {
	var ev C.struct_gt_event
	rc := C.gt_ring_read(&ev)
	if rc != 1 {
		return false
	}
	C.memcpy(unsafe.Pointer(&out.Data[0]), unsafe.Pointer(&ev.data[0]), C.size_t(events.FrameSize))
	return true
}
