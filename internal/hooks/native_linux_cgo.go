//go:build linux && cgo

package hooks

/*
#cgo CFLAGS: -I${SRCDIR}/../../cshim
#cgo LDFLAGS: ${SRCDIR}/../../cshim/libghosttrace_shim.a
#include "shim.h"
*/
import "C"

func nativeInstallAll() int {
	return int(C.gt_hook_install_all())
}

func nativeRemoveAll() int {
	return int(C.gt_hook_remove_all())
}
