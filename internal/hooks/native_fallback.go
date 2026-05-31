//go:build !linux || !cgo

package hooks

func nativeInstallAll() int {
	return -95
}

func nativeRemoveAll() int {
	return 0
}
