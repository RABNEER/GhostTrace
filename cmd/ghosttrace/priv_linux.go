//go:build linux

package main

import "os"

func isRootRequiredAndMissing() bool {
	return os.Geteuid() != 0
}
