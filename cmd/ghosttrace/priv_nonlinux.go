//go:build !linux

package main

func isRootRequiredAndMissing() bool {
	return false
}
