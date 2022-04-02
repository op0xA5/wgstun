package main

import (
	"fmt"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"os"
	"unsafe"
)
func printf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
}

const wordSize = int(unsafe.Sizeof(uintptr(0)))
const wordCount = wgtypes.KeyLen / wordSize

func keyEquals(a, b wgtypes.Key) bool {
	aw := *(*[wordCount]uintptr)(unsafe.Pointer(&a))
	bw := *(*[wordCount]uintptr)(unsafe.Pointer(&b))

	for i := 0; i < wordCount; i++ {
		if aw[i] != bw[i] {
			return false
		}
	}

	return true
}

