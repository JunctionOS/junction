package main

// #cgo CFLAGS: -I${SRCDIR}
// #cgo LDFLAGS: ${SRCDIR}/libgo_snapshot.a
// #include "snapshot_sys.h"
// #include <stdlib.h>
import "C"

import (
	"fmt"
	"os"
	//	"unsafe"
)

func main() {
	fmt.Println("Hello world!")
	if len(os.Args) > 1 {
		elf := C.CString("/tmp/junction.elf")
		metadata := C.CString("/tmp/junction.metadata")
		if len(os.Args) > 3 {
			elf = C.CString(os.Args[2])
			metadata = C.CString(os.Args[3])
		}

		ret := C.snapshot(elf, metadata)
		fmt.Println(ret)
		
		if ret == 0 {
			fmt.Println("Snapshotted!")
		} else {
			fmt.Println("Restored!")
		}
	}
}
