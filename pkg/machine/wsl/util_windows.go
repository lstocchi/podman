//go:build windows

package wsl

import (
	"fmt"
	"os"

	"github.com/containers/podman/v5/pkg/machine/windows"
	win "golang.org/x/sys/windows"
)

func winVersionAtLeast(major uint, minor uint, build uint) bool {
	var out [3]uint32

	in := []uint32{uint32(major), uint32(minor), uint32(build)}
	out[0], out[1], out[2] = win.RtlGetNtVersionNumbers()

	for i, o := range out {
		if in[i] > o {
			return false
		}
		if in[i] < o {
			return true
		}
	}

	return true
}

func getElevatedOutputFileWrite() (*os.File, error) {
	return windows.GetElevatedOutputFile(os.O_WRONLY | os.O_CREATE | os.O_APPEND)
}

func appendOutputIfError(write bool, err error) {
	if write && err == nil {
		return
	}

	if file, check := getElevatedOutputFileWrite(); check == nil {
		defer file.Close()
		fmt.Fprintf(file, "Error: %v\n", err)
	}
}
