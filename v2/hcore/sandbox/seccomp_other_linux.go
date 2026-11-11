//go:build linux && !amd64 && !android

package sandbox

import (
	"errors"
	"os"
)

func applicationFilter(_ bool) (*os.File, error) {
	return nil, errors.New("sandbox syscall policy is currently validated only on Linux x86_64")
}
