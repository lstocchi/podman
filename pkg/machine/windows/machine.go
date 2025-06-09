package windows

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/containers/storage/pkg/homedir"
	"github.com/sirupsen/logrus"
)

type ExitCodeError struct {
	code uint
}

func (e *ExitCodeError) Error() string {
	return fmt.Sprintf("Process failed with exit code: %d", e.code)
}

func getElevatedOutputFileName() (string, error) {
	dir, err := homedir.GetDataHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "podman-elevated-output.log"), nil
}

func truncateElevatedOutputFile() error {
	name, err := getElevatedOutputFileName()
	if err != nil {
		return err
	}

	return os.Truncate(name, 0)
}

func getElevatedOutputFileRead() (*os.File, error) {
	return GetElevatedOutputFile(os.O_RDONLY)
}

func GetElevatedOutputFile(mode int) (*os.File, error) {
	name, err := getElevatedOutputFileName()
	if err != nil {
		return nil, err
	}

	dir, err := homedir.GetDataHome()
	if err != nil {
		return nil, err
	}

	if err = os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	return os.OpenFile(name, mode, 0644)
}

func IsMsiError(err error) bool {
	if err == nil {
		return false
	}

	if eerr, ok := err.(*exec.ExitError); ok {
		switch eerr.ExitCode() {
		case 0:
			fallthrough
		case ErrorSuccessRebootInitiated:
			fallthrough
		case ErrorSuccessRebootRequired:
			return false
		}
	}

	return true
}

func dumpOutputFile() {
	file, err := getElevatedOutputFileRead()
	if err != nil {
		logrus.Debug("could not find elevated child output file")
		return
	}
	defer file.Close()
	_, _ = io.Copy(os.Stdout, file)
}
