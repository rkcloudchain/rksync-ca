package metadata

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// Version specifies courier-ca version
var Version = "1.0.0"

// GetVersionInfo returns version information for the courier-ca
func GetVersionInfo(prgName string) string {
	if Version == "" {
		Version = "development build"
	}

	return fmt.Sprintf("%s:\n Version: %s\n Go version: %s\n OS/Arch: %s\n",
		prgName,
		Version,
		runtime.Version(),
		fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))
}

// GetVersion returns the version
func GetVersion() string {
	if Version == "" {
		panic("Version is not set for courier-ca library")
	}
	return Version
}

// CmpVersion compares version v1 to v2.
func CmpVersion(v1, v2 string) (int, error) {
	v1strs := strs(v1)
	v2strs := strs(v2)
	m := max(len(v1strs), len(v2strs))
	for i := 0; i < m; i++ {
		v1val, err := val(v1strs, i)
		if err != nil {
			return 0, errors.WithMessage(err, fmt.Sprintf("Invalid version: '%s'", v1))
		}
		v2val, err := val(v2strs, i)
		if err != nil {
			return 0, errors.WithMessage(err, fmt.Sprintf("Invalid version: '%s'", v2))
		}
		if v1val < v2val {
			return 1, nil
		} else if v1val > v2val {
			return -1, nil
		}
	}
	return 0, nil
}

func strs(version string) []string {
	return strings.Split(strings.Split(version, "-")[0], ".")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func val(strs []string, i int) (int, error) {
	if i >= len(strs) {
		return 0, nil
	}
	str := strs[i]
	v, err := strconv.Atoi(str)
	if err != nil {
		return 0, errors.WithMessage(err, fmt.Sprintf("Invalid version format at '%s'", str))
	}
	return v, nil
}
