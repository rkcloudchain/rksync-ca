package metadata

import (
	"fmt"
	"runtime"
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
