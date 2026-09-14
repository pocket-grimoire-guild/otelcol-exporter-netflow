//go:build integration && linux

package leak_test

import (
	"os"
	"strings"
)

// processSocketCount counts live socket descriptors through the Linux
// process view. Readlink races with a descriptor closing are ignored because
// the enclosing directory snapshot remains authoritative for the next sample.
func processSocketCount() (int, bool) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	count := 0
	for _, entry := range entries {
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err == nil && strings.HasPrefix(target, "socket:[") {
			count++
		}
	}
	return count, true
}
