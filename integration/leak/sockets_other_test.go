//go:build integration && !linux

package leak_test

// The functional and goroutine checks run on every platform. This process
// does not claim a portable OS socket counter outside Linux.
func processSocketCount() (int, bool) { return 0, false }
