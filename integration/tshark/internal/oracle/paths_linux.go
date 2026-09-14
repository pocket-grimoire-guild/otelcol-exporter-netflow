package oracle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Remote Podman resolves mount source paths on its host, so a client-side file
// descriptor cannot pin the bind source. Require a trusted ancestry instead:
// root/the invoking UID own every component, no group/other can replace it,
// and sticky shared ancestors (such as /tmp) protect our owned child. The leaf
// itself must be owned by the caller and not writable by group/other.
// The invoking UID and root are trusted, including access to the Podman socket.
func trustedDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, ",\n\r") {
		return fmt.Errorf("directory must be an absolute clean path without mount separators")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		owner := info.Sys().(*syscall.Stat_t).Uid
		leaf := current == path
		if !info.IsDir() || (owner != uint32(os.Getuid()) && (leaf || owner != 0)) ||
			(info.Mode().Perm()&0022 != 0 && (leaf || info.Mode()&os.ModeSticky == 0)) {
			return fmt.Errorf("directory ancestry must be owned/trusted and protected from group/other replacement: %s", current)
		}
		if current == "/" {
			return nil
		}
	}
}
