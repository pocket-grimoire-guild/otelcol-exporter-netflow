package fixturepcap

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Hold the directory used for creation, reads and cleanup rather than checking
// a pathname and resolving it again. Even newly created directories are opened
// with O_NOFOLLOW relative to their already-open parent.
func openDirectory(path string, create bool) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fd, err := syscall.Open("/", flags, 0)
	if err != nil {
		return nil, err
	}
	if abs == "/" {
		return os.NewFile(uintptr(fd), abs), nil
	}
	for _, p := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
		next, openErr := syscall.Openat(fd, p, flags, 0)
		if openErr == syscall.ENOENT && create {
			if mkdirErr := syscall.Mkdirat(fd, p, 0755); mkdirErr != nil && mkdirErr != syscall.EEXIST {
				syscall.Close(fd)
				return nil, mkdirErr
			}
			next, openErr = syscall.Openat(fd, p, flags, 0)
		}
		syscall.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("open fixture directory %s: %w", path, openErr)
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), abs), nil
}

func writeCapture(dir *os.File, name string, data []byte) error {
	fd, err := syscall.Openat(int(dir.Fd()), name,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0644)
	if err == syscall.EEXIST {
		existing, err := readRegularAt(dir, name, 1<<17)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("refusing to overwrite differing capture: %s", name)
		}
		return nil
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		// Cleanup stays on the same held directory if its pathname is replaced.
		syscall.Unlinkat(int(dir.Fd()), name)
		return fmt.Errorf("write PCAP: %v; close: %v", writeErr, closeErr)
	}
	return nil
}

// Open every path component without following links. O_NONBLOCK prevents a
// substituted FIFO from blocking before the regular-file check. Bounds apply
// before allocation and while reading, even if an input grows concurrently.
func readRegular(path string, limit int64) ([]byte, error) {
	dir, err := openDirectory(filepath.Dir(path), false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return readRegularAt(dir, filepath.Base(path), limit)
}

func readRegularAt(dir *os.File, name string, limit int64) ([]byte, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open regular fixture %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > limit {
		return nil, fmt.Errorf("fixture must be a bounded regular file: %s", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	b, a := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
	if int64(len(data)) != before.Size() || len(data) > int(limit) || b.Size != a.Size ||
		b.Dev != a.Dev || b.Ino != a.Ino || b.Mode != a.Mode || b.Mtim != a.Mtim || b.Ctim != a.Ctim {
		return nil, fmt.Errorf("fixture changed during bounded read: %s", name)
	}
	return data, nil
}
