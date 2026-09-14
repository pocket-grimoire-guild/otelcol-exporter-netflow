// Package cursor provides a checked, caller-buffer-backed write cursor.
package cursor

import (
	"encoding/binary"
	"io"
)

// ErrInvalidLength reports a negative length passed to Reserve.
const ErrInvalidLength invalidLengthError = "cursor: invalid length"

type invalidLengthError string

func (e invalidLengthError) Error() string { return string(e) }

// Cursor writes values into a caller-owned byte slice without growing it.
//
// A zero-value Cursor is ready for use with no available capacity. A Cursor
// does not retain ownership of its buffer; callers must keep the backing slice
// valid for the lifetime of the cursor.
type Cursor struct {
	buf []byte
	off int
}

// New returns a cursor positioned at the beginning of buf.
func New(buf []byte) Cursor {
	return Cursor{buf: buf}
}

// Offset reports the number of bytes written or reserved so far.
func (c *Cursor) Offset() int {
	return c.off
}

// Remaining reports the number of bytes still available in the buffer.
func (c *Cursor) Remaining() int {
	return len(c.buf) - c.off
}

// WriteByte writes one byte at the current offset.
func (c *Cursor) WriteByte(v byte) error {
	if c.off >= len(c.buf) {
		return io.ErrShortBuffer
	}
	c.buf[c.off] = v
	c.off++
	return nil
}

// WriteUint8 writes one byte at the current offset.
func (c *Cursor) WriteUint8(v uint8) error {
	return c.WriteByte(byte(v))
}

// WriteUint16 writes a big-endian uint16 at the current offset.
func (c *Cursor) WriteUint16(v uint16) error {
	if len(c.buf)-c.off < 2 {
		return io.ErrShortBuffer
	}
	binary.BigEndian.PutUint16(c.buf[c.off:c.off+2], v)
	c.off += 2
	return nil
}

// WriteUint32 writes a big-endian uint32 at the current offset.
func (c *Cursor) WriteUint32(v uint32) error {
	if len(c.buf)-c.off < 4 {
		return io.ErrShortBuffer
	}
	binary.BigEndian.PutUint32(c.buf[c.off:c.off+4], v)
	c.off += 4
	return nil
}

// WriteUint64 writes a big-endian uint64 at the current offset.
func (c *Cursor) WriteUint64(v uint64) error {
	if len(c.buf)-c.off < 8 {
		return io.ErrShortBuffer
	}
	binary.BigEndian.PutUint64(c.buf[c.off:c.off+8], v)
	c.off += 8
	return nil
}

// Reserve returns the next n bytes and advances the cursor by n.
// The returned slice aliases the caller-owned backing buffer and is not zeroed.
func (c *Cursor) Reserve(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrInvalidLength
	}
	if n > len(c.buf)-c.off {
		return nil, io.ErrShortBuffer
	}
	start := c.off
	c.off += n
	return c.buf[start:c.off], nil
}

// Copy copies src into the next bytes and advances the cursor by its length.
func (c *Cursor) Copy(src []byte) error {
	if len(src) > len(c.buf)-c.off {
		return io.ErrShortBuffer
	}
	copy(c.buf[c.off:c.off+len(src)], src)
	c.off += len(src)
	return nil
}
