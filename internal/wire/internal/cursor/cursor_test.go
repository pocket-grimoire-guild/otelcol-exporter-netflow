package cursor

import (
	"bytes"
	"io"
	"testing"
)

func TestZeroValueAndBufferBoundaries(t *testing.T) {
	var zero Cursor
	if got := zero.Offset(); got != 0 {
		t.Fatalf("zero Offset() = %d, want 0", got)
	}
	if got := zero.Remaining(); got != 0 {
		t.Fatalf("zero Remaining() = %d, want 0", got)
	}
	if err := zero.WriteByte(1); err != io.ErrShortBuffer {
		t.Fatalf("zero WriteByte() error = %v, want %v", err, io.ErrShortBuffer)
	}

	cases := []struct {
		name string
		buf  []byte
	}{
		{name: "nil", buf: nil},
		{name: "zero", buf: []byte{}},
		{name: "one", buf: []byte{0xa5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := New(tc.buf)
			if got := c.Offset(); got != 0 {
				t.Fatalf("initial Offset() = %d, want 0", got)
			}
			if got := c.Remaining(); got != len(tc.buf) {
				t.Fatalf("initial Remaining() = %d, want %d", got, len(tc.buf))
			}

			if len(tc.buf) == 1 {
				if err := c.WriteByte(0x7e); err != nil {
					t.Fatalf("WriteByte() error = %v", err)
				}
				if got := c.Offset(); got != 1 {
					t.Fatalf("end Offset() = %d, want 1", got)
				}
				if got := c.Remaining(); got != 0 {
					t.Fatalf("end Remaining() = %d, want 0", got)
				}
				if tc.buf[0] != 0x7e {
					t.Fatalf("written byte = %#x, want %#x", tc.buf[0], byte(0x7e))
				}
				return
			}

			before := append([]byte(nil), tc.buf...)
			if err := c.WriteByte(1); err != io.ErrShortBuffer {
				t.Fatalf("WriteByte() error = %v, want %v", err, io.ErrShortBuffer)
			}
			if c.Offset() != 0 || c.Remaining() != len(tc.buf) || !bytes.Equal(tc.buf, before) {
				t.Fatalf("failed WriteByte mutated cursor or buffer: offset=%d remaining=%d buf=%x before=%x", c.Offset(), c.Remaining(), tc.buf, before)
			}
		})
	}
}

func TestIntegerWritesExactShortAndByteOrder(t *testing.T) {
	cases := []struct {
		name  string
		width int
		want  []byte
		write func(*Cursor) error
		retry func(*Cursor) error
	}{
		{name: "byte", width: 1, want: []byte{0x7e}, write: func(c *Cursor) error { return c.WriteByte(0x7e) }, retry: func(c *Cursor) error { _, err := c.Reserve(0); return err }},
		{name: "uint8", width: 1, want: []byte{0xd3}, write: func(c *Cursor) error { return c.WriteUint8(0xd3) }, retry: func(c *Cursor) error { return c.Copy(nil) }},
		{name: "uint16", width: 2, want: []byte{0x12, 0x34}, write: func(c *Cursor) error { return c.WriteUint16(0x1234) }, retry: func(c *Cursor) error { return c.WriteByte(0x9a) }},
		{name: "uint32", width: 4, want: []byte{0x12, 0x34, 0x56, 0x78}, write: func(c *Cursor) error { return c.WriteUint32(0x12345678) }, retry: func(c *Cursor) error { return c.WriteUint16(0x9abc) }},
		{name: "uint64", width: 8, want: []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}, write: func(c *Cursor) error { return c.WriteUint64(0x0123456789abcdef) }, retry: func(c *Cursor) error { return c.WriteUint32(0x9abcdef0) }},
	}

	for _, tc := range cases {
		t.Run(tc.name+"-exact", func(t *testing.T) {
			buf := bytes.Repeat([]byte{0xa5}, tc.width)
			c := New(buf)
			if err := tc.write(&c); err != nil {
				t.Fatalf("exact write error = %v", err)
			}
			if !bytes.Equal(buf, tc.want) {
				t.Fatalf("bytes = %x, want %x", buf, tc.want)
			}
			if c.Offset() != tc.width || c.Remaining() != 0 {
				t.Fatalf("end cursor = offset %d remaining %d, want %d and 0", c.Offset(), c.Remaining(), tc.width)
			}
		})

		t.Run(tc.name+"-short", func(t *testing.T) {
			buf := bytes.Repeat([]byte{0xa5}, tc.width-1)
			before := append([]byte(nil), buf...)
			c := New(buf)
			if err := tc.write(&c); err != io.ErrShortBuffer {
				t.Fatalf("short write error = %v, want %v", err, io.ErrShortBuffer)
			}
			if c.Offset() != 0 || c.Remaining() != len(buf) || !bytes.Equal(buf, before) {
				t.Fatalf("failed write mutated cursor or buffer: offset=%d remaining=%d buf=%x before=%x", c.Offset(), c.Remaining(), buf, before)
			}
			if err := tc.retry(&c); err != nil {
				t.Fatalf("successful retry error = %v", err)
			}
		})
	}
}

func TestReserveBoundariesAndAlias(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	buf := []byte{0x11, 0x22, 0x33, 0x44}
	c := New(buf)
	before := append([]byte(nil), buf...)

	if got, err := c.Reserve(-1); err != ErrInvalidLength || got != nil {
		t.Fatalf("Reserve(-1) = (%x, %v), want (nil, %v)", got, err, ErrInvalidLength)
	}
	if c.Offset() != 0 || c.Remaining() != len(buf) || !bytes.Equal(buf, before) {
		t.Fatalf("negative reserve mutated cursor or buffer")
	}

	if got, err := c.Reserve(0); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("Reserve(0) = (%x, %v), want empty success", got, err)
	}
	if c.Offset() != 0 || !bytes.Equal(buf, before) {
		t.Fatalf("zero reserve mutated cursor or buffer")
	}

	reserved, err := c.Reserve(2)
	if err != nil || len(reserved) != 2 || !bytes.Equal(reserved, before[:2]) {
		t.Fatalf("Reserve(2) = (%x, %v), want alias of %x", reserved, err, before[:2])
	}
	reserved[0] = 0xf0
	if buf[0] != 0xf0 || c.Offset() != 2 || c.Remaining() != 2 {
		t.Fatalf("reserve result does not alias or cursor is wrong: buf=%x offset=%d remaining=%d", buf, c.Offset(), c.Remaining())
	}

	for _, n := range []int{3, maxInt} {
		beforeFail := append([]byte(nil), buf...)
		off := c.Offset()
		if got, err := c.Reserve(n); err != io.ErrShortBuffer || got != nil {
			t.Fatalf("Reserve(%d) = (%x, %v), want (nil, %v)", n, got, err, io.ErrShortBuffer)
		}
		if c.Offset() != off || c.Remaining() != len(buf)-off || !bytes.Equal(buf, beforeFail) {
			t.Fatalf("Reserve(%d) mutated cursor or buffer", n)
		}
	}
	if _, err := c.Reserve(2); err != nil {
		t.Fatalf("exact reserve retry error = %v", err)
	}
}

func TestCopyBoundariesAndImmutability(t *testing.T) {
	buf := []byte{0xa1, 0xa2, 0xa3, 0xa4}
	c := New(buf)
	before := append([]byte(nil), buf...)
	if err := c.Copy(nil); err != nil {
		t.Fatalf("Copy(nil) error = %v", err)
	}
	if err := c.Copy([]byte{}); err != nil {
		t.Fatalf("Copy(empty) error = %v", err)
	}
	if c.Offset() != 0 || !bytes.Equal(buf, before) {
		t.Fatalf("empty copies mutated cursor or buffer")
	}

	src := []byte{1, 2, 3, 4}
	if err := c.Copy(src); err != nil {
		t.Fatalf("Copy(exact) error = %v", err)
	}
	if c.Offset() != len(buf) || c.Remaining() != 0 || !bytes.Equal(buf, src) {
		t.Fatalf("exact copy result: offset=%d remaining=%d buf=%x", c.Offset(), c.Remaining(), buf)
	}

	shortBuf := []byte{0xb1, 0xb2, 0xb3}
	shortBefore := append([]byte(nil), shortBuf...)
	short := New(shortBuf)
	if err := short.Copy([]byte{9, 8, 7, 6}); err != io.ErrShortBuffer {
		t.Fatalf("oversize Copy() error = %v, want %v", err, io.ErrShortBuffer)
	}
	if short.Offset() != 0 || short.Remaining() != len(shortBuf) || !bytes.Equal(shortBuf, shortBefore) {
		t.Fatalf("oversize copy mutated cursor or buffer")
	}
	if err := short.Copy([]byte{9, 8, 7}); err != nil {
		t.Fatalf("successful copy retry error = %v", err)
	}
	if !bytes.Equal(shortBuf, []byte{9, 8, 7}) || short.Offset() != 3 {
		t.Fatalf("copy retry result: offset=%d buf=%x", short.Offset(), shortBuf)
	}
}

func TestFailedOperationsPreserveState(t *testing.T) {
	tests := []struct {
		name   string
		bufLen int
		fail   func(*Cursor) error
		retry  func(*Cursor) error
	}{
		{name: "byte", bufLen: 0, fail: func(c *Cursor) error { return c.WriteByte(1) }, retry: func(c *Cursor) error { return c.Copy(nil) }},
		{name: "uint8", bufLen: 0, fail: func(c *Cursor) error { return c.WriteUint8(1) }, retry: func(c *Cursor) error { _, err := c.Reserve(0); return err }},
		{name: "uint16", bufLen: 1, fail: func(c *Cursor) error { return c.WriteUint16(1) }, retry: func(c *Cursor) error { return c.WriteByte(2) }},
		{name: "uint32", bufLen: 3, fail: func(c *Cursor) error { return c.WriteUint32(1) }, retry: func(c *Cursor) error { return c.WriteUint16(2) }},
		{name: "uint64", bufLen: 7, fail: func(c *Cursor) error { return c.WriteUint64(1) }, retry: func(c *Cursor) error { return c.WriteUint32(2) }},
		{name: "reserve-negative", bufLen: 2, fail: func(c *Cursor) error { _, err := c.Reserve(-1); return err }, retry: func(c *Cursor) error { _, err := c.Reserve(2); return err }},
		{name: "reserve-oversize", bufLen: 2, fail: func(c *Cursor) error { _, err := c.Reserve(3); return err }, retry: func(c *Cursor) error { _, err := c.Reserve(2); return err }},
		{name: "reserve-max-int", bufLen: 2, fail: func(c *Cursor) error { _, err := c.Reserve(int(^uint(0) >> 1)); return err }, retry: func(c *Cursor) error { _, err := c.Reserve(2); return err }},
		{name: "copy-oversize", bufLen: 2, fail: func(c *Cursor) error { return c.Copy([]byte{1, 2, 3}) }, retry: func(c *Cursor) error { return c.Copy([]byte{1, 2}) }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.Repeat([]byte{0xc1}, tc.bufLen)
			before := append([]byte(nil), buf...)
			c := New(buf)
			off, rem := c.Offset(), c.Remaining()
			wantErr := io.ErrShortBuffer
			if tc.name == "reserve-negative" {
				wantErr = ErrInvalidLength
			}
			if err := tc.fail(&c); err != wantErr {
				t.Fatalf("failed operation error = %v, want %v", err, wantErr)
			}
			if c.Offset() != off || c.Remaining() != rem || !bytes.Equal(buf, before) {
				t.Fatalf("failed operation mutated state: offset=%d remaining=%d buf=%x before=%x", c.Offset(), c.Remaining(), buf, before)
			}
			if err := tc.retry(&c); err != nil {
				t.Fatalf("successful retry error = %v", err)
			}
		})
	}
}

func TestOperationAllocations(t *testing.T) {
	buf := make([]byte, 8)
	src := []byte{1, 2, 3, 4}
	oversizedSrc := make([]byte, 9)
	maxInt := int(^uint(0) >> 1)
	tests := []struct {
		name string
		op   int
	}{
		{name: "write-byte-success", op: 0},
		{name: "write-byte-failure", op: 1},
		{name: "write-uint8-success", op: 2},
		{name: "write-uint8-failure", op: 3},
		{name: "write-uint16-success", op: 4},
		{name: "write-uint16-failure", op: 5},
		{name: "write-uint32-success", op: 6},
		{name: "write-uint32-failure", op: 7},
		{name: "write-uint64-success", op: 8},
		{name: "write-uint64-failure", op: 9},
		{name: "reserve-success", op: 10},
		{name: "reserve-negative", op: 11},
		{name: "reserve-oversize", op: 12},
		{name: "reserve-max-int", op: 13},
		{name: "copy-success", op: 14},
		{name: "copy-failure", op: 15},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			op := tc.op
			got := testing.AllocsPerRun(1000, func() {
				c := New(buf)
				switch op {
				case 0:
					_ = c.WriteByte(1)
				case 1:
					c = New(nil)
					_ = c.WriteByte(1)
				case 2:
					_ = c.WriteUint8(1)
				case 3:
					c = New(nil)
					_ = c.WriteUint8(1)
				case 4:
					_ = c.WriteUint16(1)
				case 5:
					c = New(buf[:1])
					_ = c.WriteUint16(1)
				case 6:
					_ = c.WriteUint32(1)
				case 7:
					c = New(buf[:3])
					_ = c.WriteUint32(1)
				case 8:
					_ = c.WriteUint64(1)
				case 9:
					c = New(buf[:7])
					_ = c.WriteUint64(1)
				case 10:
					_, _ = c.Reserve(2)
				case 11:
					_, _ = c.Reserve(-1)
				case 12:
					_, _ = c.Reserve(9)
				case 13:
					_, _ = c.Reserve(maxInt)
				case 14:
					_ = c.Copy(src)
				case 15:
					_ = c.Copy(oversizedSrc)
				}
			})
			if got != 0 {
				t.Fatalf("allocations per operation = %v, want 0", got)
			}
		})
	}
}
