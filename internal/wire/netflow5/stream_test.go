package netflow5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func TestDataPacketGoldenLifecycleAndReuse(t *testing.T) {
	base := canonicalRequest(t)
	streamRequest := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape}
	streamRequest.Header.Count = 0
	dst := bytes.Repeat([]byte{0xa5}, 72)
	appender := NewDataPacket()
	if err := appender.Begin(dst, streamRequest); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if got := binary.BigEndian.Uint16(dst[2:4]); got != 0 {
		t.Fatalf("count before Finish = %d, want zero", got)
	}
	n, err := appender.Finish()
	if err != nil || n != 72 {
		t.Fatalf("Finish = (%d,%v), want (72,nil)", n, err)
	}
	if want := readGolden(t); !bytes.Equal(dst[:n], want) {
		t.Fatal("streamed v5 packet differs from immutable golden")
	}
	afterFinish := append([]byte(nil), dst...)
	if err := appender.Append(base.Records[0]); !errors.Is(err, wire.ErrPacketFinished) || !bytes.Equal(dst, afterFinish) {
		t.Fatalf("Append after Finish = %v, mutated=%v", err, !bytes.Equal(dst, afterFinish))
	}
	if _, err := appender.Finish(); !errors.Is(err, wire.ErrPacketFinished) || !bytes.Equal(dst, afterFinish) {
		t.Fatalf("second Finish = %v, mutated=%v", err, !bytes.Equal(dst, afterFinish))
	}

	reuse := bytes.Repeat([]byte{0x5a}, 72)
	if err := appender.Begin(reuse, streamRequest); err != nil {
		t.Fatalf("reuse Begin: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("reuse Append: %v", err)
	}
	if n, err := appender.Finish(); err != nil || n != 72 || !bytes.Equal(reuse, wantBytes(t)) {
		t.Fatalf("reuse Finish = (%d,%v), packet parity=%v", n, err, bytes.Equal(reuse, wantBytes(t)))
	}
}

func TestDataPacketBoundariesAndAtomicRejection(t *testing.T) {
	base := canonicalRequest(t)
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: maxRecords}
	request.Header.Count = 0
	for _, tc := range []struct {
		name  string
		count int
		want  error
	}{
		{name: "zero", count: 0, want: wire.ErrPacketEmpty},
		{name: "one", count: 1},
		{name: "thirty", count: 30},
		{name: "thirty-one", count: 31, want: wire.ErrBounds},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := bytes.Repeat([]byte{0x91}, headerLength+recordLength*maxRecords)
			appender := NewDataPacket()
			if err := appender.Begin(dst, request); err != nil {
				t.Fatalf("Begin: %v", err)
			}
			for i := 0; i < tc.count; i++ {
				if err := appender.Append(base.Records[0]); err != nil {
					if tc.want == nil || !errors.Is(err, tc.want) {
						t.Fatalf("Append %d: %v", i, err)
					}
					return
				}
			}
			if tc.want != nil {
				if _, err := appender.Finish(); !errors.Is(err, tc.want) {
					t.Fatalf("Finish = %v, want %v", err, tc.want)
				}
				return
			}
			n, err := appender.Finish()
			if err != nil || n != headerLength+recordLength*tc.count {
				t.Fatalf("Finish = (%d,%v)", n, err)
			}
			if got := binary.BigEndian.Uint16(dst[2:4]); got != uint16(tc.count) {
				t.Fatalf("count = %d, want %d", got, tc.count)
			}
		})
	}

	bad := recordWith(t, base.Records[0], 17, wire.UintValue(33))
	dst := bytes.Repeat([]byte{0x7e}, 120)
	appender := NewDataPacket()
	if err := appender.Begin(dst, wire.DataPacketRequest{Header: request.Header, Shape: request.Shape, MaxRecords: 2}); err != nil {
		t.Fatalf("atomic Begin: %v", err)
	}
	before := append([]byte(nil), dst...)
	if err := appender.Append(bad); !errors.Is(err, wire.ErrInvalidValue) || !bytes.Equal(dst, before) {
		t.Fatalf("invalid Append = %v, mutated=%v", err, !bytes.Equal(dst, before))
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("valid sibling Append: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("second valid Append: %v", err)
	}
	if _, err := appender.Finish(); err != nil {
		t.Fatalf("atomic Finish: %v", err)
	}
}

func TestDataPacketBeginResetContract(t *testing.T) {
	base := canonicalRequest(t)
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 1}
	request.Header.Count = 0
	bad := recordWith(t, base.Records[0], 17, wire.UintValue(33))
	appender := NewDataPacket()
	oldDst := bytes.Repeat([]byte{0x71}, 72)
	if err := appender.Begin(oldDst, request); err != nil {
		t.Fatalf("initial Begin: %v", err)
	}
	oldBefore := append([]byte(nil), oldDst...)
	if err := appender.Append(bad); !errors.Is(err, wire.ErrInvalidValue) || !bytes.Equal(oldDst, oldBefore) {
		t.Fatalf("first invalid Append = %v, mutated=%v", err, !bytes.Equal(oldDst, oldBefore))
	}
	if _, err := appender.Finish(); !errors.Is(err, wire.ErrPacketEmpty) || !bytes.Equal(oldDst, oldBefore) {
		t.Fatalf("empty Finish = %v, mutated=%v", err, !bytes.Equal(oldDst, oldBefore))
	}
	newDst := bytes.Repeat([]byte{0x82}, 72)
	if err := appender.Begin(newDst, request); err != nil {
		t.Fatalf("Begin after rejected packet: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("replacement Append: %v", err)
	}
	if n, err := appender.Finish(); err != nil || n != 72 {
		t.Fatalf("replacement Finish = (%d,%v)", n, err)
	}

	accepted := NewDataPacket()
	acceptedDst := bytes.Repeat([]byte{0x93}, 120)
	acceptedRequest := wire.DataPacketRequest{Header: request.Header, Shape: request.Shape, MaxRecords: 2}
	if err := accepted.Begin(acceptedDst, acceptedRequest); err != nil {
		t.Fatalf("accepted Begin: %v", err)
	}
	if err := accepted.Append(base.Records[0]); err != nil {
		t.Fatalf("accepted Append: %v", err)
	}
	acceptedBefore := append([]byte(nil), acceptedDst...)
	replacement := bytes.Repeat([]byte{0xa4}, 72)
	if err := accepted.Begin(replacement, request); err != nil {
		t.Fatalf("reset Begin: %v", err)
	}
	if !bytes.Equal(acceptedDst, acceptedBefore) {
		t.Fatal("successful Begin changed discarded packet buffer")
	}
	if err := accepted.Append(base.Records[0]); err != nil {
		t.Fatalf("reset Append: %v", err)
	}
	if _, err := accepted.Finish(); err != nil {
		t.Fatalf("reset Finish: %v", err)
	}

	failed := NewDataPacket()
	failedDst := bytes.Repeat([]byte{0xb5}, 120)
	if err := failed.Begin(failedDst, acceptedRequest); err != nil {
		t.Fatalf("failed-reset Begin: %v", err)
	}
	if err := failed.Append(base.Records[0]); err != nil {
		t.Fatalf("failed-reset Append: %v", err)
	}
	candidate := bytes.Repeat([]byte{0xc6}, 72)
	candidateBefore := append([]byte(nil), candidate...)
	invalidRequest := acceptedRequest
	invalidRequest.MaxDatagramBytes = 1
	if err := failed.Begin(candidate, invalidRequest); !errors.Is(err, wire.ErrBounds) || !bytes.Equal(candidate, candidateBefore) {
		t.Fatalf("failed reset Begin = %v, candidate mutated=%v", err, !bytes.Equal(candidate, candidateBefore))
	}
	if err := failed.Append(base.Records[0]); err != nil {
		t.Fatalf("old packet after failed reset: %v", err)
	}
	if n, err := failed.Finish(); err != nil || n != 120 {
		t.Fatalf("old packet Finish after failed reset = (%d,%v)", n, err)
	}
}

func TestDataPacketCapacityAndZeroAllocations(t *testing.T) {
	base := canonicalRequest(t)
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxDatagramBytes: 72}
	request.Header.Count = 0
	appender := NewDataPacket()
	if err := appender.Begin(make([]byte, 72), request); err != nil {
		t.Fatalf("exact Begin: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("exact Append: %v", err)
	}
	if _, err := appender.Finish(); err != nil {
		t.Fatalf("exact Finish: %v", err)
	}

	tooSmallBudget := wire.DataPacketRequest{Header: request.Header, Shape: request.Shape, MaxDatagramBytes: 71}
	dst := bytes.Repeat([]byte{0xc3}, 72)
	if err := appender.Begin(dst, tooSmallBudget); err != nil {
		t.Fatalf("narrow Begin: %v", err)
	}
	before := append([]byte(nil), dst...)
	if err := appender.Append(base.Records[0]); !errors.Is(err, wire.ErrBounds) || !bytes.Equal(dst, before) {
		t.Fatalf("narrow Append = %v, mutated=%v", err, !bytes.Equal(dst, before))
	}
	short := bytes.Repeat([]byte{0x4d}, 71)
	shortAppender := NewDataPacket()
	if err := shortAppender.Begin(short, wire.DataPacketRequest{Header: request.Header, Shape: request.Shape}); err != nil {
		t.Fatalf("short Begin: %v", err)
	}
	before = append([]byte(nil), short...)
	if err := shortAppender.Append(base.Records[0]); !errors.Is(err, wire.ErrShortBuffer) || !bytes.Equal(short, before) {
		t.Fatalf("short Append = %v, mutated=%v", err, !bytes.Equal(short, before))
	}

	allocDst := make([]byte, 72)
	allocAppender := NewDataPacket()
	allocRequest := wire.DataPacketRequest{Header: request.Header, Shape: request.Shape}
	allocs := testing.AllocsPerRun(1000, func() {
		if err := allocAppender.Begin(allocDst, allocRequest); err != nil {
			panic(err)
		}
		if err := allocAppender.Append(base.Records[0]); err != nil {
			panic(err)
		}
		if _, err := allocAppender.Finish(); err != nil {
			panic(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("stream operations allocations = %v, want zero", allocs)
	}
}

func wantBytes(t *testing.T) []byte {
	t.Helper()
	return readGolden(t)
}

func TestDataPacketResetReleasesCallerBuffer(t *testing.T) {
	base := canonicalRequest(t)
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 1}
	request.Header.Count = 0
	dst := make([]byte, 72)
	appender := &dataPacketAppender{}
	if err := appender.Begin(dst, request); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("Append: %v", err)
	}
	appender.Reset()
	if appender.dst != nil || appender.header != (wire.HeaderMetadata{}) || len(appender.shape.Fields()) != 0 || appender.budget != 0 || appender.recordCap != 0 || appender.begun || appender.done || appender.records != 0 || appender.recordBytes != 0 {
		t.Fatalf("Reset retained appender state: %+v", appender)
	}
	if err := appender.Append(base.Records[0]); !errors.Is(err, wire.ErrPacketNotBegun) {
		t.Fatalf("Append after Reset = %v", err)
	}
	if _, err := appender.Finish(); !errors.Is(err, wire.ErrPacketNotBegun) {
		t.Fatalf("Finish after Reset = %v", err)
	}
}
