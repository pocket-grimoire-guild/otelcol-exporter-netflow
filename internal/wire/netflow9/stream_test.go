package netflow9

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func TestDataPacketGoldenAndEnvelopeAdjustment(t *testing.T) {
	for _, id := range []string{"canonical-ipv4-v1", "canonical-ipv6-v1", "sampling-ie34-two-distinct-rates-v9-v1"} {
		t.Run(id, func(t *testing.T) {
			base := fixtureRequest(t, id)
			golden := readGolden(t, map[string]string{
				"canonical-ipv4-v1":                      "canonical-ipv4-v1.bin",
				"canonical-ipv6-v1":                      "canonical-ipv6-v1.bin",
				"sampling-ie34-two-distinct-rates-v9-v1": "sampling-ie34-two-distinct-rates-v1.bin",
			}[id])
			const templateBytes = 80
			want := make([]byte, len(golden)-templateBytes)
			copy(want[:headerLength], golden[:headerLength])
			copy(want[headerLength:], golden[headerLength+templateBytes:])
			binary.BigEndian.PutUint16(want[2:4], uint16(len(base.Records)))

			dst := bytes.Repeat([]byte{0xa5}, len(want))
			request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: uint64(len(base.Records))}
			request.Header.Count = 0
			appender := NewDataPacket()
			if err := appender.Begin(dst, request); err != nil {
				t.Fatalf("Begin: %v", err)
			}
			for _, record := range base.Records {
				if err := appender.Append(record); err != nil {
					t.Fatalf("Append: %v", err)
				}
			}
			n, err := appender.Finish()
			if err != nil || n != len(want) || !bytes.Equal(dst[:n], want) {
				t.Fatalf("Finish = (%d,%v), parity=%v", n, err, bytes.Equal(dst[:n], want))
			}
			if got := binary.BigEndian.Uint16(dst[2:4]); got != uint16(len(base.Records)) {
				t.Fatalf("data count = %d, want %d", got, len(base.Records))
			}
		})
	}
}

func TestDataPacketAtomicTemporalGatePaddingAndReuse(t *testing.T) {
	base := fixtureRequest(t, "canonical-ipv4-v1")
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 2}
	request.Header.Count = 0
	dst := bytes.Repeat([]byte{0x91}, 128)
	appender := NewDataPacket()
	if err := appender.Begin(dst, request); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	bad := recordWith(t, base.Records[0], 16, wire.UintValue(uint64(^uint32(0))+1))
	before := append([]byte(nil), dst...)
	if err := appender.Append(bad); !errors.Is(err, wire.ErrInvalidValue) || !bytes.Equal(dst, before) {
		t.Fatalf("invalid Append = %v, mutated=%v", err, !bytes.Equal(dst, before))
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("valid sibling Append: %v", err)
	}
	if _, err := appender.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	after := append([]byte(nil), dst...)
	if err := appender.Append(base.Records[0]); !errors.Is(err, wire.ErrPacketFinished) || !bytes.Equal(dst, after) {
		t.Fatalf("Append after Finish = %v, mutated=%v", err, !bytes.Equal(dst, after))
	}

	shape := customByteShape(t)
	record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.UintValue(1)})
	if err != nil {
		t.Fatal(err)
	}
	header := wire.HeaderMetadata{Protocol: wire.ProtocolV9, SourceID: 9, ObservationDomainID: 9, ExportTimeUnixNanos: 1, UptimeOriginUnixNanos: 1, HasUptimeOrigin: true, Count: 0}
	stream := NewDataPacket()
	noPadding := make([]byte, 29)
	if err := stream.Begin(noPadding, wire.DataPacketRequest{Header: header, Shape: shape}); err != nil {
		t.Fatalf("custom Begin: %v", err)
	}
	if err := stream.Append(record); err != nil {
		t.Fatalf("custom Append: %v", err)
	}
	if n, err := stream.Finish(); err != nil || n != 25 || binary.BigEndian.Uint16(noPadding[22:24]) != 5 {
		t.Fatalf("custom Finish = (%d,%v), set length=%d", n, err, binary.BigEndian.Uint16(noPadding[22:24]))
	}

	timeShape := timestampShape(t,
		wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldFlowStart, ID: 22, Length: 4, Encoding: wire.EncodingUnsigned32},
		wire.FieldDescriptor{Protocol: wire.ProtocolV9, Field: wire.FieldFlowEnd, ID: 21, Length: 4, Encoding: wire.EncodingUnsigned32},
	)
	origin := uint64(1_700_000_000) * nanosPerSec
	timeRequest := timestampRequest(t, timeShape, origin, origin+1234*nanosPerMS, origin+2345*nanosPerMS, origin+3000*nanosPerMS)
	timeRequest.Header.Count = 0
	timeApp := NewDataPacket()
	timeDst := make([]byte, 32) // data-only packet: 20-byte header + 4-byte set header + 8-byte record
	if err := timeApp.Begin(timeDst, wire.DataPacketRequest{Header: timeRequest.Header, Shape: timeRequest.Shape}); err != nil {
		t.Fatalf("time Begin: %v", err)
	}
	if err := timeApp.Append(timeRequest.Records[0]); err != nil {
		t.Fatalf("time Append: %v", err)
	}
	if _, err := timeApp.Finish(); err != nil {
		t.Fatalf("time Finish: %v", err)
	}
}

func TestDataPacketRecordCap1024And1025(t *testing.T) {
	shape := customByteShape(t)
	record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.UintValue(1)})
	if err != nil {
		t.Fatal(err)
	}
	header := wire.HeaderMetadata{Protocol: wire.ProtocolV9, SourceID: 9, ObservationDomainID: 9, ExportTimeUnixNanos: 1, UptimeOriginUnixNanos: 1, HasUptimeOrigin: true}
	dst := make([]byte, 1100)
	appender := NewDataPacket()
	if err := appender.Begin(dst, wire.DataPacketRequest{Header: header, Shape: shape, MaxRecords: 1024}); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for i := 0; i < 1024; i++ {
		if err := appender.Append(record); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	before := append([]byte(nil), dst...)
	if err := appender.Append(record); !errors.Is(err, wire.ErrBounds) || !bytes.Equal(dst, before) {
		t.Fatalf("1025th Append = %v, mutated=%v", err, !bytes.Equal(dst, before))
	}
	if n, err := appender.Finish(); err != nil || n != 1048 {
		t.Fatalf("Finish = (%d,%v), want (1048,nil)", n, err)
	}
}

func TestDataPacketBeginResetContract(t *testing.T) {
	base := fixtureRequest(t, "canonical-ipv4-v1")
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 1}
	request.Header.Count = 0
	bad := recordWith(t, base.Records[0], 16, wire.UintValue(uint64(^uint32(0))+1))
	appender := NewDataPacket()
	oldDst := bytes.Repeat([]byte{0x71}, 68)
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
	newDst := bytes.Repeat([]byte{0x82}, 68)
	if err := appender.Begin(newDst, request); err != nil {
		t.Fatalf("Begin after rejected packet: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("replacement Append: %v", err)
	}
	if n, err := appender.Finish(); err != nil || n != 68 {
		t.Fatalf("replacement Finish = (%d,%v)", n, err)
	}

	accepted := NewDataPacket()
	acceptedDst := bytes.Repeat([]byte{0x93}, 128)
	acceptedRequest := wire.DataPacketRequest{Header: request.Header, Shape: request.Shape, MaxRecords: 2}
	if err := accepted.Begin(acceptedDst, acceptedRequest); err != nil {
		t.Fatalf("accepted Begin: %v", err)
	}
	if err := accepted.Append(base.Records[0]); err != nil {
		t.Fatalf("accepted Append: %v", err)
	}
	acceptedBefore := append([]byte(nil), acceptedDst...)
	replacement := bytes.Repeat([]byte{0xa4}, 68)
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
	failedDst := bytes.Repeat([]byte{0xb5}, 128)
	if err := failed.Begin(failedDst, acceptedRequest); err != nil {
		t.Fatalf("failed-reset Begin: %v", err)
	}
	if err := failed.Append(base.Records[0]); err != nil {
		t.Fatalf("failed-reset Append: %v", err)
	}
	candidate := bytes.Repeat([]byte{0xc6}, 68)
	candidateBefore := append([]byte(nil), candidate...)
	invalidRequest := acceptedRequest
	invalidRequest.MaxDatagramBytes = 1
	if err := failed.Begin(candidate, invalidRequest); !errors.Is(err, wire.ErrBounds) || !bytes.Equal(candidate, candidateBefore) {
		t.Fatalf("failed reset Begin = %v, candidate mutated=%v", err, !bytes.Equal(candidate, candidateBefore))
	}
	if err := failed.Append(base.Records[0]); err != nil {
		t.Fatalf("old packet after failed reset: %v", err)
	}
	if n, err := failed.Finish(); err != nil || n != 112 {
		t.Fatalf("old packet Finish after failed reset = (%d,%v)", n, err)
	}
}

func TestDataPacketCapacityAndZeroAllocations(t *testing.T) {
	base := fixtureRequest(t, "canonical-ipv4-v1")
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxDatagramBytes: 68}
	request.Header.Count = 0
	appender := NewDataPacket()
	if err := appender.Begin(make([]byte, 68), request); err != nil {
		t.Fatalf("exact Begin: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("exact Append: %v", err)
	}
	if _, err := appender.Finish(); err != nil {
		t.Fatalf("exact Finish: %v", err)
	}

	narrow := NewDataPacket()
	dst := bytes.Repeat([]byte{0xc3}, 67)
	if err := narrow.Begin(dst, wire.DataPacketRequest{Header: request.Header, Shape: request.Shape, MaxDatagramBytes: 67}); err != nil {
		t.Fatalf("narrow Begin: %v", err)
	}
	before := append([]byte(nil), dst...)
	if err := narrow.Append(base.Records[0]); !errors.Is(err, wire.ErrBounds) || !bytes.Equal(dst, before) {
		t.Fatalf("narrow Append = %v, mutated=%v", err, !bytes.Equal(dst, before))
	}

	allocDst := make([]byte, 68)
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

func TestDataPacketResetReleasesCallerBuffer(t *testing.T) {
	base := fixtureRequest(t, "canonical-ipv4-v1")
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 1}
	request.Header.Count = 0
	dst := make([]byte, 68)
	appender := &dataPacketAppender{}
	if err := appender.Begin(dst, request); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("Append: %v", err)
	}
	appender.Reset()
	if appender.dst != nil || appender.header != (wire.HeaderMetadata{}) || len(appender.shape.Fields()) != 0 || appender.budget != 0 || appender.recordCap != 0 || appender.begun || appender.done || appender.records != 0 || appender.recordBytes != 0 || appender.dataOffset != 0 {
		t.Fatalf("Reset retained appender state: %+v", appender)
	}
	if err := appender.Append(base.Records[0]); !errors.Is(err, wire.ErrPacketNotBegun) {
		t.Fatalf("Append after Reset = %v", err)
	}
	if _, err := appender.Finish(); !errors.Is(err, wire.ErrPacketNotBegun) {
		t.Fatalf("Finish after Reset = %v", err)
	}
}
