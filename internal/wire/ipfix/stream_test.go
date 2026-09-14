package ipfix

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func TestDataPacketGoldenAndEnvelopeAdjustment(t *testing.T) {
	for _, id := range []string{"canonical-ipv4-v1", "canonical-ipv6-v1", "sampling-ie34-two-distinct-rates-v1"} {
		t.Run(id, func(t *testing.T) {
			base := fixtureRequest(id)
			golden := readGolden(t, id+".bin")
			const templateBytes = 88
			want := make([]byte, len(golden)-templateBytes)
			copy(want[:headerLength], golden[:headerLength])
			copy(want[headerLength:], golden[headerLength+templateBytes:])
			binary.BigEndian.PutUint16(want[2:4], uint16(len(want)))

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
		})
	}
}

func TestDataPacketAtomicVariablePrefixPaddingAndReuse(t *testing.T) {
	base := fixtureRequest("canonical-ipv4-v1")
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 2}
	request.Header.Count = 0
	dst := bytes.Repeat([]byte{0x91}, 256)
	appender := NewDataPacket()
	if err := appender.Begin(dst, request); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	bad := replaceValue(t, base.Records[0], 18, wire.UnixNanosValue(maxUnixNanosIPFIX+1))
	before := append([]byte(nil), dst...)
	if err := appender.Append(bad); !errors.Is(err, wire.ErrTimeOutOfRange) || !bytes.Equal(dst, before) {
		t.Fatalf("invalid NTP Append = %v, mutated=%v", err, !bytes.Equal(dst, before))
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

	descriptor, err := wire.NewIPFIXEnterpriseDescriptor("vendor.variable", 32473, 100, wire.EncodingOctetArray, true, 65535, 65535)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := wire.NewShape(wire.ShapeSpec{Protocol: wire.ProtocolIPFIX, Family: wire.FamilyIPv4, ID: 300, Fields: []wire.FieldDescriptor{descriptor}, RecordLength: 1, TemplateBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	header := wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX, ObservationDomainID: 9, ExportTimeUnixNanos: 1}
	for _, length := range []int{254, 255} {
		source := bytes.Repeat([]byte{0x5a}, length)
		value := wire.OctetsValue(string(source))
		record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{value})
		if err != nil {
			t.Fatal(err)
		}
		packet := make([]byte, headerLength+4+length+3+4)
		stream := NewDataPacket()
		if err := stream.Begin(packet, wire.DataPacketRequest{Header: header, Shape: shape}); err != nil {
			t.Fatalf("variable %d Begin: %v", length, err)
		}
		if err := stream.Append(record); err != nil {
			t.Fatalf("variable %d Append: %v", length, err)
		}
		for i := range source {
			source[i] = 0x11
		}
		n, err := stream.Finish()
		if err != nil {
			t.Fatalf("variable %d Finish: %v", length, err)
		}
		prefix := headerLength + 4
		if length < 255 {
			if packet[prefix] != byte(length) || n != headerLength+4+1+length {
				t.Fatalf("variable %d one-byte prefix/length: %#x/%d", length, packet[prefix], n)
			}
		} else if packet[prefix] != 255 || binary.BigEndian.Uint16(packet[prefix+1:prefix+3]) != uint16(length) {
			t.Fatalf("variable %d extended prefix = %x", length, packet[prefix:prefix+3])
		}
		payloadOffset := prefix + 1
		if length >= 255 {
			payloadOffset += 2
		}
		if !bytes.Equal(packet[payloadOffset:payloadOffset+length], bytes.Repeat([]byte{0x5a}, length)) {
			t.Fatalf("variable %d payload changed after source mutation", length)
		}
	}
}

func TestDataPacketRecordCap1024And1025(t *testing.T) {
	descriptor, err := wire.NewIPFIXEnterpriseDescriptor("vendor.byte", 32473, 100, wire.EncodingUnsigned8, false, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := wire.NewShape(wire.ShapeSpec{Protocol: wire.ProtocolIPFIX, Family: wire.FamilyIPv4, ID: 300, Fields: []wire.FieldDescriptor{descriptor}, RecordLength: 1, TemplateBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	record, err := wire.NewWireRecord(wire.FamilyIPv4, []wire.Value{wire.UintValue(1)})
	if err != nil {
		t.Fatal(err)
	}
	header := wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX, ObservationDomainID: 9, ExportTimeUnixNanos: 1}
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
	if n, err := appender.Finish(); err != nil || n != 1044 {
		t.Fatalf("Finish = (%d,%v), want (1044,nil)", n, err)
	}
}

func TestDataPacketBeginResetContract(t *testing.T) {
	base := fixtureRequest("canonical-ipv4-v1")
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 1}
	request.Header.Count = 0
	bad := replaceValue(t, base.Records[0], 18, wire.UnixNanosValue(maxUnixNanosIPFIX+1))
	appender := NewDataPacket()
	oldDst := bytes.Repeat([]byte{0x71}, 92)
	if err := appender.Begin(oldDst, request); err != nil {
		t.Fatalf("initial Begin: %v", err)
	}
	oldBefore := append([]byte(nil), oldDst...)
	if err := appender.Append(bad); !errors.Is(err, wire.ErrTimeOutOfRange) || !bytes.Equal(oldDst, oldBefore) {
		t.Fatalf("first invalid Append = %v, mutated=%v", err, !bytes.Equal(oldDst, oldBefore))
	}
	if _, err := appender.Finish(); !errors.Is(err, wire.ErrPacketEmpty) || !bytes.Equal(oldDst, oldBefore) {
		t.Fatalf("empty Finish = %v, mutated=%v", err, !bytes.Equal(oldDst, oldBefore))
	}
	newDst := bytes.Repeat([]byte{0x82}, 92)
	if err := appender.Begin(newDst, request); err != nil {
		t.Fatalf("Begin after rejected packet: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("replacement Append: %v", err)
	}
	if n, err := appender.Finish(); err != nil || n != 92 {
		t.Fatalf("replacement Finish = (%d,%v)", n, err)
	}

	accepted := NewDataPacket()
	acceptedDst := bytes.Repeat([]byte{0x93}, 200)
	acceptedRequest := wire.DataPacketRequest{Header: request.Header, Shape: request.Shape, MaxRecords: 2}
	if err := accepted.Begin(acceptedDst, acceptedRequest); err != nil {
		t.Fatalf("accepted Begin: %v", err)
	}
	if err := accepted.Append(base.Records[0]); err != nil {
		t.Fatalf("accepted Append: %v", err)
	}
	acceptedBefore := append([]byte(nil), acceptedDst...)
	replacement := bytes.Repeat([]byte{0xa4}, 92)
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
	failedDst := bytes.Repeat([]byte{0xb5}, 200)
	if err := failed.Begin(failedDst, acceptedRequest); err != nil {
		t.Fatalf("failed-reset Begin: %v", err)
	}
	if err := failed.Append(base.Records[0]); err != nil {
		t.Fatalf("failed-reset Append: %v", err)
	}
	candidate := bytes.Repeat([]byte{0xc6}, 92)
	candidateBefore := append([]byte(nil), candidate...)
	invalidRequest := acceptedRequest
	invalidRequest.MaxDatagramBytes = 1
	if err := failed.Begin(candidate, invalidRequest); !errors.Is(err, wire.ErrBounds) || !bytes.Equal(candidate, candidateBefore) {
		t.Fatalf("failed reset Begin = %v, candidate mutated=%v", err, !bytes.Equal(candidate, candidateBefore))
	}
	if err := failed.Append(base.Records[0]); err != nil {
		t.Fatalf("old packet after failed reset: %v", err)
	}
	if n, err := failed.Finish(); err != nil || n != 164 {
		t.Fatalf("old packet Finish after failed reset = (%d,%v)", n, err)
	}
}

func TestDataPacketCapacityAndZeroAllocations(t *testing.T) {
	base := fixtureRequest("canonical-ipv4-v1")
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxDatagramBytes: 92}
	request.Header.Count = 0
	appender := NewDataPacket()
	if err := appender.Begin(make([]byte, 92), request); err != nil {
		t.Fatalf("exact Begin: %v", err)
	}
	if err := appender.Append(base.Records[0]); err != nil {
		t.Fatalf("exact Append: %v", err)
	}
	if _, err := appender.Finish(); err != nil {
		t.Fatalf("exact Finish: %v", err)
	}

	narrow := NewDataPacket()
	dst := bytes.Repeat([]byte{0xc3}, 91)
	if err := narrow.Begin(dst, wire.DataPacketRequest{Header: request.Header, Shape: request.Shape, MaxDatagramBytes: 91}); err != nil {
		t.Fatalf("narrow Begin: %v", err)
	}
	before := append([]byte(nil), dst...)
	if err := narrow.Append(base.Records[0]); !errors.Is(err, wire.ErrBounds) || !bytes.Equal(dst, before) {
		t.Fatalf("narrow Append = %v, mutated=%v", err, !bytes.Equal(dst, before))
	}

	allocDst := make([]byte, 92)
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
	base := fixtureRequest("canonical-ipv4-v1")
	request := wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxRecords: 1}
	request.Header.Count = 0
	dst := make([]byte, 92)
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
