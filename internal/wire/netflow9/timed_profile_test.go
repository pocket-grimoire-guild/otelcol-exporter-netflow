package netflow9

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

const timedOrigin = uint64(1_788_220_800_000_000_000)

func TestTimedProfileWritesMeasuredUptime(t *testing.T) {
	for index, id := range []string{"canonical-ipv4-v1", "canonical-ipv6-v1"} {
		req := timedFixtureRequest(t, id)
		want := readGolden(t, map[string]string{
			"canonical-ipv4-v1": "timed-ipv4-v1.bin",
			"canonical-ipv6-v1": "timed-ipv6-v1.bin",
		}[id])
		packet := bytes.Repeat([]byte{0xa5}, len(want))
		n, err := (Writer{}).Write(packet, req)
		if err != nil || n != len(want) || !bytes.Equal(packet, want) {
			t.Fatalf("timed materialized %s write=(%d,%v), length=%d/%d parity=%v", id, n, err, len(packet), len(want), bytes.Equal(packet, want))
		}
		if got := binary.BigEndian.Uint32(packet[4:8]); got != 5000 {
			t.Fatalf("timed %s header sysUptime=%d, want 5000", id, got)
		}
		shape, ok := wire.BuiltinV9Timed().ShapeAt(index)
		if !ok {
			t.Fatalf("timed shape %d missing", index)
		}
		legacy, _ := wire.BuiltinV9().ShapeAt(index)
		data := 20 + int(shape.TemplateBytes())
		recordOffset := data + 4
		timeOffset := recordOffset + int(legacy.RecordLength())
		if got := binary.BigEndian.Uint32(packet[timeOffset : timeOffset+4]); got != 3000 {
			t.Fatalf("timed %s FIRST_SWITCHED=%d, want 3000", id, got)
		}
		if got := binary.BigEndian.Uint32(packet[timeOffset+4 : timeOffset+8]); got != 4000 {
			t.Fatalf("timed %s LAST_SWITCHED=%d, want 4000", id, got)
		}
	}
}

func TestTimedProfileStreamingBytes(t *testing.T) {
	for _, id := range []string{"canonical-ipv4-v1", "canonical-ipv6-v1"} {
		t.Run(id, func(t *testing.T) {
			base := timedFixtureRequest(t, id)
			golden := readGolden(t, map[string]string{
				"canonical-ipv4-v1": "timed-ipv4-v1.bin",
				"canonical-ipv6-v1": "timed-ipv6-v1.bin",
			}[id])
			const templateBytes = 88
			want := make([]byte, len(golden)-templateBytes)
			copy(want[:headerLength], golden[:headerLength])
			copy(want[headerLength:], golden[headerLength+templateBytes:])
			binary.BigEndian.PutUint16(want[2:4], 1)
			base.Header.Count = 0
			packet := bytes.Repeat([]byte{0x5a}, len(want))
			appender := (Writer{}).NewDataPacket()
			if err := appender.Begin(packet, wire.DataPacketRequest{Header: base.Header, Shape: base.Shape, MaxDatagramBytes: 464}); err != nil {
				t.Fatalf("timed stream begin: %v", err)
			}
			if err := appender.Append(base.Records[0]); err != nil {
				t.Fatalf("timed stream append: %v", err)
			}
			n, err := appender.Finish()
			if err != nil || n != len(want) || !bytes.Equal(packet, want) {
				t.Fatalf("timed stream finish=(%d,%v), length=%d/%d parity=%v", n, err, len(packet), len(want), bytes.Equal(packet, want))
			}
		})
	}
}

func TestTimedProfileGoldenFiles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length int
		id     string
	}{
		{name: "timed-ipv4-v1.bin", length: 164, id: "canonical-ipv4-v1"},
		{name: "timed-ipv6-v1.bin", length: 188, id: "canonical-ipv6-v1"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			req := timedFixtureRequest(t, tc.id)
			got := make([]byte, tc.length)
			n, err := (Writer{}).Write(got, req)
			if err != nil || n != tc.length {
				t.Fatalf("timed golden write=(%d,%v), want (%d,nil)", n, err, tc.length)
			}
			want := readGolden(t, tc.name)
			if len(want) != tc.length || !bytes.Equal(got, want) {
				t.Fatalf("timed golden mismatch length=%d/%d sha256=%x", len(want), tc.length, sha256.Sum256(got))
			}
		})
	}
}

func timedFixtureRequest(t *testing.T, id string) wire.PacketRequest {
	t.Helper()
	base := fixtureRequest(t, id)
	shapeIndex := 0
	if id == "canonical-ipv6-v1" {
		shapeIndex = 1
	}
	shape, ok := wire.BuiltinV9Timed().ShapeAt(shapeIndex)
	if !ok {
		t.Fatalf("timed shape %d missing", shapeIndex)
	}
	values := append([]wire.Value(nil), base.Records[0].Values()...)
	values = append(values, wire.UnixNanosValue(timedOrigin+3_000_000_000), wire.UnixNanosValue(timedOrigin+4_000_000_000))
	record, err := wire.NewWireRecord(shape.Family(), values)
	if err != nil {
		t.Fatalf("timed fixture record: %v", err)
	}
	base.Shape = shape
	base.Records = []wire.WireRecord{record}
	base.Header.Count = 2
	base.Header.ExportTimeUnixNanos = timedOrigin + 5_000_000_000
	base.Header.UptimeOriginUnixNanos = timedOrigin
	base.Header.HasUptimeOrigin = true
	base.TemplateBytes = shape.TemplateBytes()
	return base
}

func TestTimedProfileRejectsUnrepresentableTimes(t *testing.T) {
	shape, _ := wire.BuiltinV9Timed().ShapeAt(0)
	legacy, _ := wire.BuiltinV9().ShapeAt(0)
	values := make([]wire.Value, shape.FieldCount())
	for i := 0; i < legacy.FieldCount(); i++ {
		values[i], _ = structuralValue(legacy, i, wire.FamilyIPv4)
	}
	values[18] = wire.UnixNanosValue(timedOrigin + 3_000_000_000)
	values[19] = wire.UnixNanosValue(timedOrigin + 4_000_000_000)
	record, err := wire.NewWireRecord(wire.FamilyIPv4, values)
	if err != nil {
		t.Fatal(err)
	}
	base := wire.PacketRequest{Header: wire.HeaderMetadata{Protocol: wire.ProtocolV9, SourceID: 42, Count: 2, ExportTimeUnixNanos: timedOrigin + 5_000_000_000, UptimeOriginUnixNanos: timedOrigin, HasUptimeOrigin: true}, Shape: shape, Records: []wire.WireRecord{record}, TemplateRecords: 1, TemplateBytes: shape.TemplateBytes()}
	reject := func(name string, mutate func(*wire.PacketRequest)) {
		t.Run(name, func(t *testing.T) {
			req := base
			req.Records = append([]wire.WireRecord(nil), base.Records...)
			mutate(&req)
			packet := bytes.Repeat([]byte{0x5a}, 256)
			before := append([]byte(nil), packet...)
			n, err := (Writer{}).Write(packet, req)
			if n != 0 || err == nil || !bytes.Equal(packet, before) {
				t.Fatalf("rejection=(%d,%v), mutated=%v", n, err, !bytes.Equal(packet, before))
			}
			if !errors.Is(err, wire.ErrInvalidValue) && !errors.Is(err, wire.ErrInvalidHeader) {
				t.Fatalf("unexpected error=%v", err)
			}
		})
	}
	reject("missing-origin", func(req *wire.PacketRequest) { req.Header.HasUptimeOrigin = false })
	reject("pre-origin", func(req *wire.PacketRequest) {
		req.Records[0] = replaceTimedValue(t, req.Records[0], 18, wire.UnixNanosValue(timedOrigin-1_000_000))
	})
	reject("reversed", func(req *wire.PacketRequest) {
		req.Records[0] = replaceTimedValue(t, req.Records[0], 19, wire.UnixNanosValue(timedOrigin+2_000_000_000))
	})
	reject("sub-millisecond", func(req *wire.PacketRequest) {
		req.Records[0] = replaceTimedValue(t, req.Records[0], 18, wire.UnixNanosValue(timedOrigin+3_000_000_001))
	})
	reject("past-header", func(req *wire.PacketRequest) {
		req.Records[0] = replaceTimedValue(t, req.Records[0], 19, wire.UnixNanosValue(timedOrigin+5_001_000_000))
	})
	reject("uptime-exhausted", func(req *wire.PacketRequest) {
		req.Header.ExportTimeUnixNanos = timedOrigin + uint64(math.MaxUint32)*1_000_000
		req.Records[0] = replaceTimedValue(t, req.Records[0], 19, wire.UnixNanosValue(timedOrigin+(uint64(math.MaxUint32)+1)*1_000_000))
	})
}

func structuralValue(shape wire.Shape, index int, family wire.Family) (wire.Value, error) {
	descriptor, _ := shape.DescriptorAt(index)
	switch descriptor.Encoding {
	case wire.EncodingIPv4Address:
		return wire.ParseIPv4Value("192.0.2.1")
	case wire.EncodingIPv6Address:
		return wire.ParseIPv6Value("2001:db8::1")
	case wire.EncodingMACAddress:
		return wire.ParseMACValue("00:11:22:33:44:55")
	default:
		return wire.UintValue(1), nil
	}
}

func replaceTimedValue(t *testing.T, record wire.WireRecord, index int, value wire.Value) wire.WireRecord {
	t.Helper()
	values := record.Values()
	values[index] = value
	replaced, err := wire.NewWireRecord(record.Family(), values)
	if err != nil {
		t.Fatal(err)
	}
	return replaced
}
