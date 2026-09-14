package mapping

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/normalize"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/ipfix"
)

func TestIPFIXFragmentFlagsFamilyAndWireMatrix(t *testing.T) {
	compiled, err := Compile(explicitConfig(wire.ProtocolIPFIX, []FieldSelection{{Canonical: "flow.ip_flags"}}))
	if err != nil {
		t.Fatal(err)
	}

	for _, family := range []wire.Family{wire.FamilyIPv4, wire.FamilyIPv6} {
		for flags := uint64(0); flags < 8; flags++ {
			t.Run(fmt.Sprintf("family=%s/flags=%d", family, flags), func(t *testing.T) {
				record := normalizedFragmentFlagsRecord(t, family, "ipfix", flags)
				mapped, mapErr := compiled.Map(record, nil)
				valid := flags <= 3
				if family == wire.FamilyIPv6 {
					valid = flags <= 1
				}
				if !valid {
					assertFragmentFlagsInvalid(t, mapErr)
					return
				}
				if mapErr != nil {
					t.Fatalf("valid flags map error: %v", mapErr)
				}
				want := [...]uint64{0x00, 0x20, 0x40, 0x60}[flags]
				got, ok := mapped.ValueAt(0)
				if !ok || got != wire.UintValue(want) {
					t.Fatalf("mapped value=%+v/%v want %d", got, ok, want)
				}

				shape, ok := compiled.Catalog().ShapeAt(0)
				if !ok {
					t.Fatal("missing family shape")
				}
				buffer := make([]byte, 21)
				n, writeErr := (ipfix.Writer{}).Write(buffer, wire.PacketRequest{
					Header: wire.HeaderMetadata{Protocol: wire.ProtocolIPFIX, ExportTimeUnixNanos: 1_000_000_000},
					Shape:  shape, Records: []wire.WireRecord{mapped},
				})
				if writeErr != nil || n != len(buffer) {
					t.Fatalf("wire write=(%d,%v), want (21,nil)", n, writeErr)
				}
				wantPacket := []byte{
					0x00, 0x0a, 0x00, 0x15,
					0x00, 0x00, 0x00, 0x01,
					0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x01, 0x00, 0x00, 0x05, byte(want),
				}
				if !bytes.Equal(buffer, wantPacket) {
					t.Fatalf("literal IPFIX packet=%x want %x", buffer, wantPacket)
				}
			})
		}
	}

	t.Run("provenance-remains-protocol-mismatch", func(t *testing.T) {
		// Wrong provenance wins even when the flags are also invalid.
		_, mapErr := compiled.Map(normalizedFragmentFlagsRecord(t, wire.FamilyIPv4, "netflow_v9", 8), nil)
		if !errors.Is(mapErr, ErrProtocolMismatch) {
			t.Fatalf("error=%v want %v", mapErr, ErrProtocolMismatch)
		}
		var runtimeErr *RuntimeError
		if !errors.As(mapErr, &runtimeErr) || runtimeErr.Reason != RuntimeProtocolMismatch || runtimeErr.Ordinal != 0 {
			t.Fatalf("runtime error=%T/%+v want protocol mismatch ordinal 0", mapErr, runtimeErr)
		}
	})

	t.Run("value-above-three-remains-invalid", func(t *testing.T) {
		_, mapErr := compiled.Map(normalizedFragmentFlagsRecord(t, wire.FamilyIPv4, "ipfix", 8), nil)
		assertFragmentFlagsInvalid(t, mapErr)
	})
}

func assertFragmentFlagsInvalid(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("error=%v want %v", err, ErrInvalidValue)
	}
	var runtimeErr *RuntimeError
	if !errors.As(err, &runtimeErr) || runtimeErr.Reason != RuntimeValueInvalid || runtimeErr.Ordinal != 0 {
		t.Fatalf("runtime error=%T/%+v want invalid value ordinal 0", err, runtimeErr)
	}
}

func normalizedFragmentFlagsRecord(t *testing.T, family wire.Family, flowType string, flags uint64) wire.NormalizedRecord {
	t.Helper()
	logs := testpdata.CanonicalIPv4Logs()
	if family == wire.FamilyIPv6 {
		logs = testpdata.CanonicalIPv6Logs()
	}
	attrs := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes()
	attrs.PutStr("flow.type", flowType)
	attrs.PutInt("flow.ip_flags", int64(flags))
	var normalized wire.NormalizedRecord
	if err := normalize.NormalizeEach(logs, func(record wire.NormalizedRecord) error {
		normalized = record
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return normalized
}
