package mapping

import (
	"errors"
	"math"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/normalize"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func generalProfileConfig() Config {
	return Config{
		Profile:             ProfileIPFIXGeneral,
		Protocol:            wire.ProtocolIPFIX,
		LossPolicy:          LossPolicyEncodeAndCount,
		ProtocolIdentifiers: []ProtocolIdentifier{{Token: "tcp", Number: 6}},
		NetworkTypeVersions: []NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}},
	}
}

func TestIPFIXGeneralProfileCatalogAndRuntime(t *testing.T) {
	compiled, err := Compile(generalProfileConfig())
	if err != nil {
		t.Fatalf("compile general profile: %v", err)
	}
	if compiled.Profile() != ProfileIPFIXGeneral || compiled.ShapeCount() != 2 || compiled.MaxDatagramSize() != 464 {
		t.Fatalf("profile=%q shapes=%d payload=%d", compiled.Profile(), compiled.ShapeCount(), compiled.MaxDatagramSize())
	}
	wantIDs := []uint16{1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 34, 52, 60, 152, 153}
	wantWidths := []uint16{8, 8, 1, 1, 2, 2, 4, 1, 4, 2, 4, 1, 4, 4, 4, 4, 1, 1, 8, 8}
	for index, family := range []wire.Family{wire.FamilyIPv4, wire.FamilyIPv6} {
		shape, ok := compiled.Catalog().ShapeAt(index)
		if !ok || shape.Family() != family || shape.ID() != uint16(256+index) || shape.FieldCount() != 20 || shape.RecordLength() != uint64([]int{72, 96}[index]) || shape.TemplateBytes() != 88 {
			t.Fatalf("shape %d = family=%v id=%d fields=%d record=%d template=%d", index, shape.Family(), shape.ID(), shape.FieldCount(), shape.RecordLength(), shape.TemplateBytes())
		}
		for i, descriptor := range shape.Fields() {
			wantID := wantIDs[i]
			wantWidth := wantWidths[i]
			if family == wire.FamilyIPv6 {
				if i == 6 {
					wantID, wantWidth = 27, 16
				}
				if i == 7 {
					wantID = 29
				}
				if i == 10 {
					wantID, wantWidth = 28, 16
				}
				if i == 11 {
					wantID = 30
				}
			}
			if descriptor.ID != wantID || descriptor.Length != wantWidth {
				t.Fatalf("shape %d field %d = id=%d width=%d, want id=%d width=%d", index, i, descriptor.ID, descriptor.Length, wantID, wantWidth)
			}
			if i >= 18 && descriptor.Encoding != wire.EncodingDateTimeMilliseconds {
				t.Fatalf("shape %d time field %d encoding=%v", index, i, descriptor.Encoding)
			}
		}
	}

	var mapped wire.WireRecord
	var stats MappingResult
	err = normalize.NormalizeEach(testpdata.CanonicalLogs(), func(record wire.NormalizedRecord) error {
		stats, err = compiled.MapWithStats(record, nil)
		mapped = stats.Record
		return err
	})
	if err != nil {
		t.Fatalf("map canonical fixture: %v", err)
	}
	if mapped.Family() != wire.FamilyIPv4 || mapped.Len() != 20 {
		t.Fatalf("mapped family/fields=%v/%d", mapped.Family(), mapped.Len())
	}
	start, _ := mapped.ValueAt(18)
	end, _ := mapped.ValueAt(19)
	if start.Kind() != wire.ValueUnixNanos || end.Kind() != wire.ValueUnixNanos || start.UnixNanos() != 1788220801000000000 || end.UnixNanos() != 1788220801001000000 {
		t.Fatalf("mapped times=%d/%d kinds=%v/%v", start.UnixNanos(), end.UnixNanos(), start.Kind(), end.Kind())
	}
	if stats.ExporterLosses != 6 || stats.CanonicalSourceLoss != 2 {
		t.Fatalf("loss stats=%d/%d, want 6/2", stats.ExporterLosses, stats.CanonicalSourceLoss)
	}
}

func TestIPFIXGeneralExplicitMillisecondsAndLegacySelection(t *testing.T) {
	msConfig := Config{Protocol: wire.ProtocolIPFIX, LossPolicy: LossPolicyEncodeAndCount, Fields: []FieldSelection{
		{Canonical: "flow.start", Target: "flow_start_milliseconds"},
		{Canonical: "flow.end", Target: "flow_end_milliseconds"},
	}}
	compiled, err := Compile(msConfig)
	if err != nil {
		t.Fatalf("compile explicit ms times: %v", err)
	}
	shape, _ := compiled.Catalog().ShapeAt(0)
	if got := shape.Fields(); got[0].ID != 152 || got[0].Encoding != wire.EncodingDateTimeMilliseconds || got[1].ID != 153 || got[1].Encoding != wire.EncodingDateTimeMilliseconds {
		t.Fatalf("explicit ms descriptors=%+v", got)
	}
	legacy, err := Compile(Config{Protocol: wire.ProtocolIPFIX, LossPolicy: LossPolicyEncodeAndCount, Fields: []FieldSelection{{Canonical: "flow.start"}, {Canonical: "flow.end"}}})
	if err != nil {
		t.Fatalf("compile explicit legacy times: %v", err)
	}
	legacyShape, _ := legacy.Catalog().ShapeAt(0)
	if got := legacyShape.Fields(); got[0].ID != 156 || got[0].Encoding != wire.EncodingDateTimeNanoseconds || got[1].ID != 157 || got[1].Encoding != wire.EncodingDateTimeNanoseconds {
		t.Fatalf("explicit legacy descriptors=%+v", got)
	}
	conflicting := msConfig
	conflicting.Fields = append(conflicting.Fields, FieldSelection{Canonical: "flow.start"})
	if _, err := Compile(conflicting); err == nil {
		t.Fatal("same canonical time selected with conflicting target")
	}
}

func TestIPFIXGeneralSelectorAndFingerprintBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config Config
	}{
		{
			name: "wrong protocol target",
			config: Config{Protocol: wire.ProtocolV9, LossPolicy: LossPolicyEncodeAndCount, Fields: []FieldSelection{
				{Canonical: "flow.start", Target: "flow_start_milliseconds"},
			}},
		},
		{
			name: "wrong field target",
			config: Config{Protocol: wire.ProtocolIPFIX, LossPolicy: LossPolicyEncodeAndCount, Fields: []FieldSelection{
				{Canonical: "network.type", Target: "flow_start_milliseconds"},
			}},
		},
		{
			name: "general profile wrong protocol",
			config: func() Config {
				c := generalProfileConfig()
				c.Protocol = wire.ProtocolV9
				return c
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Compile(tc.config); err == nil {
				t.Fatal("invalid selector accepted")
			}
		})
	}

	coreConfig := generalProfileConfig()
	coreConfig.Profile = ProfileIPFIX
	core, err := Compile(coreConfig)
	if err != nil {
		t.Fatal(err)
	}
	general, err := Compile(generalProfileConfig())
	if err != nil {
		t.Fatal(err)
	}
	if core.Fingerprint() == general.Fingerprint() {
		t.Fatal("general and core profile fingerprints are identical")
	}
	rebasedConfig := generalProfileConfig()
	rebasedConfig.IDBase = 300
	rebased, err := Compile(rebasedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if rebased.Fingerprint() == general.Fingerprint() {
		t.Fatal("rebased general profile fingerprint is unchanged")
	}
	shape, _ := rebased.Catalog().ShapeAt(0)
	if shape.ID() != 300 {
		t.Fatalf("rebased first template ID=%d, want 300", shape.ID())
	}
}

func TestIPFIXGeneralLossCountsPreserveExactAndSubmillisecond(t *testing.T) {
	compiled, err := Compile(generalProfileConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		start, end int64
	}{
		{"exact", 1_788_220_801_000_000_000, 1_788_220_801_001_000_000},
		{"submillisecond", 1_788_220_801_000_000_123, 1_788_220_801_001_000_456},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := testpdata.CanonicalLogs()
			attrs := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes()
			attrs.PutInt("flow.start", tc.start)
			attrs.PutInt("flow.end", tc.end)
			var result MappingResult
			if err := normalize.NormalizeEach(logs, func(record wire.NormalizedRecord) error {
				result, err = compiled.MapWithStats(record, nil)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if result.ExporterLosses != 6 || result.CanonicalSourceLoss != 2 {
				t.Fatalf("loss stats=%d/%d, want 6/2", result.ExporterLosses, result.CanonicalSourceLoss)
			}
		})
	}
}

func TestIPFIXGeneralTimeBoundaries(t *testing.T) {
	config := Config{Protocol: wire.ProtocolIPFIX, LossPolicy: LossPolicyEncodeAndCount, Fields: []FieldSelection{
		{Canonical: "flow.start", Target: "flow_start_milliseconds"},
		{Canonical: "flow.end", Target: "flow_end_milliseconds"},
	}}
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	mapTimes := func(start, end uint64) (wire.WireRecord, error) {
		record, err := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{
			{Field: wire.FieldFlowStart, Value: wire.UnixNanosValue(start)},
			{Field: wire.FieldFlowEnd, Value: wire.UnixNanosValue(end)},
		})
		if err != nil {
			return wire.WireRecord{}, err
		}
		return compiled.Map(record, nil)
	}
	for _, tc := range []struct {
		name       string
		start, end uint64
		valid      bool
	}{
		{name: "exact milliseconds", start: 1_788_220_800_123_000_000, end: 1_788_220_801_123_000_000, valid: true},
		{name: "submillisecond collapse", start: 1_788_220_800_123_456_789, end: 1_788_220_800_123_456_790, valid: true},
		{name: "ordering before floor", start: 1_788_220_800_123_456_790, end: 1_788_220_800_123_456_789},
		{name: "zero", start: 0, end: 0, valid: true},
		{name: "signed safe maximum", start: math.MaxInt64, end: math.MaxInt64, valid: true},
		{name: "2036 boundary", start: maxIPFIXUnixNanos - 999_999_999, end: maxIPFIXUnixNanos, valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record, mapErr := mapTimes(tc.start, tc.end)
			if (mapErr == nil) != tc.valid {
				t.Fatalf("map=(%+v,%v), valid=%v", record, mapErr, tc.valid)
			}
			if tc.valid {
				start, _ := record.ValueAt(0)
				end, _ := record.ValueAt(1)
				if start.UnixNanos() != tc.start || end.UnixNanos() != tc.end {
					t.Fatalf("mapper floored source values=%d/%d", start.UnixNanos(), end.UnixNanos())
				}
			}
		})
	}
	if _, err := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldFlowStart, Value: wire.IntValue(-1)}}); !errors.Is(err, wire.ErrInvalidValue) {
		t.Fatalf("negative time accepted: %v", err)
	}
	if _, err := wire.NewRecord(wire.FamilyIPv4, []wire.FieldValue{{Field: wire.FieldFlowStart, Value: wire.StringValue("1788220800123")}}); !errors.Is(err, wire.ErrInvalidValue) {
		t.Fatalf("wrong time type accepted: %v", err)
	}
}
