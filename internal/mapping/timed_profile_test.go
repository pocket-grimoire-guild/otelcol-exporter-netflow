package mapping

import (
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/normalize"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func timedProfileConfig() Config {
	return Config{
		Profile:               ProfileV9Timed,
		Protocol:              wire.ProtocolV9,
		LossPolicy:            LossPolicyEncodeAndCount,
		ProtocolIdentifiers:   []ProtocolIdentifier{{Token: "tcp", Number: 6}},
		NetworkTypeVersions:   versionMap(),
		HasUptimeOrigin:       true,
		UptimeOriginUnixNanos: 1_788_220_800_000_000_000,
	}
}

func TestV9TimedProfileCatalogAndRuntime(t *testing.T) {
	compiled, err := Compile(timedProfileConfig())
	if err != nil {
		t.Fatalf("compile timed profile: %v", err)
	}
	if compiled.Profile() != ProfileV9Timed || compiled.ShapeCount() != 2 || compiled.MaxDatagramSize() != 464 {
		t.Fatalf("profile=%q shapes=%d payload=%d", compiled.Profile(), compiled.ShapeCount(), compiled.MaxDatagramSize())
	}
	wantIDs := []uint16{1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 34, 52, 60, 22, 21}
	wantWidths := []uint16{4, 4, 1, 1, 1, 2, 4, 1, 2, 2, 4, 1, 2, 4, 4, 4, 1, 1, 4, 4}
	for index, family := range []wire.Family{wire.FamilyIPv4, wire.FamilyIPv6} {
		shape, ok := compiled.Catalog().ShapeAt(index)
		if !ok || shape.Family() != family || shape.ID() != uint16(256+index) || shape.FieldCount() != 20 || shape.RecordLength() != uint64([]int{51, 75}[index]) || shape.TemplateBytes() != 88 {
			t.Fatalf("shape %d = family=%v id=%d fields=%d record=%d template=%d", index, shape.Family(), shape.ID(), shape.FieldCount(), shape.RecordLength(), shape.TemplateBytes())
		}
		for i, descriptor := range shape.Fields() {
			wantID, wantWidth := wantIDs[i], wantWidths[i]
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
		}
	}

	var mapped wire.WireRecord
	err = normalize.NormalizeEach(testpdata.CanonicalLogs(), func(record wire.NormalizedRecord) error {
		mapped, err = compiled.Map(record, nil)
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
	if start.Kind() != wire.ValueUnixNanos || end.Kind() != wire.ValueUnixNanos || start.UnixNanos() != 1_788_220_801_000_000_000 || end.UnixNanos() != 1_788_220_801_001_000_000 {
		t.Fatalf("mapped times=%d/%d kinds=%v/%v", start.UnixNanos(), end.UnixNanos(), start.Kind(), end.Kind())
	}
}

func TestV9TimedProfileRequiresExplicitOrigin(t *testing.T) {
	config := timedProfileConfig()
	config.HasUptimeOrigin = false
	config.UptimeOriginUnixNanos = 0
	if _, err := Compile(config); err == nil {
		t.Fatal("timed profile compiled without uptime origin")
	} else {
		configError, ok := err.(*ConfigError)
		if !ok || configError.Code != ErrCodeProvenance {
			t.Fatalf("missing origin error=%v", err)
		}
	}

	core := config
	core.Profile = ProfileV9
	if _, err := Compile(core); err != nil {
		t.Fatalf("time-free core profile unexpectedly requires origin: %v", err)
	}
}
