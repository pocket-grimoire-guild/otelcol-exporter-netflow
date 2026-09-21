package destination

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/normalize"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/ipfix"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow5"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow9"
	"go.opentelemetry.io/collector/pdata/plog"
)

func boundedPackerContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func packerState(t *testing.T) *State {
	return packerV5State(t, 1, 464)
}

func packerV5State(t *testing.T, maxRecords uint16, maxDatagram uint64) *State {
	t.Helper()
	compiled := compiledMapping(t, wire.ProtocolV5)
	config := DefaultConfig(wire.ProtocolV5)
	config.HasUptimeOrigin = true
	config.UptimeOriginUnixNanos = 0
	config.MaxRecordsPerMessage = maxRecords
	config.MaxDatagramSize = maxDatagram
	state, err := NewState(compiled, netflow5.Writer{}, config)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func appendPackerCopies(t *testing.T, logs plog.Logs, count int) plog.Logs {
	t.Helper()
	if count < 1 {
		t.Fatal("count must be positive")
	}
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	base := records.At(0)
	for i := 1; i < count; i++ {
		base.CopyTo(records.AppendEmpty())
	}
	return logs
}

func shapeSwitchState(t *testing.T, refreshCount uint32) *State {
	t.Helper()
	config := mapping.Config{
		Protocol:        wire.ProtocolV9,
		Fields:          []mapping.FieldSelection{{Canonical: "source.address"}},
		LossPolicy:      mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize: 65507,
		PathMTU:         65535,
		Endpoint:        "192.0.2.1:4739",
	}
	compiled, err := mapping.Compile(config)
	if err != nil {
		t.Fatalf("compile shape switch: %v", err)
	}
	stateConfig := DefaultConfig(wire.ProtocolV9)
	stateConfig.SourceID, stateConfig.ObservationDomainID = 42, 42
	stateConfig.V9RefreshPacketCount = refreshCount
	state, err := NewState(compiled, netflow9.Writer{}, stateConfig)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, state, 3_000_000_000, 1)
	return state
}

func customPackerState(t *testing.T, variable bool, maxDatagram uint64, refreshCount uint32, maxRecords ...uint16) *State {
	t.Helper()
	pen, element := uint32(32473), uint32(100)
	entry := mapping.CustomField{Source: "vendor.value", PEN: &pen, ElementID: &element, Encoding: "unsigned8"}
	if variable {
		isVariable := true
		maxLength := uint32(4096)
		entry.Encoding = "string"
		entry.Variable = &isVariable
		entry.MaxLength = &maxLength
	} else {
		fixedLength := uint16(1)
		entry.FixedLength = &fixedLength
	}
	config := mapping.Config{
		Protocol:        wire.ProtocolIPFIX,
		Fields:          []mapping.FieldSelection{{Canonical: "source.port"}},
		LossPolicy:      mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize: 65507,
		PathMTU:         65535,
		Endpoint:        "192.0.2.1:4739",
		Custom:          []mapping.CustomField{entry},
	}
	compiled, err := mapping.Compile(config)
	if err != nil {
		t.Fatalf("compile custom: %v", err)
	}
	stateConfig := DefaultConfig(wire.ProtocolIPFIX)
	stateConfig.ObservationDomainID = 42
	stateConfig.MaxDatagramSize = maxDatagram
	stateConfig.IPFIXDataMessageRefreshCount = refreshCount
	if len(maxRecords) != 0 {
		stateConfig.MaxRecordsPerMessage = maxRecords[0]
	}
	state, err := NewState(compiled, ipfix.Writer{}, stateConfig)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, state, 3_000_000_000, 1)
	return state
}

func validPackerLogs(t *testing.T) plog.Logs {
	t.Helper()
	logs := testpdata.CanonicalLogs()
	record := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	for _, key := range []string{"flow.time_received", "flow.start", "flow.end"} {
		record.Attributes().PutInt(key, 3_000_000_000)
	}
	return logs
}

func assertPackerRejectionCounts(t *testing.T, result *PackResult, want RejectionCounts) {
	t.Helper()
	if got := result.RejectionCounts(); got != want {
		t.Fatalf("rejection reasons = %v, want %v", got, want)
	}
	if got := rejectionReasonTotal(result.RejectionCounts()); got != result.Counts().Invalid {
		t.Fatalf("reason total = %d, invalid = %d", got, result.Counts().Invalid)
	}
}

func TestPackerAdmissionAndInternalFailuresHaveNoRejectionReasons(t *testing.T) {
	packer, err := NewPacker(packerState(t), PackerConfig{
		Write: func(context.Context, []byte) (int, error) {
			t.Fatal("failed admission reached transport")
			return 0, nil
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		packer *Packer
		ctx    context.Context
		logs   plog.Logs
		want   error
	}{
		{"nil-packer", nil, boundedPackerContext(t), validPackerLogs(t), ErrPackInternal},
		{"nil-context", packer, nil, validPackerLogs(t), ErrPackInternal},
		// Zero pdata is a private malformed-input probe, not a source record.
		{"malformed-pdata", packer, boundedPackerContext(t), plog.Logs{}, ErrPackAdmission},
		{"empty-request", packer, boundedPackerContext(t), plog.NewLogs(), ErrPackPermanent},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.packer.Pack(test.ctx, test.logs, nil)
			if !errors.Is(err, test.want) {
				t.Fatalf("Pack() error = %v, want %v", err, test.want)
			}
			if result.Counts() != (SourceLedgerCounts{}) {
				t.Fatalf("admission failure covered source records: %+v", result.Counts())
			}
			assertPackerRejectionCounts(t, result, RejectionCounts{})
		})
	}
}

func TestPackerStreamsAndConfirmsSource(t *testing.T) {
	state := packerState(t)
	logs := validPackerLogs(t)
	writes := 0
	var packet []byte
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) {
			writes++
			packet = append(packet[:0], datagram...)
			if len(datagram) != 72 {
				t.Fatalf("datagram length = %d, want 72", len(datagram))
			}
			return len(datagram), nil
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(context.Background(), logs, nil)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	if result.Outcome() != PackSucceeded || result.Classification(0) != SourceConfirmed {
		t.Fatalf("result = outcome %d class %d", result.Outcome(), result.Classification(0))
	}
	if got := result.Counts(); got.Covered != 1 || got.Valid != 1 || got.Confirmed != 1 || got.Unsent != 0 {
		t.Fatalf("counts = %+v", got)
	}
	assertPackerRejectionCounts(t, result, RejectionCounts{})
	if writes != 1 || state.Sequence() != 1 {
		t.Fatalf("writes/sequence = %d/%d, want 1/1", writes, state.Sequence())
	}
	if got := binary.BigEndian.Uint16(packet[0:2]); got != 5 {
		t.Fatalf("version = %d, want 5", got)
	}
	if got := binary.BigEndian.Uint16(packet[2:4]); got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint32(packet[4:8]); got != 4000 {
		t.Fatalf("sysUptime = %d, want 4000", got)
	}
	if got := binary.BigEndian.Uint32(packet[8:12]); got != 4 {
		t.Fatalf("seconds = %d, want 4", got)
	}
	if got := binary.BigEndian.Uint32(packet[12:16]); got != 0 || binary.BigEndian.Uint32(packet[16:20]) != 0 {
		t.Fatalf("timestamp/sequence bytes = %x, want zero nanos and sequence", packet[12:20])
	}
	if got := binary.BigEndian.Uint16(packet[22:24]); got != 1000 {
		t.Fatalf("sampling = %d, want 1000", got)
	}
	if !bytes.Equal(packet[24:28], []byte{192, 0, 2, 1}) || !bytes.Equal(packet[28:32], []byte{198, 51, 100, 2}) || !bytes.Equal(packet[32:36], []byte{192, 0, 2, 254}) {
		t.Fatalf("address bytes = %x, want canonical IPv4 values", packet[24:36])
	}
	if got := binary.BigEndian.Uint16(packet[56:58]); got != 12345 {
		t.Fatalf("source port = %d, want 12345", got)
	}
	if got := binary.BigEndian.Uint16(packet[58:60]); got != 443 {
		t.Fatalf("destination port = %d, want 443", got)
	}
	if got := binary.BigEndian.Uint32(packet[40:44]); got != 1234 || binary.BigEndian.Uint32(packet[44:48]) != 56789 {
		t.Fatalf("packet/octet counters = %x, want 1234/56789", packet[40:48])
	}
	if got := binary.BigEndian.Uint32(packet[48:52]); got != 3000 || binary.BigEndian.Uint32(packet[52:56]) != 3000 {
		t.Fatalf("flow times = %x, want 3000/3000", packet[48:56])
	}
}

func TestPackerContinuesInvalidSources(t *testing.T) {
	state := packerState(t)
	logs := validPackerLogs(t)
	base := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	second := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().AppendEmpty()
	base.CopyTo(second)
	second.Attributes().Remove("source.address")
	writes := 0
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) { writes++; return len(datagram), nil },
		Clock: func() (uint64, uint64) { return 4_000_000_000, 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(context.Background(), logs, nil)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	if result.Classification(0) != SourceConfirmed || result.Classification(1) != SourceInvalid {
		t.Fatalf("classes = %d/%d", result.Classification(0), result.Classification(1))
	}
	if got := result.Counts(); got.Valid != 1 || got.Invalid != 1 || got.Confirmed != 1 {
		t.Fatalf("counts = %+v", got)
	}
	wantReasons := RejectionCounts{}
	wantReasons[RejectionMissingField] = 1
	assertPackerRejectionCounts(t, result, wantReasons)
	if writes != 1 {
		t.Fatalf("writes = %d, want 1", writes)
	}
}

func TestPackerAmbiguousWriteStopsAndValidatesSuffix(t *testing.T) {
	state := packerState(t)
	logs := validPackerLogs(t)
	base := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	second := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().AppendEmpty()
	base.CopyTo(second)
	second.Attributes().Remove("source.address")
	third := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().AppendEmpty()
	base.CopyTo(third)
	writes := 0
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) {
			writes++
			return len(datagram) - 1, errors.New("transport detail must not escape")
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(context.Background(), logs, nil)
	if !errors.Is(err, ErrPackTransient) {
		t.Fatalf("Pack() error = %v, want transient", err)
	}
	if result.Classification(0) != SourceAmbiguous || result.Classification(1) != SourceInvalid || result.Classification(2) != SourceUnsentValid {
		t.Fatalf("classes = %d/%d/%d", result.Classification(0), result.Classification(1), result.Classification(2))
	}
	if writes != 1 || state.Sequence() != 0 {
		t.Fatalf("writes/sequence = %d/%d, want 1/0", writes, state.Sequence())
	}
	wantReasons := RejectionCounts{}
	wantReasons[RejectionMissingField] = 1
	assertPackerRejectionCounts(t, result, wantReasons)
}

func TestPackerRejectsUnbootstrappedAndEmpty(t *testing.T) {
	compiled := compiledMapping(t, wire.ProtocolV9)
	config := DefaultConfig(wire.ProtocolV9)
	config.SourceID, config.ObservationDomainID = 42, 42
	state, err := NewState(compiled, netflow5.Writer{}, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPacker(state, PackerConfig{Write: func(context.Context, []byte) (int, error) { return 0, nil }, Clock: func() (uint64, uint64) { return 1, 1 }}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("unbootstrapped NewPacker() error = %v", err)
	}

	state = packerState(t)
	packer, err := NewPacker(state, PackerConfig{Write: func(context.Context, []byte) (int, error) { return 0, nil }, Clock: func() (uint64, uint64) { return 1, 1 }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(context.Background(), plog.NewLogs(), nil)
	if !errors.Is(err, ErrPackPermanent) || result.Outcome() != PackPermanent {
		t.Fatalf("empty result = (%d,%v), want permanent", result.Outcome(), err)
	}
	if result.Counts().Covered != 0 {
		t.Fatalf("empty ledger covered = %d, want zero", result.Counts().Covered)
	}
	assertPackerRejectionCounts(t, result, RejectionCounts{})
}

func TestPackerStreamsV9AndIPFIX(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		t.Run(protocol.String(), func(t *testing.T) {
			compiled := tinyCompiledMapping(t, protocol)
			config := DefaultConfig(protocol)
			if protocol == wire.ProtocolV9 {
				config.SourceID, config.ObservationDomainID = 42, 42
			}
			if protocol == wire.ProtocolIPFIX {
				config.ObservationDomainID = 42
			}
			var writer wire.ContractWriter
			switch protocol {
			case wire.ProtocolV9:
				writer = netflow9.Writer{}
			case wire.ProtocolIPFIX:
				writer = ipfix.Writer{}
			}
			state, err := NewState(compiled, writer, config)
			if err != nil {
				t.Fatal(err)
			}
			bootstrap(t, state, 3_000_000_000, 1)
			writes := 0
			packer, err := NewPacker(state, PackerConfig{
				Write: func(_ context.Context, datagram []byte) (int, error) { writes++; return len(datagram), nil },
				Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := packer.Pack(context.Background(), testpdata.CanonicalLogs(), nil)
			if err != nil || result.Classification(0) != SourceConfirmed {
				t.Fatalf("Pack() = (%d,%v), class=%d", result.Outcome(), err, result.Classification(0))
			}
			if writes != 1 {
				t.Fatalf("data writes = %d, want 1", writes)
			}
			assertPackerRejectionCounts(t, result, RejectionCounts{})
		})
	}
}

func TestPackerDrainsDueRefreshBeforeData(t *testing.T) {
	compiled := tinyCompiledMapping(t, wire.ProtocolV9)
	config := DefaultConfig(wire.ProtocolV9)
	config.SourceID, config.ObservationDomainID = 42, 42
	config.V9RefreshPacketCount = 1
	state, err := NewState(compiled, netflow9.Writer{}, config)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, state, 3_000_000_000, 1)
	writes := 0
	clocks := 0
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) { writes++; return len(datagram), nil },
		Clock: func() (uint64, uint64) { clocks++; return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := packer.Pack(context.Background(), testpdata.CanonicalLogs(), nil)
	if err != nil {
		t.Fatal(err)
	}
	assertPackerRejectionCounts(t, first, RejectionCounts{})
	if writes != 1 || !state.Progress().RefreshDue {
		t.Fatalf("first pack writes/progress = %d/%+v", writes, state.Progress())
	}
	result, err := packer.Pack(context.Background(), testpdata.CanonicalLogs(), nil)
	if err != nil || result.Classification(0) != SourceConfirmed {
		t.Fatalf("second Pack() = (%d,%v), class=%d", result.Outcome(), err, result.Classification(0))
	}
	if writes != 3 || clocks != 3 || state.Sequence() != 5 || state.Progress().RefreshActive {
		t.Fatalf("refresh writes/clocks/progress = %d/%d/%+v", writes, clocks, state.Progress())
	}
	assertPackerRejectionCounts(t, result, RejectionCounts{})
}

func TestPackerRefreshFailureLeavesValidatedSuffix(t *testing.T) {
	compiled := tinyCompiledMapping(t, wire.ProtocolV9)
	config := DefaultConfig(wire.ProtocolV9)
	config.SourceID, config.ObservationDomainID = 42, 42
	config.V9RefreshPacketCount = 1
	state, err := NewState(compiled, netflow9.Writer{}, config)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, state, 3_000_000_000, 1)
	writes := 0
	fail := false
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) {
			writes++
			if fail {
				return len(datagram) - 1, errors.New("refresh handoff detail must not escape")
			}
			return len(datagram), nil
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := packer.Pack(context.Background(), testpdata.CanonicalLogs(), nil)
	if err != nil {
		t.Fatal(err)
	}
	assertPackerRejectionCounts(t, first, RejectionCounts{})
	sequence := state.Sequence()
	fail = true
	logs := testpdata.CanonicalLogs()
	base := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	invalid := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().AppendEmpty()
	base.CopyTo(invalid)
	invalid.Attributes().Remove("source.port")
	result, err := packer.Pack(context.Background(), logs, nil)
	if !errors.Is(err, ErrPackTransient) {
		t.Fatalf("refresh failure error = %v, want transient", err)
	}
	if result.Classification(0) != SourceUnsentValid || result.Classification(1) != SourceInvalid {
		t.Fatalf("suffix classes = %d/%d, want unsent/invalid", result.Classification(0), result.Classification(1))
	}
	if writes != 2 || state.Sequence() != sequence || !state.Progress().RefreshDue {
		t.Fatalf("refresh failure writes/sequence/progress = %d/%d/%+v", writes, state.Sequence(), state.Progress())
	}
	wantReasons := RejectionCounts{}
	wantReasons[RejectionMissingField] = 1
	assertPackerRejectionCounts(t, result, wantReasons)
}

func TestPackerLookupIsRequestLocalAndResultsOwnLedgers(t *testing.T) {
	state := customPackerState(t, false, 464, 0)
	logs := appendPackerCopies(t, testpdata.CanonicalLogs(), 2)
	var packets [][]byte
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) {
			packets = append(packets, append([]byte(nil), datagram...))
			return len(datagram), nil
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	var firstOrdinals []uint64
	result1, err := packer.Pack(context.Background(), logs, func(ordinal uint64, source string) (wire.Value, bool) {
		firstOrdinals = append(firstOrdinals, ordinal)
		if source != "vendor.value" {
			t.Fatalf("lookup source = %q", source)
		}
		return wire.UintValue(7 + uint64(ordinal)), true
	})
	if err != nil || result1.Classification(0) != SourceConfirmed || result1.Classification(1) != SourceConfirmed {
		t.Fatalf("first Pack() = (%d,%v), classes=%d/%d", result1.Outcome(), err, result1.Classification(0), result1.Classification(1))
	}
	shape, _ := state.Catalog().ShapeAt(0)
	customOffset := uint64(0)
	for index := 0; index < shape.FieldCount(); index++ {
		descriptor, _ := shape.DescriptorAt(index)
		if descriptor.Custom {
			break
		}
		customOffset += uint64(descriptor.Length)
	}
	firstCustom := 20 + customOffset
	secondCustom := firstCustom + shape.RecordLength()
	if packets[0][firstCustom] != 7 || packets[0][secondCustom] != 8 {
		t.Fatalf("first custom values = %d/%d, want 7/8", packets[0][firstCustom], packets[0][secondCustom])
	}
	var secondOrdinals []uint64
	result2, err := packer.Pack(context.Background(), testpdata.CanonicalLogs(), func(ordinal uint64, source string) (wire.Value, bool) {
		secondOrdinals = append(secondOrdinals, ordinal)
		if source != "vendor.value" {
			t.Fatalf("second lookup source = %q", source)
		}
		return wire.UintValue(100 + uint64(ordinal)), true
	})
	if err != nil || result2.Classification(0) != SourceConfirmed {
		t.Fatalf("second Pack() = (%d,%v), class=%d", result2.Outcome(), err, result2.Classification(0))
	}
	if len(firstOrdinals) != 2 || firstOrdinals[0] != 0 || firstOrdinals[1] != 1 || len(secondOrdinals) != 1 || secondOrdinals[0] != 0 {
		t.Fatalf("lookup ordinals = %v/%v", firstOrdinals, secondOrdinals)
	}
	if packets[1][firstCustom] != 100 {
		t.Fatalf("second custom value = %d, want 100", packets[1][firstCustom])
	}
	if got := result1.Counts(); got.Covered != 2 || got.Confirmed != 2 {
		t.Fatalf("first result changed after reuse: %+v", got)
	}
	if got := result2.Counts(); got.Covered != 1 || got.Confirmed != 1 {
		t.Fatalf("second result counts = %+v", got)
	}
	assertPackerRejectionCounts(t, result1, RejectionCounts{})
	assertPackerRejectionCounts(t, result2, RejectionCounts{})
}

func TestPackerSwitchesFamilyShapesWithRealV9Packets(t *testing.T) {
	state := shapeSwitchState(t, 1000)
	logs := testpdata.CanonicalLogs()
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	testpdata.CanonicalIPv6Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).CopyTo(records.AppendEmpty())
	var packets [][]byte
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) {
			packets = append(packets, append([]byte(nil), datagram...))
			return len(datagram), nil
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(context.Background(), logs, nil)
	if err != nil || result.Classification(0) != SourceConfirmed || result.Classification(1) != SourceConfirmed {
		t.Fatalf("Pack() = (%d,%v), classes=%d/%d", result.Outcome(), err, result.Classification(0), result.Classification(1))
	}
	if len(packets) != 2 || binary.BigEndian.Uint16(packets[0]) != 9 || binary.BigEndian.Uint16(packets[1]) != 9 {
		t.Fatalf("packets = %d or versions = %x/%x", len(packets), packets[0][:2], packets[1][:2])
	}
	assertPackerRejectionCounts(t, result, RejectionCounts{})
	shape0, _ := state.Catalog().ShapeAt(0)
	shape1, _ := state.Catalog().ShapeAt(1)
	if got := binary.BigEndian.Uint16(packets[0][20:22]); got != shape0.ID() {
		t.Fatalf("IPv4 data set ID = %d, want %d", got, shape0.ID())
	}
	if got := binary.BigEndian.Uint16(packets[1][20:22]); got != shape1.ID() {
		t.Fatalf("IPv6 data set ID = %d, want %d", got, shape1.ID())
	}
}

// TestPackerNoMatchingFamilyShapeReason injects an inconsistent destination
// catalog after bootstrap so shapeIndex reaches its no-family-match branch.
// Valid public mappings reject this mismatch earlier in the mapper.
func TestPackerNoMatchingFamilyShapeReason(t *testing.T) {
	state := shapeSwitchState(t, 1000)
	ipv6, ok := state.Catalog().wire.ShapeAt(1)
	if !ok {
		t.Fatal("IPv6 shape missing")
	}
	onlyIPv6, err := wire.NewCatalog(wire.CatalogSpec{
		Protocol: wire.ProtocolV9,
		IDBase:   uint32(ipv6.ID()),
		Shapes: []wire.ShapeSpec{{
			Protocol: wire.ProtocolV9, Family: ipv6.Family(), ID: uint32(ipv6.ID()),
			Fields: ipv6.Fields(), RecordLength: ipv6.RecordLength(), TemplateBytes: ipv6.TemplateBytes(),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	destinationCatalog, err := NewCatalogFromWire(onlyIPv6)
	if err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	state.catalog = destinationCatalog
	state.mu.Unlock()
	packer, err := NewPacker(state, PackerConfig{
		Write: func(context.Context, []byte) (int, error) {
			t.Fatal("shape mismatch reached transport")
			return 0, nil
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(boundedPackerContext(t), validPackerLogs(t), nil)
	if !errors.Is(err, ErrPackPermanent) || result.Classification(0) != SourceInvalid {
		t.Fatalf("shape mismatch = (%d,%v,%v)", result.Outcome(), err, result.Classification(0))
	}
	want := RejectionCounts{}
	want[RejectionFamilyMismatch] = 1
	assertPackerRejectionCounts(t, result, want)
}

func TestPackerFlushesV5SamplingChanges(t *testing.T) {
	state := packerV5State(t, 30, 464)
	logs := appendPackerCopies(t, validPackerLogs(t), 2)
	logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(1).Attributes().PutInt("flow.sampling_rate", 2000)
	var packets [][]byte
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) {
			packets = append(packets, append([]byte(nil), datagram...))
			return len(datagram), nil
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(context.Background(), logs, nil)
	if err != nil || result.Outcome() != PackSucceeded || len(packets) != 2 {
		t.Fatalf("Pack() = (%d,%v), packets=%d", result.Outcome(), err, len(packets))
	}
	if binary.BigEndian.Uint16(packets[0][22:24]) != 1000 || binary.BigEndian.Uint16(packets[1][22:24]) != 2000 {
		t.Fatalf("sampling headers = %d/%d", binary.BigEndian.Uint16(packets[0][22:24]), binary.BigEndian.Uint16(packets[1][22:24]))
	}
	assertPackerRejectionCounts(t, result, RejectionCounts{})
}

func TestPackerV5SamplingRejectionReason(t *testing.T) {
	state := packerV5State(t, 30, 464)
	logs := validPackerLogs(t)
	logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutInt("flow.sampling_rate", 16384)
	writes := 0
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) { writes++; return len(datagram), nil },
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(boundedPackerContext(t), logs, nil)
	if !errors.Is(err, ErrPackPermanent) || result.Classification(0) != SourceInvalid || writes != 0 {
		t.Fatalf("sampling rejection = (%d,%v,%d), writes=%d", result.Outcome(), err, result.Classification(0), writes)
	}
	want := RejectionCounts{}
	want[RejectionInvalidValue] = 1
	assertPackerRejectionCounts(t, result, want)
}

func TestPackerMappingLossesRetainedWhenMappedRecordIsRejected(t *testing.T) {
	state := packerV5State(t, 30, 464)
	logs := validPackerLogs(t)
	normalized := wire.NormalizedRecord{}
	if err := normalize.NormalizeEachIndexed(logs, func(_ uint64, record wire.NormalizedRecord, recordErr error) error {
		if recordErr != nil {
			return recordErr
		}
		normalized = record
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	expected, err := state.Mapping().MapWithStats(normalized, nil)
	if err != nil {
		t.Fatal(err)
	}
	logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutInt("flow.sampling_rate", 16384)
	packer, err := NewPacker(state, PackerConfig{
		Write: func(context.Context, []byte) (int, error) {
			t.Fatal("sampling rejection reached transport")
			return 0, nil
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(boundedPackerContext(t), logs, nil)
	if !errors.Is(err, ErrPackPermanent) {
		t.Fatalf("Pack() error = %v, want permanent", err)
	}
	if result.ExporterLosses() != uint64(expected.ExporterLosses) || result.CanonicalSourceLoss() != uint64(expected.CanonicalSourceLoss) {
		t.Fatalf("loss counters = %d/%d, want %d/%d", result.ExporterLosses(), result.CanonicalSourceLoss(), expected.ExporterLosses, expected.CanonicalSourceLoss)
	}
	want := RejectionCounts{}
	want[RejectionInvalidValue] = 1
	assertPackerRejectionCounts(t, result, want)
}

type rejectingDataWriter struct{ appendErr error }

func (w rejectingDataWriter) Write(dst []byte, request wire.PacketRequest) (int, error) {
	return (netflow5.Writer{}).Write(dst, request)
}

func (w rejectingDataWriter) NewDataPacket() wire.DataPacketAppender {
	return &rejectingDataAppender{inner: (netflow5.Writer{}).NewDataPacket(), appendErr: w.appendErr, reject: true}
}

type suffixRejectWriter struct {
	created   *int
	appendErr error
	base      wire.ContractWriter
	stream    wire.StreamingWriter
}

func (w suffixRejectWriter) Write(dst []byte, request wire.PacketRequest) (int, error) {
	return w.base.Write(dst, request)
}

func (w suffixRejectWriter) NewDataPacket() wire.DataPacketAppender {
	(*w.created)++
	return &rejectingDataAppender{
		inner: w.stream.NewDataPacket(), appendErr: w.appendErr, reject: *w.created > 1,
	}
}

type rejectingDataAppender struct {
	inner     wire.DataPacketAppender
	appendErr error
	reject    bool
	rejected  bool
}

func (a *rejectingDataAppender) Begin(dst []byte, request wire.DataPacketRequest) error {
	return a.inner.Begin(dst, request)
}

func (a *rejectingDataAppender) Append(record wire.WireRecord) error {
	if a.reject && !a.rejected {
		a.rejected = true
		return a.appendErr
	}
	return a.inner.Append(record)
}

func (a *rejectingDataAppender) Finish() (int, error) { return a.inner.Finish() }
func (a *rejectingDataAppender) Reset()               { a.inner.Reset(); a.rejected = false }

// TestPackerTerminalAppendRejectionReasons injects trusted wire sentinels at
// the private writer seam; it does not claim public reachability of each cause.
func TestPackerTerminalAppendRejectionReasons(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want RejectionReason
	}{
		{"value", wire.ErrInvalidValue, RejectionRecordInvalid},
		{"family", wire.ErrInvalidFamily, RejectionFamilyMismatch},
		{"bounds", wire.ErrBounds, RejectionRecordTooLarge},
		{"short-buffer", wire.ErrShortBuffer, RejectionRecordTooLarge},
		{"value-limit", wire.ErrRecordValueLimit, RejectionRecordTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compiled := compiledMapping(t, wire.ProtocolV5)
			config := DefaultConfig(wire.ProtocolV5)
			config.HasUptimeOrigin = true
			config.UptimeOriginUnixNanos = 0
			state, err := NewState(compiled, rejectingDataWriter{appendErr: test.err}, config)
			if err != nil {
				t.Fatal(err)
			}
			packer, err := NewPacker(state, PackerConfig{
				Write: func(context.Context, []byte) (int, error) {
					t.Fatal("terminal append rejection reached transport")
					return 0, nil
				},
				Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := packer.Pack(boundedPackerContext(t), validPackerLogs(t), nil)
			if !errors.Is(err, ErrPackPermanent) || result.Classification(0) != SourceInvalid {
				t.Fatalf("terminal append = (%d,%v,%v)", result.Outcome(), err, result.Classification(0))
			}
			want := RejectionCounts{}
			want[test.want] = 1
			assertPackerRejectionCounts(t, result, want)
		})
	}
}

// TestPackerPureAppenderSuffixAvailabilityReason injects a pure appender
// value rejection after the availability gate; this branch cannot be reached
// through a validated writer/value pair because normal appenders accept the
// mapped record.
func TestPackerPureAppenderSuffixAvailabilityReason(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want RejectionReason
	}{
		{name: "value", err: wire.ErrInvalidValue, want: RejectionRecordInvalid},
		{name: "capacity", err: wire.ErrBounds, want: RejectionRecordTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			created := 0
			writer := suffixRejectWriter{
				created: &created, appendErr: test.err,
				base: netflow5.Writer{}, stream: netflow5.Writer{},
			}
			compiled := compiledMapping(t, wire.ProtocolV5)
			config := DefaultConfig(wire.ProtocolV5)
			config.HasUptimeOrigin = true
			config.UptimeOriginUnixNanos = 0
			state, err := NewState(compiled, writer, config)
			if err != nil {
				t.Fatal(err)
			}
			availableChecks := 0
			packer, err := NewPacker(state, PackerConfig{
				Available: func() bool {
					availableChecks++
					return availableChecks <= 2
				},
				Write: func(context.Context, []byte) (int, error) {
					t.Fatal("unavailable suffix reached transport")
					return 0, nil
				},
				Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := packer.Pack(boundedPackerContext(t), appendPackerCopies(t, validPackerLogs(t), 2), nil)
			if !errors.Is(err, ErrPackTransient) || result.Classification(0) != SourceUnsentValid || result.Classification(1) != SourceInvalid {
				t.Fatalf("availability suffix = (%d,%v,%v/%v)", result.Outcome(), err, result.Classification(0), result.Classification(1))
			}
			want := RejectionCounts{}
			want[test.want] = 1
			assertPackerRejectionCounts(t, result, want)
		})
	}
}

// TestPackerPureAppenderSuffixCancellationReason injects a validation
// appender rejection after a request context is canceled. The cancellation
// gate is public behavior; the rejecting validation appender is private-only.
func TestPackerPureAppenderSuffixCancellationReason(t *testing.T) {
	pen, element := uint32(32473), uint32(100)
	variable := true
	maxLength := uint32(16)
	compiled, err := mapping.Compile(mapping.Config{
		Protocol:        wire.ProtocolIPFIX,
		Fields:          []mapping.FieldSelection{{Canonical: "source.port"}},
		LossPolicy:      mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize: 65507, PathMTU: 65535, Endpoint: "192.0.2.1:4739",
		Custom: []mapping.CustomField{{Source: "vendor.value", PEN: &pen, ElementID: &element, Encoding: "string", Variable: &variable, MaxLength: &maxLength}},
	})
	if err != nil {
		t.Fatal(err)
	}
	created := 0
	writer := suffixRejectWriter{
		created: &created, appendErr: wire.ErrInvalidValue,
		base: ipfix.Writer{}, stream: ipfix.Writer{},
	}
	config := DefaultConfig(wire.ProtocolIPFIX)
	config.ObservationDomainID = 42
	state, err := NewState(compiled, writer, config)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, state, 4_000_000_000, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) { return len(datagram), nil },
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	logs := appendPackerCopies(t, testpdata.CanonicalLogs(), 2)
	result, err := packer.Pack(ctx, logs, func(ordinal uint64, _ string) (wire.Value, bool) {
		if ordinal == 1 {
			cancel()
		}
		return wire.StringValue("x"), true
	})
	if !errors.Is(err, ErrPackTransient) || result.Classification(0) != SourceUnsentValid || result.Classification(1) != SourceInvalid {
		t.Fatalf("cancellation suffix = (%d,%v,%v/%v)", result.Outcome(), err, result.Classification(0), result.Classification(1))
	}
	want := RejectionCounts{}
	want[RejectionRecordInvalid] = 1
	assertPackerRejectionCounts(t, result, want)
}

func TestPackerFlushBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		maxRecords  uint16
		maxDatagram uint64
		count       int
		wantWrites  int
	}{
		{name: "configurable-count", maxRecords: 2, maxDatagram: 464, count: 3, wantWrites: 2},
		{name: "datagram-capacity", maxRecords: 30, maxDatagram: 128, count: 3, wantWrites: 2},
		{name: "absolute-v5-cap", maxRecords: 30, maxDatagram: 464, count: 31, wantWrites: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := packerV5State(t, test.maxRecords, test.maxDatagram)
			logs := appendPackerCopies(t, validPackerLogs(t), test.count)
			writes := 0
			packer, err := NewPacker(state, PackerConfig{
				Write: func(_ context.Context, datagram []byte) (int, error) { writes++; return len(datagram), nil },
				Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := packer.Pack(context.Background(), logs, nil)
			if err != nil || result.Outcome() != PackSucceeded {
				t.Fatalf("Pack() = (%d,%v)", result.Outcome(), err)
			}
			if writes != test.wantWrites || result.Counts().Confirmed != uint64(test.count) {
				t.Fatalf("writes/confirmed = %d/%d, want %d/%d", writes, result.Counts().Confirmed, test.wantWrites, test.count)
			}
			assertPackerRejectionCounts(t, result, RejectionCounts{})
		})
	}
}

func TestPackerAllLegalWritesAndInvalidWriteResults(t *testing.T) {
	tests := []struct {
		name       string
		write      func(int) (int, error)
		wantResult PackOutcome
		wantClass  SourceClass
		wantError  error
	}{
		{name: "full-nil", write: func(length int) (int, error) { return length, nil }, wantResult: PackSucceeded, wantClass: SourceConfirmed},
		{name: "short-nil", write: func(length int) (int, error) { return length - 1, nil }, wantResult: PackTransient, wantClass: SourceAmbiguous, wantError: ErrPackTransient},
		{name: "zero-nil", write: func(int) (int, error) { return 0, nil }, wantResult: PackTransient, wantClass: SourceAmbiguous, wantError: ErrPackTransient},
		{name: "short-error", write: func(length int) (int, error) { return length - 1, errors.New("short") }, wantResult: PackTransient, wantClass: SourceAmbiguous, wantError: ErrPackTransient},
		{name: "zero-error", write: func(int) (int, error) { return 0, errors.New("zero") }, wantResult: PackTransient, wantClass: SourceAmbiguous, wantError: ErrPackTransient},
		{name: "full-error", write: func(length int) (int, error) { return length, errors.New("full") }, wantResult: PackTransient, wantClass: SourceAmbiguous, wantError: ErrPackTransient},
		{name: "negative-n", write: func(int) (int, error) { return -1, nil }, wantResult: PackInternal, wantClass: SourceUnsentValid, wantError: ErrPackInternal},
		{name: "over-length-n", write: func(length int) (int, error) { return length + 1, nil }, wantResult: PackInternal, wantClass: SourceUnsentValid, wantError: ErrPackInternal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := packerState(t)
			writes := 0
			packer, err := NewPacker(state, PackerConfig{
				Write: func(_ context.Context, datagram []byte) (int, error) { writes++; return test.write(len(datagram)) },
				Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := packer.Pack(context.Background(), validPackerLogs(t), nil)
			if result.Outcome() != test.wantResult || result.Classification(0) != test.wantClass {
				t.Fatalf("result = (%d,%d), want (%d,%d)", result.Outcome(), result.Classification(0), test.wantResult, test.wantClass)
			}
			if test.wantError != nil && !errors.Is(err, test.wantError) {
				t.Fatalf("Pack() error = %v, want %v", err, test.wantError)
			}
			if test.wantError == nil && err != nil {
				t.Fatalf("Pack() error = %v, want nil", err)
			}
			if writes != 1 || state.Sequence() != 0 && test.wantResult != PackSucceeded {
				t.Fatalf("writes/sequence = %d/%d", writes, state.Sequence())
			}
			assertPackerRejectionCounts(t, result, RejectionCounts{})
		})
	}
}

func TestPackerMixedConfirmedInvalidAmbiguousAndUnsentLedger(t *testing.T) {
	state := packerV5State(t, 1, 464)
	logs := appendPackerCopies(t, validPackerLogs(t), 4)
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	records.At(1).Attributes().Remove("source.address")
	writes := 0
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) {
			writes++
			if writes == 1 {
				return len(datagram), nil
			}
			return len(datagram) - 1, errors.New("second handoff")
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(context.Background(), logs, nil)
	if !errors.Is(err, ErrPackTransient) {
		t.Fatalf("Pack() error = %v, want transient", err)
	}
	want := []SourceClass{SourceConfirmed, SourceInvalid, SourceAmbiguous, SourceUnsentValid}
	for ordinal, class := range want {
		if got := result.Classification(uint64(ordinal)); got != class {
			t.Errorf("ordinal %d class = %d, want %d", ordinal, got, class)
		}
	}
	if writes != 2 || state.Sequence() != 1 {
		t.Fatalf("writes/sequence = %d/%d, want 2/1", writes, state.Sequence())
	}
	wantReasons := RejectionCounts{}
	wantReasons[RejectionMissingField] = 1
	assertPackerRejectionCounts(t, result, wantReasons)
}

func TestPackerAllInvalidWritesNothing(t *testing.T) {
	state := packerState(t)
	logs := validPackerLogs(t)
	logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Remove("source.address")
	writes := 0
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) { writes++; return len(datagram), nil },
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(context.Background(), logs, nil)
	if !errors.Is(err, ErrPackPermanent) || result.Outcome() != PackPermanent || result.Classification(0) != SourceInvalid {
		t.Fatalf("all-invalid result = (%d,%v,%d)", result.Outcome(), err, result.Classification(0))
	}
	if writes != 0 || state.Sequence() != 0 {
		t.Fatalf("all-invalid writes/sequence = %d/%d", writes, state.Sequence())
	}
	wantReasons := RejectionCounts{}
	wantReasons[RejectionMissingField] = 1
	assertPackerRejectionCounts(t, result, wantReasons)
}

func TestPackerLargeRequestDoesNotUseAggregateAdmission(t *testing.T) {
	state := packerState(t)
	lookupCalls, writes := 0, 0
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) { writes++; return len(datagram), nil },
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(context.Background(), appendPackerCopies(t, validPackerLogs(t), 2), func(uint64, string) (wire.Value, bool) {
		lookupCalls++
		return wire.UintValue(1), true
	})
	if err != nil || result.Outcome() != PackSucceeded || result.Counts().Covered != 2 {
		t.Fatalf("large request result = (%d,%v,%+v)", result.Outcome(), err, result.Counts())
	}
	if lookupCalls != 0 || writes == 0 || state.Sequence() == 0 {
		t.Fatalf("large request callbacks/writes/sequence = %d/%d/%d", lookupCalls, writes, state.Sequence())
	}
	assertPackerRejectionCounts(t, result, RejectionCounts{})
}

func TestPackerOversizeVariableCustomBeforeAndAfterData(t *testing.T) {
	longValue := strings.Repeat("x", 120)
	shortLookup := func(ordinal uint64, _ string) (wire.Value, bool) {
		if ordinal == 0 {
			return wire.StringValue(longValue), true
		}
		return wire.StringValue("x"), true
	}
	t.Run("before-data-valid-sibling", func(t *testing.T) {
		state := customPackerState(t, true, 128, 0)
		writes := 0
		packer, err := NewPacker(state, PackerConfig{
			Write: func(_ context.Context, datagram []byte) (int, error) { writes++; return len(datagram), nil },
			Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
		})
		if err != nil {
			t.Fatal(err)
		}
		result, err := packer.Pack(boundedPackerContext(t), appendPackerCopies(t, testpdata.CanonicalLogs(), 2), shortLookup)
		if err != nil || result.Classification(0) != SourceInvalid || result.Classification(1) != SourceConfirmed {
			t.Fatalf("Pack() = (%d,%v), classes=%d/%d", result.Outcome(), err, result.Classification(0), result.Classification(1))
		}
		if writes != 1 {
			t.Fatalf("writes = %d, want one valid sibling packet", writes)
		}
		wantReasons := RejectionCounts{}
		wantReasons[RejectionRecordTooLarge] = 1
		assertPackerRejectionCounts(t, result, wantReasons)
	})

	t.Run("after-data-write-failure", func(t *testing.T) {
		state := customPackerState(t, true, 128, 0, 1)
		writes := 0
		packer, err := NewPacker(state, PackerConfig{
			Write: func(_ context.Context, datagram []byte) (int, error) {
				writes++
				return len(datagram) - 1, errors.New("data handoff")
			},
			Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
		})
		if err != nil {
			t.Fatal(err)
		}
		logs := appendPackerCopies(t, testpdata.CanonicalLogs(), 2)
		result, err := packer.Pack(boundedPackerContext(t), logs, func(ordinal uint64, _ string) (wire.Value, bool) {
			if ordinal == 1 {
				return wire.StringValue(longValue), true
			}
			return wire.StringValue("x"), true
		})
		if !errors.Is(err, ErrPackTransient) || result.Classification(0) != SourceAmbiguous || result.Classification(1) != SourceInvalid {
			t.Fatalf("Pack() = (%d,%v), classes=%d/%d", result.Outcome(), err, result.Classification(0), result.Classification(1))
		}
		if writes != 1 || state.Sequence() != 0 {
			t.Fatalf("writes/sequence = %d/%d, want 1/0", writes, state.Sequence())
		}
		wantReasons := RejectionCounts{}
		wantReasons[RejectionRecordTooLarge] = 1
		assertPackerRejectionCounts(t, result, wantReasons)
	})

	t.Run("after-successful-boundary-flush", func(t *testing.T) {
		state := customPackerState(t, true, 128, 0)
		writes := 0
		packer, err := NewPacker(state, PackerConfig{
			Write: func(_ context.Context, datagram []byte) (int, error) { writes++; return len(datagram), nil },
			Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
		})
		if err != nil {
			t.Fatal(err)
		}
		logs := appendPackerCopies(t, testpdata.CanonicalLogs(), 2)
		result, err := packer.Pack(boundedPackerContext(t), logs, func(ordinal uint64, _ string) (wire.Value, bool) {
			if ordinal == 1 {
				return wire.StringValue(longValue), true
			}
			return wire.StringValue("x"), true
		})
		if err != nil || result.Classification(0) != SourceConfirmed || result.Classification(1) != SourceInvalid {
			t.Fatalf("boundary flush = (%v,%v/%v)", err, result.Classification(0), result.Classification(1))
		}
		if writes != 1 || result.Counts().Confirmed != 1 || state.Sequence() != 1 {
			t.Fatalf("boundary writes/counts/sequence = %d/%+v/%d", writes, result.Counts(), state.Sequence())
		}
		want := RejectionCounts{}
		want[RejectionRecordTooLarge] = 1
		assertPackerRejectionCounts(t, result, want)
	})
}

// TestPackerMinimumFitReasonProvenCapacityAndGeneric uses package-local
// constructed records to reach wire sizing branches that validated mapping
// cannot currently produce: descriptor byte overflow, encoded-set capacity,
// and an injected unknown protocol. The public per-datagram capacity failures
// above use valid mapped values and exercise this helper or suffix preview.
func TestPackerMinimumFitReasonProvenCapacityAndGeneric(t *testing.T) {
	variableState := customPackerState(t, true, 65507, 0)
	variableShape, ok := variableState.Catalog().ShapeAt(0)
	if !ok {
		t.Fatal("variable shape missing")
	}
	variableValues := make([]wire.Value, variableShape.FieldCount())
	for index, descriptor := range variableShape.Fields() {
		if descriptor.Variable {
			variableValues[index] = wire.StringValue(strings.Repeat("x", int(descriptor.MaxLength)+1))
		} else {
			variableValues[index] = wire.UintValue(1)
		}
	}
	variableRecord, err := wire.NewWireRecord(variableShape.Family(), variableValues)
	if err != nil {
		t.Fatal(err)
	}
	variablePacker := &Packer{state: variableState, datagram: make([]byte, 65507)}
	if fits, reason := variablePacker.minimumDataPacketFits(variableRecord, 0); fits || reason != RejectionRecordTooLarge {
		t.Fatalf("variable descriptor fit = (%v,%v), want false/too-large", fits, reason)
	}

	largeFields := make([]wire.FieldDescriptor, 32)
	largeValues := make([]wire.Value, len(largeFields))
	for index := range largeFields {
		length := uint16(2048)
		if index == len(largeFields)-1 {
			length = 2047
		}
		largeFields[index] = wire.FieldDescriptor{
			Protocol: wire.ProtocolIPFIX,
			Field:    wire.FieldInvalid,
			Source:   fmt.Sprintf("vendor.capacity.%d", index),
			Custom:   true, Enterprise: true, ID: uint16(256 + index), PEN: 32473,
			Length: length, Encoding: wire.EncodingOctetArray,
		}
		largeValues[index] = wire.BytesValue(bytes.Repeat([]byte{1}, int(length)))
	}
	largeSpec := wire.ShapeSpec{
		Protocol: wire.ProtocolIPFIX, Family: wire.FamilyIPv4, ID: 256,
		Fields: largeFields, RecordLength: 65535,
	}
	var largeShape wire.Shape
	for templateBytes := uint64(1); templateBytes <= wire.DefaultMaxTemplateBytes; templateBytes++ {
		largeSpec.TemplateBytes = templateBytes
		largeShape, err = wire.NewShape(largeSpec)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("large shape construction: %v", err)
	}
	wireCatalog, err := wire.NewCatalog(wire.CatalogSpec{
		Protocol: wire.ProtocolIPFIX, IDBase: 256, Shapes: []wire.ShapeSpec{largeSpec},
	})
	if err != nil {
		t.Fatalf("large catalog construction: %v", err)
	}
	largeCatalog, err := NewCatalogFromWire(wireCatalog)
	if err != nil {
		t.Fatalf("large destination catalog: %v", err)
	}
	largeRecord, err := wire.NewWireRecord(largeShape.Family(), largeValues)
	if err != nil {
		t.Fatal(err)
	}
	largeState := &State{catalog: largeCatalog, config: Config{Protocol: wire.ProtocolIPFIX, MaxDatagramSize: 65507}}
	largePacker := &Packer{state: largeState, datagram: make([]byte, 65507)}
	if fits, reason := largePacker.minimumDataPacketFits(largeRecord, 0); fits || reason != RejectionRecordTooLarge {
		t.Fatalf("encoded set fit = (%v,%v), want false/too-large", fits, reason)
	}

	genericPacker := &Packer{state: packerState(t), datagram: make([]byte, 464)}
	var genericRecord wire.WireRecord
	if err := normalize.NormalizeEachIndexed(validPackerLogs(t), func(_ uint64, normalized wire.NormalizedRecord, normalizeErr error) error {
		if normalizeErr != nil {
			return normalizeErr
		}
		mapped, mapErr := genericPacker.state.Mapping().MapWithStats(normalized, nil)
		genericRecord = mapped.Record
		return mapErr
	}); err != nil {
		t.Fatalf("generic record mapping: %v", err)
	}
	if fits, reason := genericPacker.minimumDataPacketFits(wire.WireRecord{}, 0); fits || reason != RejectionRecordInvalid {
		t.Fatalf("generic record fit = (%v,%v), want false/record-invalid", fits, reason)
	}
	if fits, reason := genericPacker.minimumDataPacketFits(wire.WireRecord{}, 99); fits || reason != RejectionRecordInvalid {
		t.Fatalf("generic shape fit = (%v,%v), want false/record-invalid", fits, reason)
	}
	unknownState := packerState(t)
	unknownState.mu.Lock()
	unknownState.config.Protocol = wire.ProtocolUnknown
	unknownState.mu.Unlock()
	unknownPacker := &Packer{state: unknownState, datagram: make([]byte, 464)}
	if fits, reason := unknownPacker.minimumDataPacketFits(genericRecord, 0); fits || reason != RejectionOther {
		t.Fatalf("unknown protocol fit = (%v,%v), want false/other", fits, reason)
	}
}

func TestPackerPureAppenderRejectsFutureV5Suffix(t *testing.T) {
	state := packerV5State(t, 1, 464)
	logs := appendPackerCopies(t, validPackerLogs(t), 2)
	future := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(1)
	for _, key := range []string{"flow.time_received", "flow.start", "flow.end"} {
		future.Attributes().PutInt(key, 5_000_000_000)
	}
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) {
			return len(datagram) - 1, errors.New("data handoff")
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(boundedPackerContext(t), logs, nil)
	if !errors.Is(err, ErrPackTransient) || result.Classification(0) != SourceAmbiguous || result.Classification(1) != SourceInvalid {
		t.Fatalf("Pack() = (%d,%v), classes=%d/%d", result.Outcome(), err, result.Classification(0), result.Classification(1))
	}
	wantReasons := RejectionCounts{}
	wantReasons[RejectionRecordInvalid] = 1
	assertPackerRejectionCounts(t, result, wantReasons)
}

func TestPackerPureAppenderRejectsFutureSuffixAfterRefreshFailure(t *testing.T) {
	compiledConfig := mapping.Config{
		Protocol:              wire.ProtocolV9,
		Fields:                []mapping.FieldSelection{{Canonical: "flow.start"}, {Canonical: "flow.end"}},
		HasUptimeOrigin:       true,
		UptimeOriginUnixNanos: 0,
		LossPolicy:            mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize:       65507,
		PathMTU:               65535,
		Endpoint:              "192.0.2.1:4739",
	}
	compiled, err := mapping.Compile(compiledConfig)
	if err != nil {
		t.Fatalf("compile V9 time mapping: %v", err)
	}
	stateConfig := DefaultConfig(wire.ProtocolV9)
	stateConfig.SourceID, stateConfig.ObservationDomainID = 42, 42
	stateConfig.HasUptimeOrigin, stateConfig.UptimeOriginUnixNanos = true, 0
	stateConfig.V9RefreshPacketCount = 1
	state, err := NewState(compiled, netflow9.Writer{}, stateConfig)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, state, 3_000_000_000, 1)
	writes := 0
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) {
			writes++
			if writes > 1 {
				return len(datagram) - 1, errors.New("refresh handoff")
			}
			return len(datagram), nil
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	valid := testpdata.CanonicalLogs()
	for _, key := range []string{"flow.start", "flow.end"} {
		valid.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutInt(key, 3_000_000_000)
	}
	ctx := boundedPackerContext(t)
	first, err := packer.Pack(ctx, valid, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertPackerRejectionCounts(t, first, RejectionCounts{})
	logs := appendPackerCopies(t, valid, 2)
	future := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(1)
	for _, key := range []string{"flow.start", "flow.end"} {
		future.Attributes().PutInt(key, 5_000_000_000)
	}
	result, err := packer.Pack(ctx, logs, nil)
	if !errors.Is(err, ErrPackTransient) || result.Classification(0) != SourceUnsentValid || result.Classification(1) != SourceInvalid {
		t.Fatalf("Pack() = (%d,%v), classes=%d/%d", result.Outcome(), err, result.Classification(0), result.Classification(1))
	}
	if writes != 2 || !state.Progress().RefreshDue {
		t.Fatalf("writes/progress = %d/%+v", writes, state.Progress())
	}
	wantReasons := RejectionCounts{}
	wantReasons[RejectionRecordInvalid] = 1
	assertPackerRejectionCounts(t, result, wantReasons)
}

func TestPackerPureAppenderValidatesSuffixAfterRefreshFailure(t *testing.T) {
	state := customPackerState(t, true, 128, 1)
	writes := 0
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) {
			writes++
			if writes > 1 {
				return len(datagram) - 1, errors.New("refresh handoff")
			}
			return len(datagram), nil
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := boundedPackerContext(t)
	first, err := packer.Pack(ctx, testpdata.CanonicalLogs(), func(uint64, string) (wire.Value, bool) {
		return wire.StringValue("x"), true
	})
	if err != nil {
		t.Fatal(err)
	}
	assertPackerRejectionCounts(t, first, RejectionCounts{})
	logs := appendPackerCopies(t, testpdata.CanonicalLogs(), 2)
	result, err := packer.Pack(ctx, logs, func(ordinal uint64, _ string) (wire.Value, bool) {
		if ordinal == 1 {
			return wire.StringValue(strings.Repeat("x", 120)), true
		}
		return wire.StringValue("x"), true
	})
	if !errors.Is(err, ErrPackTransient) || result.Classification(0) != SourceUnsentValid || result.Classification(1) != SourceInvalid {
		t.Fatalf("Pack() = (%d,%v), classes=%d/%d", result.Outcome(), err, result.Classification(0), result.Classification(1))
	}
	if writes != 2 || !state.Progress().RefreshDue {
		t.Fatalf("writes/progress = %d/%+v", writes, state.Progress())
	}
	wantReasons := RejectionCounts{}
	wantReasons[RejectionRecordTooLarge] = 1
	assertPackerRejectionCounts(t, result, wantReasons)
}

func TestPackerIPFIXNanosecondLimitIsMapperRejection(t *testing.T) {
	compiledConfig := mapping.Config{
		Protocol:        wire.ProtocolIPFIX,
		Fields:          []mapping.FieldSelection{{Canonical: "flow.time_received", Target: "observation_time_nanoseconds"}},
		LossPolicy:      mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize: 65507,
		PathMTU:         65535,
		Endpoint:        "192.0.2.1:4739",
	}
	compiled, err := mapping.Compile(compiledConfig)
	if err != nil {
		t.Fatalf("compile IPFIX time mapping: %v", err)
	}
	config := DefaultConfig(wire.ProtocolIPFIX)
	config.ObservationDomainID = 42
	state, err := NewState(compiled, ipfix.Writer{}, config)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, state, 3_000_000_000, 1)
	logs := testpdata.CanonicalLogs()
	logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutInt("flow.time_received", 2_085_978_496_000_000_000)
	writes := 0
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) { writes++; return len(datagram), nil },
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(boundedPackerContext(t), logs, nil)
	if !errors.Is(err, ErrPackPermanent) || result.Classification(0) != SourceInvalid || writes != 0 {
		t.Fatalf("mapper rejection = (%d,%v,%d), writes=%d", result.Outcome(), err, result.Classification(0), writes)
	}
	wantReasons := RejectionCounts{}
	wantReasons[RejectionTimeInvalid] = 1
	assertPackerRejectionCounts(t, result, wantReasons)
}

func TestPackerResumesPartialMultiShapeRefresh(t *testing.T) {
	state := shapeSwitchState(t, 2)
	logs := testpdata.CanonicalLogs()
	testpdata.CanonicalIPv6Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).CopyTo(logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().AppendEmpty())
	writes := 0
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) {
			writes++
			if writes == 4 {
				return len(datagram) - 1, errors.New("partial refresh")
			}
			return len(datagram), nil
		},
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := packer.Pack(context.Background(), logs, nil)
	if err != nil || first.Counts().Confirmed != 2 || !state.Progress().RefreshDue {
		t.Fatalf("first Pack() = (%d,%v,%+v), progress=%+v", first.Outcome(), err, first.Counts(), state.Progress())
	}
	partial, err := packer.Pack(context.Background(), testpdata.CanonicalLogs(), nil)
	if !errors.Is(err, ErrPackTransient) || partial.Classification(0) != SourceUnsentValid {
		t.Fatalf("partial refresh = (%d,%v,%d)", partial.Outcome(), err, partial.Classification(0))
	}
	progress := state.Progress()
	if writes != 4 || !progress.RefreshActive || !progress.RefreshDue || progress.NextShape != 1 {
		t.Fatalf("partial writes/progress = %d/%+v", writes, progress)
	}
	resumed, err := packer.Pack(context.Background(), testpdata.CanonicalIPv6Logs(), nil)
	if err != nil || resumed.Classification(0) != SourceConfirmed {
		t.Fatalf("resumed Pack() = (%d,%v,%d)", resumed.Outcome(), err, resumed.Classification(0))
	}
	if writes != 6 || state.Progress().RefreshActive || state.Progress().RefreshDue {
		t.Fatalf("resume writes/progress = %d/%+v", writes, state.Progress())
	}
	assertPackerRejectionCounts(t, first, RejectionCounts{})
	assertPackerRejectionCounts(t, partial, RejectionCounts{})
	assertPackerRejectionCounts(t, resumed, RejectionCounts{})
}

func TestPackerAllowsOnlyOneDueRefreshRoundWhenClockAdvances(t *testing.T) {
	compiled := tinyCompiledMapping(t, wire.ProtocolV9)
	config := DefaultConfig(wire.ProtocolV9)
	config.SourceID, config.ObservationDomainID = 42, 42
	state, err := NewState(compiled, netflow9.Writer{}, config)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, state, 3_000_000_000, 1)
	initialSequence := state.Sequence()
	var clocks int
	clock := func() (uint64, uint64) {
		clocks++
		switch clocks {
		case 1:
			return 4_000_000_000, 2
		case 2:
			return 4_000_000_000, 601_000_000_001
		default:
			return 4_000_000_000, 1_201_000_000_001
		}
	}
	writes := 0
	packer, err := NewPacker(state, PackerConfig{
		Write: func(_ context.Context, datagram []byte) (int, error) { writes++; return len(datagram), nil },
		Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := packer.Pack(context.Background(), testpdata.CanonicalLogs(), nil); err != nil {
		t.Fatal(err)
	}
	result, err := packer.Pack(context.Background(), testpdata.CanonicalLogs(), nil)
	if !errors.Is(err, ErrPackTransient) || result.Classification(0) != SourceUnsentValid {
		t.Fatalf("advancing clock result = (%d,%v,%d)", result.Outcome(), err, result.Classification(0))
	}
	if writes != 2 || state.Sequence() != initialSequence+2 || !state.Progress().RefreshDue {
		t.Fatalf("writes/sequence/progress = %d/%d/%+v", writes, state.Sequence(), state.Progress())
	}
	assertPackerRejectionCounts(t, result, RejectionCounts{})
}

func TestPackerCancellationAbortsBufferedData(t *testing.T) {
	state := customPackerState(t, false, 464, 0, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	packer, err := NewPacker(state, PackerConfig{
		Clock: func() (uint64, uint64) { return 4_000_000_000, 2 },
		Write: func(context.Context, []byte) (int, error) {
			t.Fatal("canceled buffer reached transport")
			return 0, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	before := state.Epoch()
	logs := appendPackerCopies(t, validPackerLogs(t), 3)
	logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(2).Attributes().Remove("source.address")
	result, err := packer.Pack(ctx, logs, func(ordinal uint64, _ string) (wire.Value, bool) {
		if ordinal == 1 {
			if state.pending == nil || !packer.ledgerOpen {
				t.Fatal("first record was not buffered before cancellation")
			}
			cancel()
		}
		return wire.UintValue(7), true
	})
	if !errors.Is(err, ErrPackTransient) || result.Classification(0) != SourceUnsentValid || result.Classification(1) != SourceUnsentValid || result.Classification(2) != SourceInvalid {
		t.Fatalf("canceled Pack = %+v, %v", result.Counts(), err)
	}
	if state.pending != nil || state.Epoch() != before || result.Packets() != 0 {
		t.Fatal("canceled buffer advanced or retained a transaction")
	}
	wantReasons := RejectionCounts{}
	wantReasons[RejectionMissingField] = 1
	assertPackerRejectionCounts(t, result, wantReasons)
	if _, err := packer.Pack(nil, logs, nil); !errors.Is(err, ErrPackInternal) {
		t.Fatalf("nil context = %v", err)
	}
}

func TestPackerAvailabilityAbortsBufferedData(t *testing.T) {
	state := customPackerState(t, false, 464, 0, 2)
	available := true
	packer, err := NewPacker(state, PackerConfig{
		Clock:     func() (uint64, uint64) { return 4_000_000_000, 2 },
		Available: func() bool { return available },
		Write: func(context.Context, []byte) (int, error) {
			t.Fatal("unavailable buffer reached transport")
			return 0, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	before, progress := state.Epoch(), state.Progress()
	logs := appendPackerCopies(t, validPackerLogs(t), 3)
	logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(2).Attributes().Remove("source.address")
	result, err := packer.Pack(context.Background(), logs, func(ordinal uint64, _ string) (wire.Value, bool) {
		if ordinal == 1 {
			if state.pending == nil || !packer.ledgerOpen {
				t.Fatal("first record was not buffered before expiry")
			}
			available = false
		}
		return wire.UintValue(7), true
	})
	if err != ErrPackTransient || result.Classification(0) != SourceUnsentValid || result.Classification(1) != SourceUnsentValid || result.Classification(2) != SourceInvalid {
		t.Fatalf("unavailable Pack = %+v, %v", result.Counts(), err)
	}
	if state.pending != nil || state.Epoch() != before || state.Progress() != progress || result.Packets() != 0 {
		t.Fatal("unavailable buffer advanced or retained a transaction")
	}
	wantReasons := RejectionCounts{}
	wantReasons[RejectionMissingField] = 1
	assertPackerRejectionCounts(t, result, wantReasons)
}

func TestPackerCallerContextForDataAndRefresh(t *testing.T) {
	state := shapeSwitchState(t, 20)
	firstCtx, firstCancel := context.WithCancel(context.Background())
	defer firstCancel()
	secondCtx, secondCancel := context.WithCancel(context.Background())
	defer secondCancel()
	wantCtx := firstCtx
	writes := 0
	mono := uint64(2)
	packer, err := NewPacker(state, PackerConfig{
		Clock: func() (uint64, uint64) { return 4_000_000_000, mono },
		Write: func(ctx context.Context, datagram []byte) (int, error) {
			if ctx != wantCtx {
				t.Fatal("write received a substituted or retained context")
			}
			writes++
			if writes == 1 {
				firstCancel() // full success still commits even if ctx is now canceled
			}
			return len(datagram), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := packer.Pack(firstCtx, validPackerLogs(t), nil); err != nil || result.Counts().Confirmed != 1 {
		t.Fatalf("full write at cancellation = %+v, %v", result, err)
	}
	mono += uint64(state.Config().RefreshInterval)
	wantCtx = secondCtx
	if result, err := packer.Pack(secondCtx, validPackerLogs(t), nil); err != nil || result.Counts().Confirmed != 1 {
		t.Fatalf("next request = %+v, %v", result, err)
	}
	if writes != 4 { // first data, two refresh shapes, second data
		t.Fatalf("writes = %d, want 4", writes)
	}
}
