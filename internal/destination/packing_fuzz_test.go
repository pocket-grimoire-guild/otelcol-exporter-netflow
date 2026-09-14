package destination

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/ipfix"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow5"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow9"
	"go.opentelemetry.io/collector/pdata/plog"
)

// FuzzPacketPacking exercises the bounded streaming packer with a small,
// test-owned scenario grammar.  Packet checks decode only fixed protocol
// offsets and values chosen by this test; they do not round-trip through a
// production decoder or derive acceptance from Packer's own ledger.
func FuzzPacketPacking(f *testing.F) {
	f.Fuzz(func(t *testing.T, protocolByte, scenarioByte, countByte, outcomeByte, valueByte uint8) {
		switch scenarioByte % 12 {
		case 0:
			packingFuzzFull(t, packingFuzzProtocol(protocolByte), 1+int(countByte%4))
		case 1:
			packingFuzzFull(t, wire.ProtocolV5, 1+int(countByte%3))
		case 2:
			packingFuzzFull(t, wire.ProtocolV9, 1+int(countByte%3))
		case 3:
			packingFuzzFull(t, wire.ProtocolIPFIX, 1+int(countByte%3))
		case 4:
			packingFuzzRecordBoundary(t, packingFuzzProtocol(protocolByte), countByte)
		case 5:
			packingFuzzDatagramBoundary(t, valueByte)
		case 6:
			packingFuzzSamplingFlush(t, valueByte)
		case 7:
			packingFuzzShapeFlush(t, packingFuzzProtocol(protocolByte))
		case 8:
			packingFuzzInvalidSibling(t, packingFuzzProtocol(protocolByte), countByte, valueByte)
		case 9:
			packingFuzzWriteOutcome(t, packingFuzzProtocol(protocolByte), outcomeByte, valueByte)
		case 10:
			if valueByte&1 == 0 {
				packingFuzzCancellation(t, packingFuzzProtocol(protocolByte), valueByte)
			} else {
				packingFuzzMalformed(t, packingFuzzProtocol(protocolByte))
			}
		case 11:
			packingFuzzOversize(t, valueByte)
		}
	})
}

func packingFuzzProtocol(selector uint8) wire.Protocol {
	switch selector % 3 {
	case 0:
		return wire.ProtocolV5
	case 1:
		return wire.ProtocolV9
	default:
		return wire.ProtocolIPFIX
	}
}

func packingFuzzState(t *testing.T, protocol wire.Protocol, maxRecords uint16, maxDatagram uint64) *State {
	t.Helper()
	compiled := compiledMapping(t, protocol)
	writer := wire.ContractWriter(netflow5.Writer{})
	config := DefaultConfig(protocol)
	config.MaxRecordsPerMessage = maxRecords
	config.MaxDatagramSize = maxDatagram
	switch protocol {
	case wire.ProtocolV9:
		compiled = tinyCompiledMapping(t, protocol)
		writer = netflow9.Writer{}
		config.SourceID, config.ObservationDomainID = 42, 42
	case wire.ProtocolIPFIX:
		compiled = tinyCompiledMapping(t, protocol)
		writer = ipfix.Writer{}
		config.ObservationDomainID = 42
	case wire.ProtocolV5:
		config.HasUptimeOrigin = true
		config.UptimeOriginUnixNanos = 0
	}
	state, err := NewState(compiled, writer, config)
	if err != nil {
		t.Fatalf("new %s state: %v", protocol, err)
	}
	if protocol != wire.ProtocolV5 {
		bootstrap(t, state, 3_000_000_000, 1)
	}
	return state
}

type packingFuzzCapture struct {
	t         *testing.T
	maxBytes  int
	packets   [][]byte
	attempts  int
	mode      uint8
	firstFull bool
}

func (c *packingFuzzCapture) write(_ context.Context, datagram []byte) (int, error) {
	if len(datagram) == 0 || len(datagram) > c.maxBytes || c.attempts >= 5 {
		c.t.Fatal("packet exceeds test-owned write/size bounds")
	}
	c.attempts++
	c.packets = append(c.packets, append([]byte(nil), datagram...))
	if c.firstFull && c.attempts == 1 {
		return len(datagram), nil
	}
	switch c.mode % 8 {
	case 0:
		return len(datagram), nil
	case 1:
		return len(datagram) - 1, nil
	case 2:
		return 0, nil
	case 3:
		return len(datagram) - 1, errors.New("raw transport payload must not escape")
	case 4:
		return 0, errors.New("raw transport payload must not escape")
	case 5:
		return len(datagram), errors.New("raw transport payload must not escape")
	case 6:
		return -1, nil
	default:
		return len(datagram) + 1, nil
	}
}

func packingFuzzLogs(t *testing.T, protocol wire.Protocol, count int, invalidOrdinal int) plog.Logs {
	t.Helper()
	if count < 1 || count > 5 {
		t.Fatal("packing fuzz count out of bounds")
	}
	logs := testpdata.CanonicalLogs()
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	base := records.At(0)
	for ordinal := 1; ordinal < count; ordinal++ {
		base.CopyTo(records.AppendEmpty())
	}
	for ordinal := 0; ordinal < count; ordinal++ {
		record := records.At(ordinal)
		record.Attributes().PutInt("source.port", int64(10000+ordinal))
		if protocol == wire.ProtocolV5 {
			for _, key := range []string{"flow.time_received", "flow.start", "flow.end"} {
				record.Attributes().PutInt(key, 3_000_000_000)
			}
		}
		if ordinal == invalidOrdinal {
			if protocol == wire.ProtocolV5 {
				record.Attributes().Remove("source.address")
			} else {
				record.Attributes().Remove("source.port")
			}
		}
	}
	return logs
}

func newPackingFuzzPacker(t *testing.T, state *State, capture *packingFuzzCapture, available func() bool, clock func() (uint64, uint64)) *Packer {
	t.Helper()
	capture.t, capture.maxBytes = t, int(state.Config().MaxDatagramSize)
	if clock == nil {
		clock = func() (uint64, uint64) { return 4_000_000_000, 2 }
	}
	packer, err := NewPacker(state, PackerConfig{
		Available: available,
		Write:     capture.write,
		Clock:     clock,
	})
	if err != nil {
		t.Fatalf("new packer: %v", err)
	}
	return packer
}

func packingFuzzFull(t *testing.T, protocol wire.Protocol, count int) {
	t.Helper()
	state := packingFuzzState(t, protocol, uint16(count+1), 464)
	logs := packingFuzzLogs(t, protocol, count, -1)
	capture := new(packingFuzzCapture)
	packer := newPackingFuzzPacker(t, state, capture, nil, nil)
	beforeSequence := state.Sequence()
	result, err := packer.Pack(context.Background(), logs, nil)
	if err != nil || result.Outcome() != PackSucceeded {
		t.Fatalf("full %s pack=(%d,%v), counts=%+v", protocol, result.Outcome(), err, result.Counts())
	}
	want := make([]uint16, count)
	for i := range want {
		want[i] = uint16(10000 + i)
	}
	assertPackingLedger(t, result, packingClasses(count, SourceConfirmed))
	assertPackingPackets(t, protocol, capture.packets, want)
	if capture.attempts != len(capture.packets) || uint64(capture.attempts) != result.Packets() || result.ConfirmedPackets() != uint64(len(capture.packets)) || result.AmbiguousPackets() != 0 {
		t.Fatalf("full packet accounting attempts=%d packets=%d result=%d/%d/%d", capture.attempts, len(capture.packets), result.Packets(), result.ConfirmedPackets(), result.AmbiguousPackets())
	}
	wantSequence := beforeSequence
	if protocol == wire.ProtocolV9 {
		wantSequence += uint32(len(capture.packets))
	} else {
		wantSequence += uint32(count)
	}
	if state.Sequence() != wantSequence {
		t.Fatalf("full %s sequence=%d want %d", protocol, state.Sequence(), wantSequence)
	}
	// Mutating the request after return must not change the value-only ledger.
	logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().PutInt("source.port", 1)
	assertPackingLedger(t, result, packingClasses(count, SourceConfirmed))
	assertFixedPackingError(t, err)
}

func packingFuzzRecordBoundary(t *testing.T, protocol wire.Protocol, countByte uint8) {
	t.Helper()
	maxRecords := uint16(1 + countByte%3)
	count := int(maxRecords) + 2
	state := packingFuzzState(t, protocol, maxRecords, 464)
	logs := packingFuzzLogs(t, protocol, count, -1)
	capture := new(packingFuzzCapture)
	packer := newPackingFuzzPacker(t, state, capture, nil, nil)
	result, err := packer.Pack(context.Background(), logs, nil)
	if err != nil || result.Outcome() != PackSucceeded {
		t.Fatalf("record boundary %s pack=(%d,%v), counts=%+v", protocol, result.Outcome(), err, result.Counts())
	}
	want := make([]uint16, count)
	for i := range want {
		want[i] = uint16(10000 + i)
	}
	assertPackingLedger(t, result, packingClasses(count, SourceConfirmed))
	assertPackingPackets(t, protocol, capture.packets, want)
	if len(capture.packets) != (count+int(maxRecords)-1)/int(maxRecords) {
		t.Fatalf("record boundary packets=%d want %d", len(capture.packets), (count+int(maxRecords)-1)/int(maxRecords))
	}
}

func packingFuzzDatagramBoundary(t *testing.T, valueByte uint8) {
	t.Helper()
	state := packingFuzzState(t, wire.ProtocolV5, 30, 128)
	count := 3 + int(valueByte%2)
	logs := packingFuzzLogs(t, wire.ProtocolV5, count, -1)
	capture := new(packingFuzzCapture)
	packer := newPackingFuzzPacker(t, state, capture, nil, nil)
	result, err := packer.Pack(context.Background(), logs, nil)
	if err != nil || result.Outcome() != PackSucceeded {
		t.Fatalf("datagram boundary pack=(%d,%v), counts=%+v", result.Outcome(), err, result.Counts())
	}
	want := make([]uint16, count)
	for i := range want {
		want[i] = uint16(10000 + i)
	}
	assertPackingLedger(t, result, packingClasses(count, SourceConfirmed))
	assertPackingPackets(t, wire.ProtocolV5, capture.packets, want)
	if len(capture.packets) != (count+1)/2 {
		t.Fatalf("datagram boundary packets=%d want %d", len(capture.packets), (count+1)/2)
	}
}

func packingFuzzSamplingFlush(t *testing.T, valueByte uint8) {
	t.Helper()
	state := packingFuzzState(t, wire.ProtocolV5, 30, 464)
	logs := packingFuzzLogs(t, wire.ProtocolV5, 2, -1)
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	records.At(0).Attributes().PutInt("flow.sampling_rate", 1000)
	records.At(1).Attributes().PutInt("flow.sampling_rate", int64(1001+int(valueByte)%1000))
	capture := new(packingFuzzCapture)
	packer := newPackingFuzzPacker(t, state, capture, nil, nil)
	result, err := packer.Pack(context.Background(), logs, nil)
	if err != nil || result.Outcome() != PackSucceeded {
		t.Fatalf("sampling flush pack=(%d,%v), counts=%+v", result.Outcome(), err, result.Counts())
	}
	assertPackingLedger(t, result, packingClasses(2, SourceConfirmed))
	if len(capture.packets) != 2 {
		t.Fatalf("sampling flush packets=%d want 2", len(capture.packets))
	}
	for index, packet := range capture.packets {
		if len(packet) != 72 || binary.BigEndian.Uint16(packet[22:24]) != uint16(1000+index*(int(valueByte)%1000+1)) {
			t.Fatalf("sampling packet %d length/sampling=%d/%d", index, len(packet), binary.BigEndian.Uint16(packet[22:24]))
		}
	}
	assertPackingPackets(t, wire.ProtocolV5, capture.packets, []uint16{10000, 10001})
}

func packingFuzzShapeFlush(t *testing.T, protocol wire.Protocol) {
	t.Helper()
	if protocol == wire.ProtocolV5 {
		protocol = wire.ProtocolV9
	}
	state := shapeSwitchState(t, 1000)
	if state.Config().Protocol != protocol {
		// shapeSwitchState is v9-specific; keep the same two-shape construction
		// for IPFIX through a narrowly equivalent mapping and state setup.
		config := mappingShapeSwitchConfig(protocol)
		compiled, err := mapping.Compile(config)
		if err != nil {
			t.Fatal(err)
		}
		stateConfig := DefaultConfig(protocol)
		if protocol == wire.ProtocolIPFIX {
			stateConfig.ObservationDomainID = 42
			stateConfig.IPFIXDataMessageRefreshCount = 1000
		} else {
			stateConfig.SourceID, stateConfig.ObservationDomainID = 42, 42
			stateConfig.V9RefreshPacketCount = 1000
		}
		var writer wire.ContractWriter
		if protocol == wire.ProtocolIPFIX {
			writer = ipfix.Writer{}
		} else {
			writer = netflow9.Writer{}
		}
		state, err = NewState(compiled, writer, stateConfig)
		if err != nil {
			t.Fatal(err)
		}
		bootstrap(t, state, 3_000_000_000, 1)
	}
	logs := testpdata.CanonicalLogs()
	testpdata.CanonicalIPv6Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).CopyTo(logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().AppendEmpty())
	capture := new(packingFuzzCapture)
	packer := newPackingFuzzPacker(t, state, capture, nil, nil)
	result, err := packer.Pack(context.Background(), logs, nil)
	if err != nil || result.Outcome() != PackSucceeded {
		t.Fatalf("shape flush %s pack=(%d,%v), counts=%+v", protocol, result.Outcome(), err, result.Counts())
	}
	assertPackingLedger(t, result, packingClasses(2, SourceConfirmed))
	if len(capture.packets) != 2 {
		t.Fatalf("shape flush packets=%d want 2", len(capture.packets))
	}
	for index, packet := range capture.packets {
		wantVersion := uint16(9)
		if protocol == wire.ProtocolIPFIX {
			wantVersion = 10
		}
		if binary.BigEndian.Uint16(packet[0:2]) != wantVersion {
			t.Fatalf("shape flush packet %d version=%d", index, binary.BigEndian.Uint16(packet[0:2]))
		}
		offset := 24
		if protocol == wire.ProtocolIPFIX {
			offset = 20
		}
		address := []byte{192, 0, 2, 1}
		if index == 1 {
			address = []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		}
		if len(packet) != offset+len(address) || !bytes.Equal(packet[offset:], address) {
			t.Fatal("shape packet has incorrect address or length")
		}
		wantID := uint16(256 + index)
		if protocol == wire.ProtocolV9 && binary.BigEndian.Uint16(packet[20:22]) != wantID {
			t.Fatalf("shape flush v9 packet %d set id=%d want %d", index, binary.BigEndian.Uint16(packet[20:22]), wantID)
		}
		if protocol == wire.ProtocolIPFIX && binary.BigEndian.Uint16(packet[16:18]) != wantID {
			t.Fatalf("shape flush ipfix packet %d set id=%d want %d", index, binary.BigEndian.Uint16(packet[16:18]), wantID)
		}
	}
}

// These helpers keep the shape-switch scenario's IPFIX setup independent of
// the production State/packer path while avoiding a second mapping grammar.
func mappingShapeSwitchConfig(protocol wire.Protocol) mapping.Config {
	return mapping.Config{
		Protocol:        protocol,
		Fields:          []mapping.FieldSelection{{Canonical: "source.address"}},
		LossPolicy:      mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize: 65507,
		PathMTU:         65535,
		Endpoint:        "192.0.2.1:4739",
	}
}

func packingFuzzInvalidSibling(t *testing.T, protocol wire.Protocol, countByte, valueByte uint8) {
	t.Helper()
	count := 3 + int(countByte%3)
	invalid := int(valueByte % uint8(count))
	state := packingFuzzState(t, protocol, uint16(count+1), 464)
	logs := packingFuzzLogs(t, protocol, count, invalid)
	capture := new(packingFuzzCapture)
	packer := newPackingFuzzPacker(t, state, capture, nil, nil)
	result, err := packer.Pack(context.Background(), logs, nil)
	if err != nil || result.Outcome() != PackSucceeded {
		t.Fatalf("invalid sibling %s pack=(%d,%v), counts=%+v", protocol, result.Outcome(), err, result.Counts())
	}
	wantClasses := packingClasses(count, SourceConfirmed)
	wantClasses[invalid] = SourceInvalid
	assertPackingLedger(t, result, wantClasses)
	wantPorts := make([]uint16, 0, count-1)
	for i := 0; i < count; i++ {
		if i != invalid {
			wantPorts = append(wantPorts, uint16(10000+i))
		}
	}
	assertPackingPackets(t, protocol, capture.packets, wantPorts)
	if capture.attempts != len(capture.packets) || len(capture.packets) == 0 {
		t.Fatalf("invalid sibling attempts/packets=%d/%d", capture.attempts, len(capture.packets))
	}
}

func packingFuzzWriteOutcome(t *testing.T, protocol wire.Protocol, outcomeByte, valueByte uint8) {
	t.Helper()
	// One-record packets force a confirmed prefix before the selected outcome.
	// The invalid ordinal sits in a gap, so the expected ledger is authored
	// from source order rather than inferred from packet counts.
	count := 5
	invalid := 1 + int(valueByte%3)
	state := packingFuzzState(t, protocol, 1, 464)
	logs := packingFuzzLogs(t, protocol, count, invalid)
	capture := &packingFuzzCapture{mode: outcomeByte, firstFull: true}
	packer := newPackingFuzzPacker(t, state, capture, nil, nil)
	beforeSequence := state.Sequence()
	result, err := packer.Pack(context.Background(), logs, nil)
	mode := outcomeByte % 8
	wantPorts := []uint16{10000}
	for ordinal := 1; ordinal < count; ordinal++ {
		if ordinal == invalid {
			continue
		}
		wantPorts = append(wantPorts, uint16(10000+ordinal))
	}
	switch mode {
	case 0:
		if capture.attempts != len(wantPorts) || len(capture.packets) != len(wantPorts) {
			t.Fatalf("full outcome attempts/packets=%d/%d want %d", capture.attempts, len(capture.packets), len(wantPorts))
		}
		if err != nil || result.Outcome() != PackSucceeded {
			t.Fatalf("full outcome=(%d,%v)", result.Outcome(), err)
		}
		wantClasses := packingClasses(count, SourceConfirmed)
		wantClasses[invalid] = SourceInvalid
		assertPackingLedger(t, result, wantClasses)
		assertPackingPackets(t, protocol, capture.packets, wantPorts)
		wantSequence := beforeSequence + uint32(len(wantPorts))
		if state.Sequence() != wantSequence {
			t.Fatalf("full outcome sequence=%d want %d", state.Sequence(), wantSequence)
		}
	case 6, 7:
		if capture.attempts != 2 || len(capture.packets) != 2 {
			t.Fatalf("invalid outcome mode=%d attempts/packets=%d/%d", mode, capture.attempts, len(capture.packets))
		}
		if !errors.Is(err, ErrPackInternal) || result.Outcome() != PackInternal {
			t.Fatalf("invalid outcome=(%d,%v) sequence=%d/%d", result.Outcome(), err, state.Sequence(), beforeSequence)
		}
		wantClasses := packingClasses(count, SourceUnsentValid)
		wantClasses[0] = SourceConfirmed
		wantClasses[invalid] = SourceInvalid
		assertPackingLedger(t, result, wantClasses)
		assertPackingPackets(t, protocol, capture.packets, wantPorts[:2])
		if state.Sequence() != beforeSequence+1 {
			t.Fatalf("invalid outcome sequence=%d want %d", state.Sequence(), beforeSequence+1)
		}
	default:
		if capture.attempts != 2 || len(capture.packets) != 2 {
			t.Fatalf("ambiguous outcome mode=%d attempts/packets=%d/%d", mode, capture.attempts, len(capture.packets))
		}
		if !errors.Is(err, ErrPackTransient) || result.Outcome() != PackTransient {
			t.Fatalf("ambiguous outcome=%d result=(%d,%v) sequence=%d/%d", mode, result.Outcome(), err, state.Sequence(), beforeSequence)
		}
		wantClasses := packingClasses(count, SourceUnsentValid)
		wantClasses[0] = SourceConfirmed
		wantClasses[invalid] = SourceInvalid
		ambiguousOrdinal := 1
		if ambiguousOrdinal == invalid {
			ambiguousOrdinal++
		}
		wantClasses[ambiguousOrdinal] = SourceAmbiguous
		assertPackingLedger(t, result, wantClasses)
		assertPackingPackets(t, protocol, capture.packets, wantPorts[:2])
		if state.Sequence() != beforeSequence+1 {
			t.Fatalf("ambiguous outcome sequence=%d want %d", state.Sequence(), beforeSequence+1)
		}
	}
	assertFixedPackingError(t, err)
}

func packingFuzzCancellation(t *testing.T, protocol wire.Protocol, valueByte uint8) {
	t.Helper()
	state := packingFuzzState(t, protocol, 4, 464)
	count := 2 + int(valueByte%3)
	logs := packingFuzzLogs(t, protocol, count, -1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	capture := new(packingFuzzCapture)
	packer := newPackingFuzzPacker(t, state, capture, nil, nil)
	beforeSequence := state.Sequence()
	result, err := packer.Pack(ctx, logs, nil)
	if !errors.Is(err, ErrPackTransient) || result.Outcome() != PackTransient {
		t.Fatalf("canceled result=(%d,%v)", result.Outcome(), err)
	}
	assertPackingLedger(t, result, packingClasses(count, SourceUnsentValid))
	if capture.attempts != 0 || result.Packets() != 0 || state.Sequence() != beforeSequence {
		t.Fatalf("canceled writes/packets/sequence=%d/%d/%d/%d", capture.attempts, result.Packets(), state.Sequence(), beforeSequence)
	}
	assertFixedPackingError(t, err)
}

func packingFuzzMalformed(t *testing.T, protocol wire.Protocol) {
	t.Helper()
	state := packingFuzzState(t, protocol, 4, 464)
	var logs plog.Logs
	capture := new(packingFuzzCapture)
	packer := newPackingFuzzPacker(t, state, capture, nil, nil)
	beforeSequence := state.Sequence()
	lookupCalls := 0
	result, err := packer.Pack(context.Background(), logs, func(uint64, string) (wire.Value, bool) {
		lookupCalls++
		return wire.Value{}, false
	})
	if !errors.Is(err, ErrPackAdmission) || result.Outcome() != PackPermanent {
		t.Fatalf("malformed result=(%d,%v)", result.Outcome(), err)
	}
	if got := result.Counts(); got.Covered != 0 || got.Valid != 0 || got.Invalid != 0 || got.Confirmed != 0 {
		t.Fatalf("malformed ledger = %+v, want empty", got)
	}
	if lookupCalls != 0 || capture.attempts != 0 || result.Packets() != 0 || state.Sequence() != beforeSequence {
		t.Fatalf("malformed callbacks/writes/packets/sequence=%d/%d/%d/%d", lookupCalls, capture.attempts, result.Packets(), state.Sequence())
	}
	assertFixedPackingError(t, err)
}

func packingFuzzOversize(t *testing.T, valueByte uint8) {
	t.Helper()
	state := customPackerState(t, true, 128, 0, 2)
	logs := packingFuzzLogs(t, wire.ProtocolIPFIX, 2, -1)
	longLength := 120 + int(valueByte%40)
	longValue := strings.Repeat("x", longLength)
	capture := new(packingFuzzCapture)
	packer := newPackingFuzzPacker(t, state, capture, nil, nil)
	result, err := packer.Pack(context.Background(), logs, func(ordinal uint64, _ string) (wire.Value, bool) {
		if ordinal == 0 {
			return wire.StringValue(longValue), true
		}
		return wire.StringValue("x"), true
	})
	if err != nil || result.Outcome() != PackSucceeded {
		t.Fatalf("oversize result=(%d,%v), counts=%+v", result.Outcome(), err, result.Counts())
	}
	want := []SourceClass{SourceInvalid, SourceConfirmed}
	assertPackingLedger(t, result, want)
	if capture.attempts != 1 || len(capture.packets) != 1 || state.Sequence() != 1 {
		t.Fatalf("oversize attempts/packets/sequence=%d/%d/%d", capture.attempts, len(capture.packets), state.Sequence())
	}
	packet := capture.packets[0]
	if len(packet) != 24 || binary.BigEndian.Uint16(packet[0:2]) != 10 || binary.BigEndian.Uint16(packet[2:4]) != 24 || binary.BigEndian.Uint16(packet[16:18]) != 256 || binary.BigEndian.Uint16(packet[18:20]) != 8 || binary.BigEndian.Uint16(packet[20:22]) != 10001 || packet[22] != 1 || packet[23] != 'x' {
		t.Fatalf("oversize surviving packet has unexpected bytes/length: len=%d version=%d message=%d set=%d/%d port=%d custom=%x", len(packet), binary.BigEndian.Uint16(packet[0:2]), binary.BigEndian.Uint16(packet[2:4]), binary.BigEndian.Uint16(packet[16:18]), binary.BigEndian.Uint16(packet[18:20]), binary.BigEndian.Uint16(packet[20:22]), packet[22:])
	}
	assertFixedPackingError(t, err)
}

func packingClasses(count int, class SourceClass) []SourceClass {
	classes := make([]SourceClass, count)
	for i := range classes {
		classes[i] = class
	}
	return classes
}

func assertPackingLedger(t *testing.T, result *PackResult, want []SourceClass) {
	t.Helper()
	if result == nil {
		t.Fatal("nil pack result")
	}
	if result.Classification(uint64(len(want))) != SourceUncovered {
		t.Fatal("ledger covers a nonexistent source")
	}
	counts := result.Counts()
	if counts.Covered != uint64(len(want)) {
		t.Fatalf("ledger covered=%d want %d", counts.Covered, len(want))
	}
	var valid, invalid, unsent, confirmed, ambiguous uint64
	for ordinal, expected := range want {
		if got := result.Classification(uint64(ordinal)); got != expected {
			t.Fatalf("ledger ordinal %d=%d want %d", ordinal, got, expected)
		}
		switch expected {
		case SourceUnsentValid:
			valid++
			unsent++
		case SourceConfirmed:
			valid++
			confirmed++
		case SourceInvalid:
			invalid++
		case SourceAmbiguous:
			valid++
			ambiguous++
		}
	}
	if counts.Valid != valid || counts.Invalid != invalid || counts.Unsent != unsent || counts.Confirmed != confirmed || counts.Ambiguous != ambiguous || counts.Pending != 0 || counts.PacketOpen {
		t.Fatalf("ledger counts=%+v want valid/invalid/unsent/confirmed/ambiguous=%d/%d/%d/%d/%d", counts, valid, invalid, unsent, confirmed, ambiguous)
	}
}

func assertPackingPackets(t *testing.T, protocol wire.Protocol, packets [][]byte, wantPorts []uint16) {
	t.Helper()
	wantVersion := uint16(protocol)
	if protocol == wire.ProtocolV5 {
		wantVersion = 5
	} else if protocol == wire.ProtocolV9 {
		wantVersion = 9
	} else if protocol == wire.ProtocolIPFIX {
		wantVersion = 10
	}
	portIndex := 0
	for packetIndex, packet := range packets {
		if len(packet) < 2 || binary.BigEndian.Uint16(packet[0:2]) != wantVersion {
			t.Fatalf("packet %d version/length=%d/%d want version %d", packetIndex, len(packet), binary.BigEndian.Uint16(packet[0:2]), wantVersion)
		}
		var count, dataOffset, recordWidth int
		switch protocol {
		case wire.ProtocolV5:
			if len(packet) < 24 {
				t.Fatalf("v5 packet %d length=%d", packetIndex, len(packet))
			}
			count, dataOffset, recordWidth = int(binary.BigEndian.Uint16(packet[2:4])), 24, 48
			if len(packet) != dataOffset+count*recordWidth {
				t.Fatalf("v5 packet %d length=%d want %d", packetIndex, len(packet), dataOffset+count*recordWidth)
			}
		case wire.ProtocolV9:
			if len(packet) < 24 {
				t.Fatalf("v9 packet %d length=%d", packetIndex, len(packet))
			}
			count, dataOffset, recordWidth = int(binary.BigEndian.Uint16(packet[2:4])), 24, 2
			if int(binary.BigEndian.Uint16(packet[22:24])) != len(packet)-20 || len(packet) != dataOffset+count*recordWidth {
				t.Fatalf("v9 packet %d set/length/count=%d/%d/%d", packetIndex, binary.BigEndian.Uint16(packet[22:24]), len(packet), count)
			}
		case wire.ProtocolIPFIX:
			if len(packet) < 20 {
				t.Fatalf("ipfix packet %d length=%d", packetIndex, len(packet))
			}
			dataSetLength := int(binary.BigEndian.Uint16(packet[18:20]))
			if int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || dataSetLength != len(packet)-16 {
				t.Fatalf("ipfix packet %d header/set length=%d/%d want %d/%d", packetIndex, binary.BigEndian.Uint16(packet[2:4]), dataSetLength, len(packet), len(packet)-16)
			}
			count, dataOffset, recordWidth = (dataSetLength-4)/2, 20, 2
			if count < 1 || len(packet) != dataOffset+count*recordWidth {
				t.Fatalf("ipfix packet %d length/count=%d/%d", packetIndex, len(packet), count)
			}
		}
		if count < 1 {
			t.Fatalf("packet %d has no records", packetIndex)
		}
		for record := 0; record < count; record++ {
			if portIndex >= len(wantPorts) {
				t.Fatalf("packet %d contains an unexpected record", packetIndex)
			}
			offset := dataOffset + record*recordWidth
			var got uint16
			if protocol == wire.ProtocolV5 {
				if string(packet[offset:offset+4]) != string([]byte{192, 0, 2, 1}) || string(packet[offset+4:offset+8]) != string([]byte{198, 51, 100, 2}) {
					t.Fatalf("v5 packet %d record %d addresses=%x/%x", packetIndex, record, packet[offset:offset+4], packet[offset+4:offset+8])
				}
				got = binary.BigEndian.Uint16(packet[offset+32 : offset+34])
				if binary.BigEndian.Uint16(packet[offset+34:offset+36]) != 443 || binary.BigEndian.Uint32(packet[offset+16:offset+20]) != 1234 || binary.BigEndian.Uint32(packet[offset+20:offset+24]) != 56789 {
					t.Fatalf("v5 packet %d record %d fixed values mismatch", packetIndex, record)
				}
			} else {
				got = binary.BigEndian.Uint16(packet[offset : offset+2])
			}
			if got != wantPorts[portIndex] {
				t.Fatalf("packet %d record %d source port=%d want %d", packetIndex, record, got, wantPorts[portIndex])
			}
			portIndex++
		}
	}
	if portIndex != len(wantPorts) {
		t.Fatalf("packet records=%d want %d", portIndex, len(wantPorts))
	}
}

func assertFixedPackingError(t *testing.T, err error) {
	t.Helper()
	switch err {
	case nil, ErrPackPermanent, ErrPackTransient, ErrPackInternal, ErrPackAdmission:
	default:
		t.Fatal("packer returned a non-fixed diagnostic")
	}
}
