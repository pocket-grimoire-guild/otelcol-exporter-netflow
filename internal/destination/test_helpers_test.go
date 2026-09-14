package destination

import (
	"net/netip"
	"strconv"
	"sync"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

type recordingWriter struct {
	mu       sync.Mutex
	requests []wire.PacketRequest
	writeErr error
}

func (w *recordingWriter) Write(dst []byte, request wire.PacketRequest) (int, error) {
	w.mu.Lock()
	w.requests = append(w.requests, request)
	err := w.writeErr
	w.mu.Unlock()
	if err != nil {
		return len(dst), err
	}
	return len(dst), nil
}

type shortPureWriter struct{}

func (shortPureWriter) Write(dst []byte, _ wire.PacketRequest) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	return len(dst) - 1, nil
}

func compiledMapping(t *testing.T, protocol wire.Protocol) mapping.CompiledMapping {
	t.Helper()
	config := mapping.Config{
		Protocol:        protocol,
		LossPolicy:      mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize: 65507,
		PathMTU:         65535,
		Endpoint:        "192.0.2.1:4739",
	}
	config.ProtocolIdentifiers = []mapping.ProtocolIdentifier{{Token: "tcp", Number: 6}}
	switch protocol {
	case wire.ProtocolV5:
		config.Profile = mapping.ProfileV5
		config.InputGuarantees.FlowIOBytes = "layer3_total_octets"
		config.HasUptimeOrigin = true
	case wire.ProtocolV9:
		config.Profile = mapping.ProfileV9
		config.NetworkTypeVersions = []mapping.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
	case wire.ProtocolIPFIX:
		config.Profile = mapping.ProfileIPFIX
		config.NetworkTypeVersions = []mapping.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
	}
	compiled, err := mapping.Compile(config)
	if err != nil {
		t.Fatalf("compile %s: %v", protocol, err)
	}
	return compiled
}

func tinyCompiledMapping(t *testing.T, protocol wire.Protocol) mapping.CompiledMapping {
	t.Helper()
	config := mapping.Config{
		Protocol:        protocol,
		Fields:          []mapping.FieldSelection{{Canonical: "source.port"}},
		LossPolicy:      mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize: 65507,
		PathMTU:         65535,
		Endpoint:        "192.0.2.1:4739",
	}
	compiled, err := mapping.Compile(config)
	if err != nil {
		t.Fatalf("compile tiny %s: %v", protocol, err)
	}
	return compiled
}

func customPENMapping(t *testing.T, count int) (mapping.CompiledMapping, error) {
	t.Helper()
	config := mapping.Config{
		Protocol:        wire.ProtocolIPFIX,
		Fields:          []mapping.FieldSelection{{Canonical: "source.port"}},
		LossPolicy:      mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize: 65507,
		PathMTU:         65535,
		Endpoint:        "192.0.2.1:4739",
		Custom:          make([]mapping.CustomField, count),
	}
	for i := range config.Custom {
		pen, elementID, fixedLength := uint32(i+1), uint32(i+1), uint16(1)
		config.Custom[i] = mapping.CustomField{
			Source:      "vendor." + strconv.Itoa(i),
			PEN:         &pen,
			ElementID:   &elementID,
			Encoding:    "unsigned8",
			FixedLength: &fixedLength,
		}
	}
	return mapping.Compile(config)
}

func stateFor(t *testing.T, protocol wire.Protocol, mutate func(*Config)) (*State, *recordingWriter) {
	t.Helper()
	compiled := compiledMapping(t, protocol)
	writer := new(recordingWriter)
	config := DefaultConfig(protocol)
	if protocol == wire.ProtocolV9 {
		config.SourceID = 42
		config.ObservationDomainID = 42
	} else if protocol == wire.ProtocolIPFIX {
		config.ObservationDomainID = 42
	}
	config.HasUptimeOrigin = protocol == wire.ProtocolV5
	if protocol == wire.ProtocolV5 {
		config.ObservationDomainID = 0
	}
	if mutate != nil {
		mutate(&config)
	}
	state, err := NewState(compiled, writer, config)
	if err != nil {
		t.Fatalf("new state %s: %v", protocol, err)
	}
	return state, writer
}

func testRecord(t *testing.T, shape wire.Shape, instant uint64) wire.WireRecord {
	t.Helper()
	values := make([]wire.Value, shape.FieldCount())
	addr4 := netip.MustParseAddr("192.0.2.1")
	addr6 := netip.MustParseAddr("2001:db8::1")
	for i := 0; i < shape.FieldCount(); i++ {
		d, ok := shape.DescriptorAt(i)
		if !ok {
			t.Fatalf("descriptor %d missing", i)
		}
		switch d.Encoding {
		case wire.EncodingIPv4Address:
			values[i] = wire.IPValue(addr4)
		case wire.EncodingIPv6Address:
			values[i] = wire.IPValue(addr6)
		case wire.EncodingMACAddress:
			values[i] = wire.MACValue([6]byte{0, 1, 2, 3, 4, 5})
		case wire.EncodingString, wire.EncodingOctetArray:
			values[i] = wire.StringValue("")
		case wire.EncodingDateTimeNanoseconds:
			values[i] = wire.UnixNanosValue(instant)
		default:
			if d.Constant {
				values[i] = wire.UintValue(0)
			} else if d.Field == wire.FieldFlowStart || d.Field == wire.FieldFlowEnd || d.Field == wire.FieldFlowTimeReceived {
				values[i] = wire.UnixNanosValue(instant)
			} else {
				values[i] = wire.UintValue(1)
			}
		}
	}
	record, err := wire.NewWireRecord(shape.Family(), values)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	return record
}

func commitFull(t *testing.T, state *State, packet Packet) CommitResult {
	t.Helper()
	n, err := encodePacket(t, packet)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	result, err := state.Commit(packet, n, nil)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	return result
}

func encodePacket(t *testing.T, packet Packet) (int, error) {
	t.Helper()
	buffer := make([]byte, packet.DatagramLength())
	return packet.Encode(buffer)
}

func bootstrap(t *testing.T, state *State, wall, mono uint64) {
	t.Helper()
	for round := 0; round < int(state.Config().InitialCopies); round++ {
		for shape := 0; shape < state.Catalog().ShapeCount(); shape++ {
			packet, err := state.BeginTemplate(wall, mono, shape)
			if err != nil {
				t.Fatalf("bootstrap round=%d shape=%d: %v", round, shape, err)
			}
			commitFull(t, state, packet)
		}
	}
}
