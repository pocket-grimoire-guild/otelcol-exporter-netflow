package destination

import (
	"errors"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/ipfix"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow5"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow9"
)

func TestStateDefaultsAndProtocolBoundaries(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV5, wire.ProtocolV9, wire.ProtocolIPFIX} {
		t.Run(protocol.String(), func(t *testing.T) {
			state, _ := stateFor(t, protocol, nil)
			config := state.Config()
			wantRecords := uint16(256)
			if protocol == wire.ProtocolV5 {
				wantRecords = 30
			}
			if config.MaxDatagramSize != 464 || config.InitialCopies != 2 || config.RefreshInterval != 10*time.Minute || config.MaxRecordsPerMessage != wantRecords {
				t.Fatalf("defaults=%+v", config)
			}
			if protocol == wire.ProtocolV5 && !state.Ready() {
				t.Fatal("v5 must not wait for templates")
			}
			if protocol != wire.ProtocolV5 && state.Ready() {
				t.Fatal("template protocol became ready before bootstrap")
			}
		})
	}

	for _, tc := range []struct {
		name  string
		value time.Duration
		valid bool
	}{
		{"zero_default", 0, true},
		{"below_minimum", 30*time.Second - time.Nanosecond, false},
		{"minimum", 30 * time.Second, true},
		{"one_minute", time.Minute, true},
		{"default", 10 * time.Minute, true},
		{"maximum", 24 * time.Hour, true},
		{"above_maximum", 24*time.Hour + time.Nanosecond, false},
	} {
		t.Run("refresh-"+tc.name, func(t *testing.T) {
			config := DefaultConfig(wire.ProtocolIPFIX)
			config.MaxDatagramSize = 65507
			config.ObservationDomainID = 42
			config.RefreshInterval = tc.value
			state, err := NewState(compiledMapping(t, wire.ProtocolIPFIX), &recordingWriter{}, config)
			if (err == nil) != tc.valid {
				t.Fatalf("refresh interval %v valid=%v err=%v", tc.value, tc.valid, err)
			}
			if tc.valid {
				want := tc.value
				if want == 0 {
					want = 10 * time.Minute
				}
				if got := state.Config().RefreshInterval; got != want {
					t.Fatalf("normalized refresh interval=%v, want %v", got, want)
				}
			}
		})
	}

	for _, size := range []struct {
		value uint64
		valid bool
	}{
		{127, false}, {128, true}, {464, true}, {65507, true}, {65508, false},
	} {
		_, err := NewState(compiledMapping(t, wire.ProtocolIPFIX), &recordingWriter{}, Config{
			Protocol: wire.ProtocolIPFIX, MaxDatagramSize: size.value,
		})
		if (err == nil) != size.valid {
			t.Fatalf("payload %d valid=%v err=%v", size.value, size.valid, err)
		}
	}
}

func TestStateRejectsMappingOriginMismatch(t *testing.T) {
	const (
		mappingOrigin = uint64(3_000_000_000)
		otherOrigin   = uint64(4_000_000_000)
	)

	v5Config := mapping.Config{
		Protocol:              wire.ProtocolV5,
		Profile:               mapping.ProfileV5,
		ProtocolIdentifiers:   []mapping.ProtocolIdentifier{{Token: "tcp", Number: 6}},
		LossPolicy:            mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize:       65507,
		PathMTU:               65535,
		Endpoint:              "192.0.2.1:4739",
		InputGuarantees:       mapping.InputGuarantees{FlowIOBytes: "layer3_total_octets"},
		HasUptimeOrigin:       true,
		UptimeOriginUnixNanos: mappingOrigin,
	}
	v5Mapping, err := mapping.Compile(v5Config)
	if err != nil {
		t.Fatalf("compile v5 mapping: %v", err)
	}
	v5StateConfig := DefaultConfig(wire.ProtocolV5)
	v5StateConfig.MaxDatagramSize = 65507
	v5StateConfig.HasUptimeOrigin, v5StateConfig.UptimeOriginUnixNanos = true, otherOrigin
	if _, err := NewState(v5Mapping, netflow5.Writer{}, v5StateConfig); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("v5 mismatched origin err=%v", err)
	}
	v5StateConfig.UptimeOriginUnixNanos = mappingOrigin
	if _, err := NewState(v5Mapping, netflow5.Writer{}, v5StateConfig); err != nil {
		t.Fatalf("v5 matching origin: %v", err)
	}

	relativeConfig := mapping.Config{
		Protocol:              wire.ProtocolV9,
		Fields:                []mapping.FieldSelection{{Canonical: "source.address"}, {Canonical: "flow.start"}, {Canonical: "flow.end"}},
		LossPolicy:            mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize:       65507,
		PathMTU:               65535,
		Endpoint:              "192.0.2.1:4739",
		HasUptimeOrigin:       true,
		UptimeOriginUnixNanos: mappingOrigin,
	}
	relativeMapping, err := mapping.Compile(relativeConfig)
	if err != nil {
		t.Fatalf("compile v9 relative mapping: %v", err)
	}
	for _, tc := range []struct {
		name   string
		set    bool
		origin uint64
	}{
		{name: "missing", origin: mappingOrigin},
		{name: "different", set: true, origin: otherOrigin},
	} {
		t.Run("v9-"+tc.name, func(t *testing.T) {
			config := DefaultConfig(wire.ProtocolV9)
			config.MaxDatagramSize = 65507
			config.SourceID, config.ObservationDomainID = 42, 42
			config.HasUptimeOrigin, config.UptimeOriginUnixNanos = tc.set, tc.origin
			if _, err := NewState(relativeMapping, netflow9.Writer{}, config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("origin config=%+v err=%v", config, err)
			}
		})
	}

	config := DefaultConfig(wire.ProtocolV9)
	config.MaxDatagramSize = 65507
	config.SourceID, config.ObservationDomainID = 42, 42
	config.HasUptimeOrigin, config.UptimeOriginUnixNanos = true, mappingOrigin
	state, err := NewState(relativeMapping, netflow9.Writer{}, config)
	if err != nil {
		t.Fatalf("matching v9 origin: %v", err)
	}
	bootstrap(t, state, mappingOrigin, 0)
	shape := mustShape(t, state, 0)
	packet, err := state.BeginData(mappingOrigin+1_000_000, 1, 0, DataRequest{Records: []wire.WireRecord{testRecord(t, shape, mappingOrigin+1_000_000)}})
	if err != nil {
		t.Fatalf("matching v9 data: %v", err)
	}
	if got := packet.request.Header.UptimeOriginUnixNanos; got != mappingOrigin {
		t.Fatalf("data origin=%d, want %d", got, mappingOrigin)
	}
	commitFull(t, state, packet)
	shape, _ = state.Catalog().ShapeAt(1)
	packet, err = state.BeginData(mappingOrigin+1_000_000, 2, 1, DataRequest{Records: []wire.WireRecord{testRecord(t, shape, mappingOrigin+1_000_000)}})
	if err != nil {
		t.Fatalf("matching v9 IPv6 data: %v", err)
	}
	commitFull(t, state, packet)

	candidate, _ := stateFor(t, wire.ProtocolV9, func(config *Config) { config.MaxDatagramSize = 65507 })
	if _, has := candidate.Mapping().UptimeOrigin(); has {
		t.Fatal("no-relative v9 mapping unexpectedly exposed an origin")
	}
	packet, err = candidate.BeginTemplate(mappingOrigin+123, 1, 0)
	if err != nil {
		t.Fatalf("candidate template: %v", err)
	}
	if got := packet.request.Header.UptimeOriginUnixNanos; got != mappingOrigin+123 {
		t.Fatalf("candidate origin=%d, want %d", got, mappingOrigin+123)
	}
}

func TestStateV5DataCommitAndValidation(t *testing.T) {
	state, _ := stateFor(t, wire.ProtocolV5, func(config *Config) {
		config.UptimeOriginUnixNanos = 0
		config.MaxRecordsPerMessage = 30
	})
	shape, _ := state.Catalog().ShapeAt(0)
	record := testRecord(t, shape, 1_000_000)
	packet, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{Records: []wire.WireRecord{record}, V5SamplingRates: []uint32{0}})
	if err != nil {
		t.Fatal(err)
	}
	if packet.Sequence() != 0 || packet.request.Header.Count != 1 {
		t.Fatalf("request sequence/count=%d/%d", packet.Sequence(), packet.request.Header.Count)
	}
	n, err := packet.Encode(make([]byte, packet.DatagramLength()))
	if err != nil || uint64(n) != packet.DatagramLength() {
		t.Fatalf("encode=(%d,%v)", n, err)
	}
	result, err := state.Commit(packet, n, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Committed || result.SequenceBefore != 0 || result.SequenceAfter != 1 || state.Sequence() != 1 {
		t.Fatalf("commit=%+v state-seq=%d", result, state.Sequence())
	}
	if _, err := state.BeginData(3_001_000_000, 2, 0, DataRequest{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty v5 data err=%v", err)
	}
	if _, err := state.BeginData(3_001_000_000, 2, 0, DataRequest{Records: []wire.WireRecord{record, record}, V5SamplingRates: []uint32{0, 0}}); err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, mustPending(t, state))
}

func TestStateV5RecordDerivedSampling(t *testing.T) {
	state, _ := stateFor(t, wire.ProtocolV5, func(config *Config) {
		config.MaxDatagramSize = 65507
		config.SamplingMode = 2
		config.UptimeOriginUnixNanos = 0
	})
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, 1_000_000)
	packet, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{Records: []wire.WireRecord{record}, V5SamplingRates: []uint32{0}})
	if err != nil {
		t.Fatal(err)
	}
	if packet.request.Header.SamplingMode != 2 || packet.request.Header.SamplingInterval != 0 {
		t.Fatalf("zero sampling header=%+v", packet.request.Header)
	}
	commitFull(t, state, packet)
	packet, err = state.BeginData(3_000_000_000, 2, 0, DataRequest{Records: []wire.WireRecord{record, record}, V5SamplingRates: []uint32{16383, 16383}})
	if err != nil {
		t.Fatal(err)
	}
	if packet.request.Header.SamplingInterval != 16383 {
		t.Fatalf("common sampling rate=%d", packet.request.Header.SamplingInterval)
	}
	commitFull(t, state, packet)
	for name, request := range map[string]DataRequest{
		"unequal":  {Records: []wire.WireRecord{record, record}, V5SamplingRates: []uint32{1, 2}},
		"overflow": {Records: []wire.WireRecord{record}, V5SamplingRates: []uint32{16384}},
		"missing":  {Records: []wire.WireRecord{record}},
	} {
		if _, err := state.BeginData(9_000_000_000, 3, 0, request); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s sampling err=%v", name, err)
		}
	}
	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		state, _ := stateFor(t, protocol, func(config *Config) { config.MaxDatagramSize = 65507 })
		if protocol != wire.ProtocolV5 {
			bootstrap(t, state, 3_000_000_000, 0)
		}
		shape := mustShape(t, state, 0)
		request := DataRequest{Records: []wire.WireRecord{testRecord(t, shape, 3_000_000_000)}, V5SamplingRates: []uint32{1}}
		if _, err := state.BeginData(3_000_000_000, 1, 0, request); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s header sampling err=%v", protocol, err)
		}
	}
}

func TestStateExactRecordBoundaries(t *testing.T) {
	v5, _ := stateFor(t, wire.ProtocolV5, func(config *Config) {
		config.MaxDatagramSize = 65507
		config.MaxRecordsPerMessage = 30
		config.UptimeOriginUnixNanos = 0
	})
	shape := mustShape(t, v5, 0)
	record := testRecord(t, shape, 1_000_000)
	if _, err := v5.BeginData(3_000_000_000, 1, 0, DataRequest{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("v5 zero records err=%v", err)
	}
	for _, count := range []int{1, 30} {
		records := make([]wire.WireRecord, count)
		rates := make([]uint32, count)
		for i := range records {
			records[i] = record
		}
		packet, err := v5.BeginData(3_000_000_000, uint64(count+1), 0, DataRequest{Records: records, V5SamplingRates: rates})
		if err != nil {
			t.Fatalf("v5 records=%d: %v", count, err)
		}
		commitFull(t, v5, packet)
	}
	records := make([]wire.WireRecord, 31)
	rates := make([]uint32, 31)
	for i := range records {
		records[i] = record
	}
	if _, err := v5.BeginData(3_000_000_000, 40, 0, DataRequest{Records: records, V5SamplingRates: rates}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("v5 records=31 err=%v", err)
	}

	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		compiled := tinyCompiledMapping(t, protocol)
		config := DefaultConfig(protocol)
		config.MaxDatagramSize = 65507
		config.MaxRecordsPerMessage = 1024
		if protocol == wire.ProtocolV9 {
			config.SourceID, config.ObservationDomainID = 42, 42
		} else {
			config.ObservationDomainID = 42
		}
		state, err := NewState(compiled, &recordingWriter{}, config)
		if err != nil {
			t.Fatalf("new %s boundary state: %v", protocol, err)
		}
		bootstrap(t, state, 3_000_000_000, 0)
		shape := mustShape(t, state, 0)
		record := testRecord(t, shape, 3_000_000_000)
		records := make([]wire.WireRecord, 1024)
		for i := range records {
			records[i] = record
		}
		packet, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{Records: records})
		if err != nil {
			t.Fatalf("%s records=1024: %v", protocol, err)
		}
		commitFull(t, state, packet)
		records = append(records, record)
		if _, err := state.BeginData(3_000_000_000, 2, 0, DataRequest{Records: records}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s records=1025 err=%v", protocol, err)
		}
	}
}

func TestStateConstructorBudgetAndPENBoundaries(t *testing.T) {
	for _, count := range []int{31, 32} {
		compiled, err := customPENMapping(t, count)
		if err != nil {
			t.Fatalf("compile %d PENs: %v", count, err)
		}
		if _, err := NewState(compiled, &recordingWriter{}, Config{Protocol: wire.ProtocolIPFIX, MaxDatagramSize: 65507}); err != nil {
			t.Fatalf("%d-PEN state: %v", count, err)
		}
	}
	compiled, err := customPENMapping(t, 32)
	if err != nil {
		t.Fatalf("compile 32 PENs: %v", err)
	}
	if _, err := NewState(compiled, &recordingWriter{}, Config{Protocol: wire.ProtocolIPFIX, MaxDatagramSize: 128}); !errors.Is(err, wire.ErrBounds) {
		t.Fatalf("budget-mismatched state err=%v", err)
	}
	if _, err := NewState(compiled, &recordingWriter{}, Config{Protocol: wire.ProtocolIPFIX, MaxDatagramSize: 65507}); err != nil {
		t.Fatalf("large budget state: %v", err)
	}
	if _, err := customPENMapping(t, 33); err == nil {
		t.Fatal("mapping compiler accepted 33 distinct PENs")
	}
}

func TestStateRealWriterRequests(t *testing.T) {
	tests := []struct {
		name     string
		protocol wire.Protocol
		writer   wire.ContractWriter
	}{
		{"v5", wire.ProtocolV5, netflow5.Writer{}},
		{"v9", wire.ProtocolV9, netflow9.Writer{}},
		{"ipfix", wire.ProtocolIPFIX, ipfix.Writer{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			compiled := compiledMapping(t, tc.protocol)
			config := DefaultConfig(tc.protocol)
			config.MaxDatagramSize = 65507
			if tc.protocol == wire.ProtocolV5 {
				config.HasUptimeOrigin = true
				config.UptimeOriginUnixNanos = 0
			} else if tc.protocol == wire.ProtocolV9 {
				config.SourceID, config.ObservationDomainID = 42, 42
			} else {
				config.ObservationDomainID = 42
			}
			state, err := NewState(compiled, tc.writer, config)
			if err != nil {
				t.Fatalf("new state: %v", err)
			}
			var packet Packet
			if tc.protocol == wire.ProtocolV5 {
				shape := mustShape(t, state, 0)
				packet, err = state.BeginData(3_000_000_000, 1, 0, DataRequest{Records: []wire.WireRecord{testRecord(t, shape, 1_000_000)}, V5SamplingRates: []uint32{0}})
			} else {
				packet, err = state.BeginTemplate(3_000_000_000, 1, 0)
			}
			if err != nil {
				t.Fatalf("begin packet: %v", err)
			}
			buffer := make([]byte, packet.DatagramLength())
			n, err := packet.Encode(buffer)
			if err != nil || uint64(n) != packet.DatagramLength() {
				t.Fatalf("writer=(%d,%v), length=%d", n, err, packet.DatagramLength())
			}
			if _, err := state.Commit(packet, n, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStateEncodeFailureRollsBackReservation(t *testing.T) {
	for _, test := range []struct {
		name    string
		instant uint64
	}{
		{"future-flow-time", 4_000_000_000},
		{"submillisecond-flow-time", 4_000_001},
	} {
		t.Run("v5-"+test.name, func(t *testing.T) {
			compiled := compiledMapping(t, wire.ProtocolV5)
			config := DefaultConfig(wire.ProtocolV5)
			config.MaxDatagramSize = 65507
			config.HasUptimeOrigin = true
			config.UptimeOriginUnixNanos = 0
			state, err := NewState(compiled, netflow5.Writer{}, config)
			if err != nil {
				t.Fatal(err)
			}
			shape := mustShape(t, state, 0)
			packet, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{
				Records:         []wire.WireRecord{testRecord(t, shape, test.instant)},
				V5SamplingRates: []uint32{0},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := packet.Encode(make([]byte, packet.DatagramLength())); !errors.Is(err, ErrEncoding) {
				t.Fatalf("encode err=%v", err)
			}
			state.mu.Lock()
			pending, haveWall, wall := state.pending != nil, state.haveReservedWall, state.lastReservedWall
			state.mu.Unlock()
			if pending || haveWall || wall != 0 || state.Sequence() != 0 || state.Epoch().UptimeExhausted {
				t.Fatalf("failed encode mutated state pending=%v wall=%v/%d seq=%d epoch=%+v", pending, haveWall, wall, state.Sequence(), state.Epoch())
			}
		})
	}

	t.Run("ipfix-post-era-timestamp", func(t *testing.T) {
		compiled := compiledMapping(t, wire.ProtocolIPFIX)
		config := DefaultConfig(wire.ProtocolIPFIX)
		config.MaxDatagramSize = 65507
		config.ObservationDomainID = 42
		state, err := NewState(compiled, ipfix.Writer{}, config)
		if err != nil {
			t.Fatal(err)
		}
		bootstrap(t, state, 3_000_000_000, 0)
		state.mu.Lock()
		priorWall, priorHaveWall := state.lastReservedWall, state.haveReservedWall
		priorSequence := state.epoch.sequence
		state.mu.Unlock()
		shape := mustShape(t, state, 0)
		packet, err := state.BeginData(4_000_000_000, 1, 0, DataRequest{Records: []wire.WireRecord{
			testRecord(t, shape, 2_100_000_000_000_000_000),
		}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := packet.Encode(make([]byte, packet.DatagramLength())); !errors.Is(err, ErrEncoding) {
			t.Fatalf("post-era encode err=%v", err)
		}
		state.mu.Lock()
		pending, gotWall, gotHaveWall := state.pending != nil, state.lastReservedWall, state.haveReservedWall
		state.mu.Unlock()
		if pending || gotWall != priorWall || gotHaveWall != priorHaveWall || state.Sequence() != priorSequence {
			t.Fatalf("post-era rollback pending=%v wall=%v/%d seq=%d", pending, gotHaveWall, gotWall, state.Sequence())
		}
	})

	t.Run("true-short-pure-result", func(t *testing.T) {
		config := DefaultConfig(wire.ProtocolV5)
		config.MaxDatagramSize = 65507
		config.HasUptimeOrigin = true
		config.UptimeOriginUnixNanos = 0
		state, err := NewState(compiledMapping(t, wire.ProtocolV5), shortPureWriter{}, config)
		if err != nil {
			t.Fatal(err)
		}
		shape := mustShape(t, state, 0)
		packet, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{
			Records:         []wire.WireRecord{testRecord(t, shape, 1_000_000)},
			V5SamplingRates: []uint32{0},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := packet.Encode(make([]byte, packet.DatagramLength())); !errors.Is(err, ErrEncoding) {
			t.Fatalf("short pure result err=%v", err)
		}
		state.mu.Lock()
		pending, haveWall := state.pending != nil, state.haveReservedWall
		state.mu.Unlock()
		if pending || haveWall {
			t.Fatalf("short pure result retained state pending=%v wall=%v", pending, haveWall)
		}
	})

	t.Run("overlength-pure-result", func(t *testing.T) {
		state, _ := stateFor(t, wire.ProtocolV5, func(config *Config) {
			config.MaxDatagramSize = 65507
			config.UptimeOriginUnixNanos = 0
		})
		shape := mustShape(t, state, 0)
		packet, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{
			Records:         []wire.WireRecord{testRecord(t, shape, 1_000_000)},
			V5SamplingRates: []uint32{0},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := packet.Encode(make([]byte, packet.DatagramLength()+1)); !errors.Is(err, ErrEncoding) {
			t.Fatalf("overlength pure result err=%v", err)
		}
	})
}

func TestStateV9RealWriterBootstrapOriginData(t *testing.T) {
	config := DefaultConfig(wire.ProtocolV9)
	config.MaxDatagramSize = 65507
	config.SourceID, config.ObservationDomainID = 42, 42
	state, err := NewState(compiledMapping(t, wire.ProtocolV9), netflow9.Writer{}, config)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, state, 3_000_000_000, 0)
	if origin := state.Epoch(); !origin.HasStartOrigin || origin.StartOrigin != 3_000_000_000 {
		t.Fatalf("bootstrap origin=%+v", origin)
	}
	shape := mustShape(t, state, 0)
	packet, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{Records: []wire.WireRecord{
		testRecord(t, shape, 3_000_000_000),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if packet.request.Header.UptimeOriginUnixNanos != 3_000_000_000 {
		t.Fatalf("data origin=%d", packet.request.Header.UptimeOriginUnixNanos)
	}
	n, err := packet.Encode(make([]byte, packet.DatagramLength()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Commit(packet, n, nil); err != nil {
		t.Fatal(err)
	}
}

func TestStateRejectsInvalidWriteClassifications(t *testing.T) {
	if got := ClassifyWrite(-1, 10, nil); got != WriteInvalid {
		t.Fatalf("negative write class=%v", got)
	}
	if got := ClassifyWrite(11, 10, nil); got != WriteInvalid {
		t.Fatalf("overlength write class=%v", got)
	}
}

func mustPending(t *testing.T, state *State) Packet {
	t.Helper()
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.pending == nil {
		t.Fatal("missing pending packet")
	}
	return *state.pending
}

func TestStateRecordMessageBoundaries(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV9, wire.ProtocolIPFIX} {
		state, _ := stateFor(t, protocol, func(config *Config) { config.MaxRecordsPerMessage = 1024 })
		bootstrap(t, state, 3_000_000_000, 0)
		shape, _ := state.Catalog().ShapeAt(0)
		record := testRecord(t, shape, 3_000_000_000)
		if _, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s zero records err=%v", protocol, err)
		}
		records := make([]wire.WireRecord, 1024)
		for i := range records {
			records[i] = record
		}
		if _, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{Records: records}); err == nil {
			t.Fatalf("%s accepted 1024 records despite packet budget", protocol)
		}
		state, _ = stateFor(t, protocol, func(config *Config) { config.MaxRecordsPerMessage = 1024; config.MaxDatagramSize = 65507 })
		bootstrap(t, state, 3_000_000_000, 0)
		shape, _ = state.Catalog().ShapeAt(0)
		record = testRecord(t, shape, 3_000_000_000)
		records = make([]wire.WireRecord, 1024)
		for i := range records {
			records[i] = record
		}
		_, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{Records: records})
		if protocol == wire.ProtocolV9 && err != nil {
			t.Fatalf("%s 1024 records: %v", protocol, err)
		}
		if protocol == wire.ProtocolIPFIX && err == nil {
			t.Fatal("ipfix 1024 records exceeded the 16-bit packet budget")
		}
		state, _ = stateFor(t, protocol, func(config *Config) { config.MaxRecordsPerMessage = 1024; config.MaxDatagramSize = 65507 })
		bootstrap(t, state, 3_000_000_000, 0)
		shape, _ = state.Catalog().ShapeAt(0)
		record = testRecord(t, shape, 3_000_000_000)
		records = make([]wire.WireRecord, 1025)
		for i := range records {
			records[i] = record
		}
		if _, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{Records: records}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s 1025 err=%v", protocol, err)
		}
	}
}

func TestStateAllWriteResultClassesCommitBoundary(t *testing.T) {
	cases := []struct {
		name  string
		n     func(int) int
		err   error
		class WriteClass
	}{
		{"full-nil", func(length int) int { return length }, nil, WriteFull},
		{"short-nil", func(length int) int { return length - 1 }, nil, WriteShortNil},
		{"zero-nil", func(int) int { return 0 }, nil, WriteZeroNil},
		{"short-error", func(length int) int { return length - 1 }, errors.New("write"), WriteShortError},
		{"zero-error", func(int) int { return 0 }, errors.New("write"), WriteZeroError},
		{"full-error", func(length int) int { return length }, errors.New("write"), WriteFullError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, _ := stateFor(t, wire.ProtocolV5, func(config *Config) {
				config.MaxDatagramSize = 65507
				config.UptimeOriginUnixNanos = 0
			})
			shape := mustShape(t, state, 0)
			packet, err := state.BeginData(3_000_000_000, 1, 0, DataRequest{Records: []wire.WireRecord{testRecord(t, shape, 1_000_000)}, V5SamplingRates: []uint32{0}})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := encodePacket(t, packet)
			if err != nil {
				t.Fatal(err)
			}
			result, err := state.Commit(packet, tc.n(encoded), tc.err)
			if err != nil || result.Class != tc.class {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if result.Committed != (tc.class == WriteFull) || state.Sequence() != func() uint32 {
				if tc.class == WriteFull {
					return 1
				}
				return 0
			}() {
				t.Fatalf("commit=%+v sequence=%d", result, state.Sequence())
			}
			state.mu.Lock()
			wall, haveWall := state.lastReservedWall, state.haveReservedWall
			state.mu.Unlock()
			if !haveWall || wall != 3_000_000_000 {
				t.Fatalf("class=%v changed logical wall=%v/%d", tc.class, haveWall, wall)
			}
		})
	}
}

func TestStateProtocolSpecificConfigurationGates(t *testing.T) {
	compiledV9 := compiledMapping(t, wire.ProtocolV9)
	for _, config := range []Config{
		{Protocol: wire.ProtocolV9, SamplingMode: 1},
		{Protocol: wire.ProtocolV9, EngineType: 1},
		{Protocol: wire.ProtocolV9, EngineID: 1},
		{Protocol: wire.ProtocolV9, SourceID: 1, ObservationDomainID: 2},
	} {
		if _, err := NewState(compiledV9, &recordingWriter{}, config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("v9 invalid config accepted: %+v err=%v", config, err)
		}
	}
	compiledIPFIX := compiledMapping(t, wire.ProtocolIPFIX)
	for _, config := range []Config{
		{Protocol: wire.ProtocolIPFIX, SourceID: 1},
		{Protocol: wire.ProtocolIPFIX, EngineType: 1},
		{Protocol: wire.ProtocolIPFIX, HasUptimeOrigin: true},
	} {
		if _, err := NewState(compiledIPFIX, &recordingWriter{}, config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("ipfix invalid config accepted: %+v err=%v", config, err)
		}
	}
	if _, err := NewState(compiledMapping(t, wire.ProtocolV5), &recordingWriter{}, Config{Protocol: wire.ProtocolV5}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("v5 missing uptime origin accepted: %v", err)
	}
}
