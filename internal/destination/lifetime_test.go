package destination

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/transport"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow5"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow9"
)

const lifetimeTestOrigin = uint64(1_700_000_000_000_000_000)

func lifetimeRuntime(state *State, clock transport.Clock) *Runtime {
	return &Runtime{clock: clock, published: &endpoint{state: state}}
}

func timedLifetimeState(t *testing.T, protocol wire.Protocol, origin uint64) *State {
	t.Helper()
	config := mapping.Config{
		Protocol:              protocol,
		LossPolicy:            mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize:       65507,
		PathMTU:               65535,
		Endpoint:              "192.0.2.1:4739",
		HasUptimeOrigin:       true,
		UptimeOriginUnixNanos: origin,
		ProtocolIdentifiers:   []mapping.ProtocolIdentifier{{Token: "tcp", Number: 6}},
	}
	switch protocol {
	case wire.ProtocolV5:
		config.Profile = mapping.ProfileV5
		config.InputGuarantees.FlowIOBytes = "layer3_total_octets"
	case wire.ProtocolV9:
		config.Profile = mapping.ProfileV9Timed
		config.NetworkTypeVersions = []mapping.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
	default:
		t.Fatalf("timed state protocol %s", protocol)
	}
	compiled, err := mapping.Compile(config)
	if err != nil {
		t.Fatalf("compile timed %s: %v", protocol, err)
	}
	stateConfig := DefaultConfig(protocol)
	stateConfig.MaxDatagramSize = 65507
	stateConfig.HasUptimeOrigin = true
	stateConfig.UptimeOriginUnixNanos = origin
	if protocol == wire.ProtocolV9 {
		stateConfig.SourceID, stateConfig.ObservationDomainID = 42, 42
	}
	var writer wire.ContractWriter
	if protocol == wire.ProtocolV5 {
		writer = netflow5.Writer{}
	} else {
		writer = netflow9.Writer{}
	}
	state, err := NewState(compiled, writer, stateConfig)
	if err != nil {
		t.Fatalf("new timed %s: %v", protocol, err)
	}
	return state
}

func newTimedV9Runtime(t *testing.T, origin uint64, clock transport.Clock, dial transport.NumericDial) *Runtime {
	t.Helper()
	state := timedLifetimeState(t, wire.ProtocolV9, origin)
	resolver, err := transport.NewResolver("udp4", runtimeRemote.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := transport.NewCandidateDialer(resolver, runtimeRemote.Port(), 65507, state.Mapping().MaxDatagramSize(), 65535, dial, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	config := RuntimeConfig{State: state.Config(), DNSRefresh: time.Second, DNSStaleAfter: time.Minute}
	config.State.RefreshInterval = 30 * time.Second
	runtime, err := NewRuntime(state.Mapping(), netflow9.Writer{}, config, dialer, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime
}

func timedV9BootstrapSteps(t *testing.T, origin uint64) []testtransport.WriteStep {
	t.Helper()
	state := timedLifetimeState(t, wire.ProtocolV9, origin)
	steps := make([]testtransport.WriteStep, 0, int(state.Config().InitialCopies)*state.Catalog().ShapeCount())
	for round := uint8(0); round < state.Config().InitialCopies; round++ {
		for shapeIndex := 0; shapeIndex < state.Catalog().ShapeCount(); shapeIndex++ {
			shape, ok := state.Catalog().ShapeAt(shapeIndex)
			if !ok {
				t.Fatalf("missing timed v9 shape %d", shapeIndex)
			}
			steps = append(steps, testtransport.WriteStep{N: int(20 + shape.TemplateBytes())})
		}
	}
	return steps
}

func lifetimeStateValues(state *State) lifetimeStateValueCopy {
	state.mu.Lock()
	defer state.mu.Unlock()
	var pending *Packet
	if state.pending != nil {
		copy := *state.pending
		copy.request.Records = make([]wire.WireRecord, len(state.pending.request.Records))
		for index, record := range state.pending.request.Records {
			// WireRecord.Values deep-copies borrowed byte views; rebuilding the
			// value keeps this oracle sensitive to collection-time aliasing.
			copy.request.Records[index], _ = wire.NewWireRecord(record.Family(), record.Values())
		}
		if state.pending.stream != nil {
			stream := *state.pending.stream
			copy.stream = &stream
		}
		pending = &copy
	}
	return lifetimeStateValueCopy{
		epoch: state.epoch.snapshot(), config: state.config, progress: ProgressSnapshot{
			NextShape: state.nextTemplateIndex, CompletedRounds: state.templateRound,
			InitialCopies: state.config.InitialCopies, RefreshActive: state.refreshActive,
			RefreshDue: state.refreshDue, PacketCount: state.packetCount,
			DataMessageCount: state.dataMessageCount, LastRefreshMono: state.lastRefreshMono,
			HasRefreshMono: state.haveRefreshMono,
		},
		reservedWall: state.lastReservedWall, haveReservedWall: state.haveReservedWall,
		nextID: state.nextID, nextToken: state.nextToken, pending: pending,
	}
}

type lifetimeStateValueCopy struct {
	epoch             EpochSnapshot
	config            Config
	progress          ProgressSnapshot
	reservedWall      uint64
	haveReservedWall  bool
	nextID, nextToken uint64
	pending           *Packet
}

func assertLifetimeStateUnchanged(t *testing.T, state *State, before lifetimeStateValueCopy) {
	t.Helper()
	after := lifetimeStateValues(state)
	if after.epoch != before.epoch || after.config != before.config || after.progress != before.progress ||
		after.reservedWall != before.reservedWall || after.haveReservedWall != before.haveReservedWall ||
		after.nextID != before.nextID || after.nextToken != before.nextToken || !reflect.DeepEqual(after.pending, before.pending) {
		t.Fatalf("lifetime mutated state: before=%+v after=%+v", before, after)
	}
}

func lifetimeDataRequest(t *testing.T, state *State, instant uint64) DataRequest {
	t.Helper()
	shape := mustShape(t, state, 0)
	request := DataRequest{Records: []wire.WireRecord{testRecord(t, shape, instant)}}
	if state.Config().Protocol == wire.ProtocolV5 {
		request.V5SamplingRates = []uint32{0}
	}
	return request
}

func TestLifetimeProjectionBoundaries(t *testing.T) {
	const ms = uint64(1_000_000)
	limit := uint64(math.MaxUint32) + 1
	clock := testclock.New(lifetimeTestOrigin, 1)
	state := timedLifetimeState(t, wire.ProtocolV5, lifetimeTestOrigin)
	runtime := lifetimeRuntime(state, clock)

	cases := []struct {
		name string
		wall uint64
		want float64
	}{
		{"max-minus-one", lifetimeTestOrigin + (limit-2)*ms, 0.002},
		{"maximum", lifetimeTestOrigin + (limit-1)*ms, 0.001},
		{"first-exhausted", lifetimeTestOrigin + limit*ms, 0},
		{"fractional-overflow", lifetimeTestOrigin + limit*ms + 123, 0},
		{"rewind-maximum", lifetimeTestOrigin + (limit-1)*ms, 0.001},
		{"rewind-max-minus-one", lifetimeTestOrigin + (limit-2)*ms, 0.002},
		{"repeat-max-minus-one", lifetimeTestOrigin + (limit-2)*ms, 0.002},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock.Set(tc.wall, 1)
			got := runtime.Lifetime()
			if !got.Applicable || !got.RemainingKnown || got.Exhausted || got.RemainingSeconds != tc.want {
				t.Fatalf("Lifetime=%+v, want applicable known non-exhausted %.3f", got, tc.want)
			}
		})
	}

	// A collection at the last usable millisecond does not reserve that wall
	// value.  An actual State operation does, and a later rewind respects the
	// copied floor without mutating it.
	maximum := lifetimeTestOrigin + (limit-1)*ms
	clock.Set(maximum, 2)
	shape := mustShape(t, state, 0)
	packet, err := state.BeginData(maximum, 2, 0, DataRequest{
		Records:         []wire.WireRecord{testRecord(t, shape, maximum)},
		V5SamplingRates: []uint32{0},
	})
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, packet)
	clock.Set(lifetimeTestOrigin+ms, 3)
	if got := runtime.Lifetime(); !got.RemainingKnown || got.RemainingSeconds != 0.001 {
		t.Fatalf("reserved-wall rewind Lifetime=%+v, want 1ms", got)
	}

	exhaustedWall := lifetimeTestOrigin + limit*ms
	clock.Set(exhaustedWall, 4)
	if got := runtime.Lifetime(); !got.RemainingKnown || got.RemainingSeconds != 0 || got.Exhausted {
		t.Fatalf("pre-latch exhausted projection=%+v", got)
	}
	if _, err := state.BeginData(exhaustedWall, 4, 0, lifetimeDataRequest(t, state, exhaustedWall)); !errors.Is(err, ErrUptimeExhausted) {
		t.Fatalf("actual exhaustion operation=%v", err)
	}
	if !state.Epoch().UptimeExhausted {
		t.Fatal("State operation did not latch exhaustion")
	}
	clock.Set(math.MaxInt64+1, 5)
	if got := runtime.Lifetime(); !got.Exhausted || !got.RemainingKnown || got.RemainingSeconds != 0 {
		t.Fatalf("latched invalid-clock Lifetime=%+v", got)
	}

	// Invalid samples do not latch and a later valid sample recovers.
	recovery := timedLifetimeState(t, wire.ProtocolV5, lifetimeTestOrigin)
	recoveryClock := testclock.New(lifetimeTestOrigin+1, 1)
	recoveryRuntime := lifetimeRuntime(recovery, recoveryClock)
	if got := recoveryRuntime.Lifetime(); got.RemainingKnown || got.Exhausted {
		t.Fatalf("fractional under-limit sample=%+v", got)
	}
	recoveryClock.Set(lifetimeTestOrigin+ms, 2)
	if got := recoveryRuntime.Lifetime(); !got.RemainingKnown || got.Exhausted {
		t.Fatalf("valid recovery=%+v", got)
	}
	recoveryClock.Set(lifetimeTestOrigin-1, 3)
	if got := recoveryRuntime.Lifetime(); got.RemainingKnown {
		t.Fatalf("before-origin sample=%+v", got)
	}
	recoveryClock.Set(uint64(math.MaxUint32+1)*1_000_000_000, 4)
	if got := recoveryRuntime.Lifetime(); got.RemainingKnown {
		t.Fatalf("header-seconds-invalid sample=%+v", got)
	}
	// Raw signed overflow is rejected before the reservation floor can clamp it.
	recovery.mu.Lock()
	recovery.lastReservedWall, recovery.haveReservedWall = lifetimeTestOrigin+ms, true
	recovery.mu.Unlock()
	recoveryClock.Set(math.MaxInt64+1, 5)
	if got := recoveryRuntime.Lifetime(); got.RemainingKnown {
		t.Fatalf("raw signed-overflow sample=%+v", got)
	}

	// The implicit v9 origin is captured by bootstrap and is origin-relative,
	// rather than relative to construction or the process clock.
	noOrigin, _ := stateFor(t, wire.ProtocolV9, nil)
	noOriginRuntime := lifetimeRuntime(noOrigin, testclock.New(lifetimeTestOrigin+ms, 1))
	if got := noOriginRuntime.Lifetime(); !got.Applicable || got.RemainingKnown || got.Exhausted {
		t.Fatalf("missing implicit origin Lifetime=%+v", got)
	}
	implicit, _ := stateFor(t, wire.ProtocolV9, func(config *Config) { config.MaxDatagramSize = 65507 })
	bootstrap(t, implicit, lifetimeTestOrigin, 1)
	implicitClock := testclock.New(lifetimeTestOrigin+ms, 2)
	implicitRuntime := lifetimeRuntime(implicit, implicitClock)
	if got := implicitRuntime.Lifetime(); !got.Applicable || !got.RemainingKnown || got.RemainingSeconds != float64(limit-1)/1000 {
		t.Fatalf("implicit-origin Lifetime=%+v", got)
	}

	t.Run("timed-v9-boundaries", func(t *testing.T) {
		state := timedLifetimeState(t, wire.ProtocolV9, lifetimeTestOrigin)
		bootstrap(t, state, lifetimeTestOrigin, 1)
		clock := testclock.New(lifetimeTestOrigin, 1)
		runtime := lifetimeRuntime(state, clock)
		for _, tc := range cases {
			clock.Set(tc.wall, 1)
			got := runtime.Lifetime()
			if !got.Applicable || !got.RemainingKnown || got.Exhausted || got.RemainingSeconds != tc.want {
				t.Fatalf("wall=%d Lifetime=%+v want %.3f", tc.wall, got, tc.want)
			}
		}
		maximum := lifetimeTestOrigin + (limit-1)*ms
		clock.Set(maximum, 2)
		packet, err := state.BeginData(maximum, 2, 0, lifetimeDataRequest(t, state, maximum))
		if err != nil {
			t.Fatal(err)
		}
		commitFull(t, state, packet)
		clock.Set(lifetimeTestOrigin+ms, 3)
		if got := runtime.Lifetime(); !got.RemainingKnown || got.RemainingSeconds != 0.001 {
			t.Fatalf("timed v9 reserved-wall rewind=%+v", got)
		}

		exhausted := lifetimeTestOrigin + limit*ms
		clock.Set(exhausted, 4)
		if got := runtime.Lifetime(); !got.RemainingKnown || got.RemainingSeconds != 0 || got.Exhausted {
			t.Fatalf("timed v9 pre-latch exhausted=%+v", got)
		}
		if _, err := state.BeginData(exhausted, 4, 0, lifetimeDataRequest(t, state, exhausted)); !errors.Is(err, ErrUptimeExhausted) {
			t.Fatalf("timed v9 exhaustion operation=%v", err)
		}
		clock.Set(math.MaxInt64+1, 5)
		if got := runtime.Lifetime(); !got.Exhausted || !got.RemainingKnown || got.RemainingSeconds != 0 {
			t.Fatalf("timed v9 latched Lifetime=%+v", got)
		}
		clock.Set(lifetimeTestOrigin+ms, 6)
		if got := runtime.Lifetime(); !got.Exhausted || !got.RemainingKnown || got.RemainingSeconds != 0 {
			t.Fatalf("timed v9 latched rewind Lifetime=%+v", got)
		}
	})
	t.Run("implicit-v9-boundaries", func(t *testing.T) {
		state, _ := stateFor(t, wire.ProtocolV9, func(config *Config) { config.MaxDatagramSize = 65507 })
		bootstrap(t, state, lifetimeTestOrigin, 1)
		clock := testclock.New(lifetimeTestOrigin, 1)
		runtime := lifetimeRuntime(state, clock)
		for _, tc := range cases {
			clock.Set(tc.wall, 1)
			got := runtime.Lifetime()
			if !got.Applicable || !got.RemainingKnown || got.Exhausted || got.RemainingSeconds != tc.want {
				t.Fatalf("wall=%d Lifetime=%+v want %.3f", tc.wall, got, tc.want)
			}
		}
		maximum := lifetimeTestOrigin + (limit-1)*ms
		clock.Set(maximum, 2)
		packet, err := state.BeginData(maximum, 2, 0, lifetimeDataRequest(t, state, maximum))
		if err != nil {
			t.Fatal(err)
		}
		commitFull(t, state, packet)
		clock.Set(lifetimeTestOrigin+ms, 3)
		if got := runtime.Lifetime(); !got.RemainingKnown || got.RemainingSeconds != 0.001 {
			t.Fatalf("implicit reserved-wall rewind=%+v", got)
		}
		exhausted := lifetimeTestOrigin + limit*ms
		clock.Set(exhausted, 4)
		if got := runtime.Lifetime(); !got.RemainingKnown || got.RemainingSeconds != 0 || got.Exhausted {
			t.Fatalf("implicit pre-latch exhausted=%+v", got)
		}
		if _, err := state.BeginData(exhausted, 4, 0, lifetimeDataRequest(t, state, exhausted)); !errors.Is(err, ErrUptimeExhausted) {
			t.Fatalf("implicit exhaustion operation=%v", err)
		}
		clock.Set(lifetimeTestOrigin+ms, 5)
		if got := runtime.Lifetime(); !got.Exhausted || !got.RemainingKnown || got.RemainingSeconds != 0 {
			t.Fatalf("implicit latched rewind=%+v", got)
		}
	})
}

func TestLifetimeObservationReadOnly(t *testing.T) {
	const ms = uint64(1_000_000)
	limit := uint64(math.MaxUint32) + 1
	state := timedLifetimeState(t, wire.ProtocolV5, lifetimeTestOrigin)
	clock := testclock.New(lifetimeTestOrigin+ms, 1)
	runtime := lifetimeRuntime(state, clock)

	before := lifetimeStateValues(state)
	if got := runtime.Lifetime(); !got.RemainingKnown || got.Exhausted {
		t.Fatalf("initial Lifetime=%+v", got)
	}
	assertLifetimeStateUnchanged(t, state, before)

	shape := mustShape(t, state, 0)
	pending, err := state.BeginData(lifetimeTestOrigin+ms, 1, 0, DataRequest{
		Records: []wire.WireRecord{testRecord(t, shape, lifetimeTestOrigin+ms)}, V5SamplingRates: []uint32{0},
	})
	if err != nil {
		t.Fatal(err)
	}
	pendingBefore := lifetimeStateValues(state)
	if got := runtime.Lifetime(); !got.RemainingKnown {
		t.Fatalf("pending Lifetime=%+v", got)
	}
	assertLifetimeStateUnchanged(t, state, pendingBefore)
	commitFull(t, state, pending)
	sequenceAfterFull := state.Sequence()

	ambiguous, err := state.BeginData(lifetimeTestOrigin+2*ms, 2, 0, DataRequest{
		Records: []wire.WireRecord{testRecord(t, shape, lifetimeTestOrigin+2*ms)}, V5SamplingRates: []uint32{0},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodePacket(t, ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	if got := runtime.Lifetime(); !got.RemainingKnown {
		t.Fatalf("ambiguous Lifetime=%+v", got)
	}
	if _, err := state.Commit(ambiguous, encoded, errors.New("ambiguous")); err != nil {
		t.Fatal(err)
	}
	if state.Sequence() != sequenceAfterFull {
		t.Fatalf("ambiguous write changed sequence=%d want=%d", state.Sequence(), sequenceAfterFull)
	}

	aborted, err := state.BeginData(lifetimeTestOrigin+3*ms, 3, 0, DataRequest{
		Records: []wire.WireRecord{testRecord(t, shape, lifetimeTestOrigin+3*ms)}, V5SamplingRates: []uint32{0},
	})
	if err != nil {
		t.Fatal(err)
	}
	abortBefore := lifetimeStateValues(state)
	_ = runtime.Lifetime()
	assertLifetimeStateUnchanged(t, state, abortBefore)
	if err := aborted.Abort(); err != nil {
		t.Fatal(err)
	}

	// Exercise the real streaming transaction as a pending packet. The stream
	// scalar is copied in the test snapshot so a query cannot hide mutation by
	// aliasing the appender state.
	streamState := timedLifetimeState(t, wire.ProtocolV5, lifetimeTestOrigin)
	streamClock := testclock.New(lifetimeTestOrigin+4*ms, 1)
	streamRuntime := lifetimeRuntime(streamState, streamClock)
	streamShape := mustShape(t, streamState, 0)
	streamPacket, err := streamState.BeginDataStream(lifetimeTestOrigin+4*ms, 1, 0, make([]byte, 512), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := streamPacket.Append(testRecord(t, streamShape, lifetimeTestOrigin+4*ms), 0); err != nil {
		t.Fatal(err)
	}
	streamBefore := lifetimeStateValues(streamState)
	if got := streamRuntime.Lifetime(); !got.RemainingKnown {
		t.Fatalf("stream pending Lifetime=%+v", got)
	}
	assertLifetimeStateUnchanged(t, streamState, streamBefore)
	streamBytes, err := streamPacket.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := streamState.Commit(streamPacket, streamBytes, nil); err != nil {
		t.Fatal(err)
	}

	// A nonzero refresh-progress snapshot is also read-only evidence.
	progressState, _ := stateFor(t, wire.ProtocolV9, nil)
	bootstrap(t, progressState, lifetimeTestOrigin, 1)
	progressMono := 1 + uint64(progressState.Config().RefreshInterval)
	if !progressState.RefreshDue(progressMono) {
		t.Fatal("failed to establish refresh-due progress")
	}
	progressRuntime := lifetimeRuntime(progressState, testclock.New(lifetimeTestOrigin+ms, progressMono))
	progressBefore := lifetimeStateValues(progressState)
	_ = progressRuntime.Lifetime()
	assertLifetimeStateUnchanged(t, progressState, progressBefore)

	clock.Set(lifetimeTestOrigin+limit*ms, 4)
	if got := runtime.Lifetime(); !got.RemainingKnown || got.RemainingSeconds != 0 || got.Exhausted {
		t.Fatalf("post-limit observation=%+v", got)
	}
	if state.Epoch().UptimeExhausted {
		t.Fatal("observation latched exhaustion")
	}
	clock.Set(lifetimeTestOrigin+ms, 5)
	validAfterRewind, err := state.BeginData(lifetimeTestOrigin+ms, 5, 0, lifetimeDataRequest(t, state, lifetimeTestOrigin+ms))
	if err != nil {
		t.Fatalf("valid operation after observation=%v", err)
	}
	commitFull(t, state, validAfterRewind)

	// Decode the fixed synthetic v5 header independently of Lifetime's
	// projection arithmetic.  State's accepted last-valid sample must carry
	// the maximum uint32 uptime.
	last := timedLifetimeState(t, wire.ProtocolV5, lifetimeTestOrigin)
	lastShape := mustShape(t, last, 0)
	lastWall := lifetimeTestOrigin + (limit-1)*ms
	lastPacket, err := last.BeginData(lastWall, 1, 0, DataRequest{
		Records: []wire.WireRecord{testRecord(t, lastShape, lastWall)}, V5SamplingRates: []uint32{0},
	})
	if err != nil {
		t.Fatal(err)
	}
	lastBuffer := make([]byte, lastPacket.DatagramLength())
	lastBytes, err := lastPacket.Encode(lastBuffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(lastBuffer[4:8]); got != math.MaxUint32 {
		t.Fatalf("accepted last-valid sysUptime=%d", got)
	}
	if _, err := last.Commit(lastPacket, lastBytes, nil); err != nil {
		t.Fatal(err)
	}

	lastV9 := timedLifetimeState(t, wire.ProtocolV9, lifetimeTestOrigin)
	bootstrap(t, lastV9, lifetimeTestOrigin, 1)
	lastV9Shape := mustShape(t, lastV9, 0)
	lastV9Packet, err := lastV9.BeginData(lastWall, 1, 0, lifetimeDataRequest(t, lastV9, lastWall))
	if err != nil {
		t.Fatal(err)
	}
	lastV9Buffer := make([]byte, lastV9Packet.DatagramLength())
	lastV9Bytes, err := lastV9Packet.Encode(lastV9Buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(lastV9Buffer[4:8]); got != math.MaxUint32 {
		t.Fatalf("accepted last-valid v9 sysUptime=%d shape=%v", got, lastV9Shape)
	}
	if _, err := lastV9.Commit(lastV9Packet, lastV9Bytes, nil); err != nil {
		t.Fatal(err)
	}
}

func TestLifetimePublishedEpochIsolation(t *testing.T) {
	const limit = uint64(math.MaxUint32) + 1
	const ms = uint64(1_000_000)

	t.Run("inactive-and-ipfix", func(t *testing.T) {
		if got := (&Runtime{clock: testclock.New(lifetimeTestOrigin, 1)}).Lifetime(); got != (LifetimeSnapshot{}) {
			t.Fatalf("constructed runtime Lifetime=%+v", got)
		}
		unstarted := newRuntimeForTest(t, wire.ProtocolV5, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) {
			return newRuntimeConn(), nil
		}, testclock.New(4_000_000_000, 1))
		if got := unstarted.Lifetime(); got != (LifetimeSnapshot{}) {
			t.Fatalf("actual NewRuntime before Start Lifetime=%+v", got)
		}
		lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}})
		conn := newRuntimeConn(runtimeBootstrapSteps(wire.ProtocolIPFIX)...)
		r, _, timer := newDNSRuntime(t, wire.ProtocolIPFIX, 4739, lookup, func(context.Context, netip.AddrPort) (transport.Conn, error) {
			return conn, nil
		})
		if err := r.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitDNSReset(t, timer, 1)
		if currentEndpoint(r) == nil {
			t.Fatal("IPFIX runtime did not publish")
		}
		if got := r.Lifetime(); got != (LifetimeSnapshot{}) {
			t.Fatalf("published IPFIX Lifetime=%+v", got)
		}
	})

	t.Run("failed-initial-timed-v9", func(t *testing.T) {
		clock := testclock.New(limit*ms, 1)
		r := newTimedV9Runtime(t, 0, clock, func(context.Context, netip.AddrPort) (transport.Conn, error) {
			return newRuntimeConn(), nil
		})
		if err := r.Start(context.Background()); !errors.Is(err, ErrUptimeExhausted) {
			t.Fatalf("expired timed-v9 Start=%v", err)
		}
		if got := r.Lifetime(); got != (LifetimeSnapshot{}) {
			t.Fatalf("failed timed-v9 candidate Lifetime=%+v", got)
		}
	})

	t.Run("expired-v5-start-followed-by-data", func(t *testing.T) {
		clock := testclock.New(limit*ms, 1)
		conn := newRuntimeConn()
		r := newRuntimeForTest(t, wire.ProtocolV5, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) {
			return conn, nil
		}, clock)
		if err := r.Start(context.Background()); err != nil {
			t.Fatalf("expired v5 Start=%v", err)
		}
		if currentEndpoint(r) == nil {
			t.Fatal("expired v5 Start did not publish")
		}
		if got := r.Lifetime(); !got.Applicable || !got.RemainingKnown || got.RemainingSeconds != 0 || got.Exhausted {
			t.Fatalf("expired v5 pre-data Lifetime=%+v", got)
		}
		if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); err == nil {
			t.Fatal("expired v5 data unexpectedly succeeded")
		}
		if got := r.Lifetime(); !got.Exhausted || !got.RemainingKnown || got.RemainingSeconds != 0 {
			t.Fatalf("expired v5 data did not latch=%+v", got)
		}
	})

	t.Run("idle-refresh-latches-published-v9", func(t *testing.T) {
		lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}})
		conn := newRuntimeConn(runtimeBootstrapSteps(wire.ProtocolV9)...)
		fixture := newResourceRuntime(t, wire.ProtocolV9, lookup, conn)
		t.Cleanup(func() { _ = fixture.r.Close() })
		if err := fixture.r.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitDNSReset(t, fixture.timers[0], 1)
		waitRefreshReset(t, fixture.timers[1], 1)
		fixture.clock.Set(4_000_000_000+limit*ms, uint64(61*time.Second))
		if !fixture.timers[1].Fire() {
			t.Fatal("refresh timer not armed")
		}
		waitRefreshReset(t, fixture.timers[1], 2)
		if got := fixture.r.Lifetime(); !got.Applicable || !got.Exhausted || !got.RemainingKnown || got.RemainingSeconds != 0 {
			t.Fatalf("idle-refresh latch Lifetime=%+v", got)
		}
	})

	t.Run("v5-candidate-and-expiring-replacement", func(t *testing.T) {
		old, next := newRuntimeConn(), newReplacementConn()
		entered, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
		lookup := testtransport.NewResolver(
			testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}},
			testtransport.ResolverStep{Answers: []netip.Addr{replacementRemote.Addr()}},
		)
		r, clock, timer := newDNSRuntime(t, wire.ProtocolV5, 4739, lookup, func(ctx context.Context, remote netip.AddrPort) (transport.Conn, error) {
			if remote == replacementRemote {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				return next, nil
			}
			return old, nil
		})
		t.Cleanup(releaseGate)
		if err := r.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitDNSReset(t, timer, 1)
		previous := currentEndpoint(r)
		clock.SetWall(limit * ms)
		if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); err == nil {
			t.Fatal("expired old v5 data unexpectedly succeeded")
		}
		if got := r.Lifetime(); !got.Exhausted || !got.RemainingKnown || got.RemainingSeconds != 0 {
			t.Fatalf("old v5 did not latch=%+v", got)
		}
		clock.Advance(0, uint64(time.Second))
		if !timer.Fire() {
			t.Fatal("DNS timer not armed")
		}
		waitRuntimeSignal(t, entered)
		before := r.Lifetime()
		if !before.Applicable || !before.RemainingKnown || !before.Exhausted || before.RemainingSeconds != 0 {
			t.Fatalf("old epoch during candidate=%+v", before)
		}
		if currentEndpoint(r) != previous || old.closes.Load() != 0 {
			t.Fatal("candidate changed publication before bootstrap")
		}
		releaseGate()
		waitDNSReset(t, timer, 2)
		if currentEndpoint(r) == previous || old.closes.Load() != 1 || next.closes.Load() != 0 {
			t.Fatal("successful replacement did not retire old endpoint")
		}
		if got := r.Lifetime(); !got.RemainingKnown || got.RemainingSeconds != 0 || got.Exhausted {
			t.Fatalf("new explicit replacement before data=%+v", got)
		}
		if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); err == nil {
			t.Fatal("expired replacement data unexpectedly succeeded")
		}
		if got := r.Lifetime(); !got.Exhausted || !got.RemainingKnown || got.RemainingSeconds != 0 {
			t.Fatalf("replacement did not latch=%+v", got)
		}
	})

	t.Run("failed-v9-replacement-keeps-latched-old", func(t *testing.T) {
		old := newRuntimeConn(runtimeBootstrapSteps(wire.ProtocolV9)...)
		failed := newReplacementConn()
		lookup := testtransport.NewResolver(
			testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}},
			testtransport.ResolverStep{Answers: []netip.Addr{replacementRemote.Addr()}},
		)
		var calls atomic.Int32
		r, clock, timer := newDNSRuntime(t, wire.ProtocolV9, 4739, lookup, func(context.Context, netip.AddrPort) (transport.Conn, error) {
			if calls.Add(1) == 1 {
				return old, nil
			}
			return failed, nil
		})
		if err := r.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitDNSReset(t, timer, 1)
		previous := currentEndpoint(r)
		clock.SetWall(4_000_000_000 + limit*ms)
		if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); err == nil {
			t.Fatal("expired old v9 data unexpectedly succeeded")
		}
		before := r.Lifetime()
		if !before.Exhausted || !before.RemainingKnown {
			t.Fatalf("old v9 latch=%+v", before)
		}
		clock.Advance(0, uint64(time.Second))
		if !timer.Fire() {
			t.Fatal("DNS timer not armed")
		}
		waitDNSReset(t, timer, 2)
		if currentEndpoint(r) != previous || failed.closes.Load() != 1 {
			t.Fatal("failed replacement displaced published old endpoint")
		}
		if got := r.Lifetime(); got != before {
			t.Fatalf("failed replacement contaminated Lifetime: before=%+v after=%+v", before, got)
		}
	})

	t.Run("implicit-v9-new-origin", func(t *testing.T) {
		old := newRuntimeConn(runtimeBootstrapSteps(wire.ProtocolV9)...)
		next := newReplacementConn(runtimeBootstrapSteps(wire.ProtocolV9)...)
		lookup := testtransport.NewResolver(
			testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}},
			testtransport.ResolverStep{Answers: []netip.Addr{replacementRemote.Addr()}},
		)
		var calls atomic.Int32
		r, clock, timer := newDNSRuntime(t, wire.ProtocolV9, 4739, lookup, func(context.Context, netip.AddrPort) (transport.Conn, error) {
			if calls.Add(1) == 1 {
				return old, nil
			}
			return next, nil
		})
		if err := r.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitDNSReset(t, timer, 1)
		previous := currentEndpoint(r)
		clock.SetWall(4_000_000_000 + limit*ms)
		if _, err := r.Pack(context.Background(), validPackerLogs(t), nil); err == nil {
			t.Fatal("expired old implicit-v9 data unexpectedly succeeded")
		}
		before := r.Lifetime()
		if !before.Exhausted || !before.RemainingKnown || before.RemainingSeconds != 0 {
			t.Fatalf("old implicit-v9 did not latch=%+v", before)
		}
		clock.Advance(0, uint64(2*time.Second))
		if !timer.Fire() {
			t.Fatal("DNS timer not armed")
		}
		waitDNSReset(t, timer, 2)
		published := currentEndpoint(r)
		if published == previous || old.closes.Load() != 1 || next.closes.Load() != 0 {
			t.Fatal("implicit replacement did not publish a fresh endpoint")
		}
		clock.Set(4_000_000_000+limit*ms+1_000_000, uint64(2*time.Second))
		got := r.Lifetime()
		if !got.Applicable || !got.RemainingKnown || got.Exhausted || got.RemainingSeconds != float64(limit-1)/1000 {
			t.Fatalf("new implicit origin Lifetime=%+v old=%+v", got, before)
		}
	})

	t.Run("separate-published-instances", func(t *testing.T) {
		lookup1 := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}})
		lookup2 := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}})
		firstConn, secondConn := newRuntimeConn(), newRuntimeConn()
		first, firstClock, firstTimer := newDNSRuntime(t, wire.ProtocolV5, 4739, lookup1, func(context.Context, netip.AddrPort) (transport.Conn, error) {
			return firstConn, nil
		})
		second, _, secondTimer := newDNSRuntime(t, wire.ProtocolV5, 4739, lookup2, func(context.Context, netip.AddrPort) (transport.Conn, error) {
			return secondConn, nil
		})
		if err := first.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := second.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitDNSReset(t, firstTimer, 1)
		waitDNSReset(t, secondTimer, 1)
		if currentEndpoint(first) == currentEndpoint(second) {
			t.Fatal("separate runtimes shared published endpoint")
		}
		firstClock.SetWall(limit * ms)
		if _, err := first.Pack(context.Background(), validPackerLogs(t), nil); err == nil {
			t.Fatal("first expired instance data unexpectedly succeeded")
		}
		if !first.Lifetime().Exhausted || second.Lifetime().Exhausted {
			t.Fatalf("instance latch leaked: first=%+v second=%+v", first.Lifetime(), second.Lifetime())
		}
	})
}

type lifetimeBarrierClock struct {
	clock   *testclock.Clock
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *lifetimeBarrierClock) Now() (uint64, uint64) {
	wall, mono := c.clock.Now()
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	return wall, mono
}

// This clock can be armed after a literal v5 runtime has finished Start.
// Only the next caller pauses, so a held observation cannot block the clock
// used by another observation during the same shutdown drain.
type lifetimeArmedClock struct {
	clock   *testclock.Clock
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (c *lifetimeArmedClock) Now() (uint64, uint64) {
	wall, mono := c.clock.Now()
	if c.armed.CompareAndSwap(true, false) {
		close(c.entered)
		<-c.release
	}
	return wall, mono
}

func TestLifetimeConcurrentShutdown(t *testing.T) {
	t.Run("clock-sample-and-closing-drain", func(t *testing.T) {
		clock := &lifetimeArmedClock{
			clock:   testclock.New(4_000_000_000, 1),
			entered: make(chan struct{}), release: make(chan struct{}),
		}
		conn := newRuntimeConn()
		r := newRuntimeForTest(t, wire.ProtocolV5, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) {
			return conn, nil
		}, clock)
		if err := r.Start(context.Background()); err != nil {
			t.Fatal(err)
		}

		consumeCtx, cancelConsume := context.WithCancel(context.Background())
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 3*time.Second)
		consumeEntered, consumeCanceled, consumeRelease := make(chan struct{}), make(chan struct{}), make(chan struct{})
		consumeResult, shutdownResult := make(chan error, 1), make(chan error, 2)
		observation := make(chan LifetimeSnapshot, 1)
		consumeJoined, observationJoined, shutdownJoined := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var releaseClockOnce, releaseConsumeOnce sync.Once
		releaseClock := func() { releaseClockOnce.Do(func() { close(clock.release) }) }
		releaseConsume := func() { releaseConsumeOnce.Do(func() { close(consumeRelease) }) }
		observationStarted, shutdownStarted := false, false
		t.Cleanup(func() {
			// Release every hook before any join, even when an assertion fails
			// before shutdown or the observation goroutine has been started.
			releaseClock()
			cancelConsume()
			releaseConsume()
			cancelShutdown()
			joinCtx, cancelJoin := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelJoin()
			joins := []struct {
				name    string
				done    <-chan struct{}
				started bool
			}{
				{"consume", consumeJoined, true},
				{"observation", observationJoined, observationStarted},
				{"shutdown", shutdownJoined, shutdownStarted},
			}
			for _, join := range joins {
				if join.started {
					select {
					case <-join.done:
					case <-joinCtx.Done():
						t.Errorf("%s helper did not join after releasing all hooks", join.name)
					}
				}
			}
		})
		go func() {
			defer close(consumeJoined)
			consumeResult <- r.Consume(consumeCtx, func(ctx context.Context) error {
				close(consumeEntered)
				<-ctx.Done()
				close(consumeCanceled)
				<-consumeRelease
				return ctx.Err()
			})
		}()
		waitRuntimeSignal(t, consumeEntered)
		clock.armed.Store(true)
		observationStarted = true
		go func() {
			defer close(observationJoined)
			observation <- r.Lifetime()
		}()
		waitRuntimeSignal(t, clock.entered)

		var remaining atomic.Int32
		remaining.Store(2)
		shutdownStarted = true
		for range 2 {
			go func() {
				defer func() {
					if remaining.Add(-1) == 0 {
						close(shutdownJoined)
					}
				}()
				shutdownResult <- r.Shutdown(shutdownCtx)
			}()
		}
		// Cancellation is after closing under lifecycle. It must happen while
		// the observation is still in Clock.Now, proving no lifecycle lock is
		// held across the clock call. Consume then holds the drain open.
		waitRuntimeSignal(t, consumeCanceled)
		releaseClock()
		select {
		case got := <-observation:
			if got != (LifetimeSnapshot{}) {
				t.Fatalf("clock sample spanning closing produced active snapshot: %+v", got)
			}
		case <-time.After(time.Second):
			t.Fatal("observation waited behind shutdown drain")
		}
		if got := r.Lifetime(); got != (LifetimeSnapshot{}) {
			t.Fatalf("new observation during closing drain=%+v", got)
		}
		select {
		case err := <-shutdownResult:
			t.Fatalf("Shutdown returned before admitted callback released: %v", err)
		default:
		}
		releaseConsume()
		select {
		case err := <-consumeResult:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled admitted callback=%v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("admitted callback did not drain after release")
		}
		for range 2 {
			select {
			case err := <-shutdownResult:
				if err != nil {
					t.Fatalf("Shutdown after callback drain=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Shutdown did not finish after callback drain")
			}
		}
		if conn.closes.Load() != 1 {
			t.Fatalf("socket closes=%d, want one owner", conn.closes.Load())
		}
	})

	// The sample/floor barrier exercises the required ordering without a sleep:
	// Lifetime samples the rewindable clock, then a concurrent State operation
	// advances the reservation floor before the scalar copy.
	base := lifetimeTestOrigin
	clock := testclock.New(base+1_000_000, 1)
	barrier := &lifetimeBarrierClock{clock: clock, entered: make(chan struct{}), release: make(chan struct{})}
	var barrierReleaseOnce sync.Once
	barrierRelease := func() { barrierReleaseOnce.Do(func() { close(barrier.release) }) }
	state := timedLifetimeState(t, wire.ProtocolV5, base)
	runtime := lifetimeRuntime(state, barrier)
	result := make(chan LifetimeSnapshot, 1)
	resultDone := make(chan struct{})
	go func() {
		defer close(resultDone)
		result <- runtime.Lifetime()
	}()
	t.Cleanup(func() {
		barrierRelease()
		select {
		case <-resultDone:
		case <-time.After(time.Second):
			t.Errorf("Lifetime helper did not join")
		}
	})
	select {
	case <-barrier.entered:
	case <-time.After(time.Second):
		t.Fatal("Lifetime did not sample clock")
	}
	shape := mustShape(t, state, 0)
	wall := base + (uint64(math.MaxUint32)-1)*1_000_000
	record := testRecord(t, shape, wall)
	operation := make(chan error, 1)
	operationDone := make(chan struct{})
	go func() {
		defer close(operationDone)
		packet, err := state.BeginData(wall, 2, 0, DataRequest{Records: []wire.WireRecord{record}, V5SamplingRates: []uint32{0}})
		if err == nil {
			buffer := make([]byte, packet.DatagramLength())
			var n int
			n, err = packet.Encode(buffer)
			if err == nil {
				_, err = state.Commit(packet, n, nil)
			}
		}
		operation <- err
	}()
	t.Cleanup(func() {
		barrierRelease()
		select {
		case <-operationDone:
		case <-time.After(time.Second):
			t.Errorf("reservation helper did not join")
		}
	})
	select {
	case err := <-operation:
		if err != nil {
			t.Fatalf("reservation operation=%v", err)
		}
	case <-time.After(time.Second):
		barrierRelease()
		t.Fatal("reservation waited behind Lifetime clock sample")
	}
	barrierRelease()
	select {
	case got := <-result:
		if !got.RemainingKnown || got.RemainingSeconds != 0.002 || got.Exhausted {
			t.Fatalf("sample/floor result=%+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("Lifetime remained blocked after floor copy")
	}

	t.Run("observation-during-publication", func(t *testing.T) {
		dialEntered, dialRelease := make(chan struct{}), make(chan struct{})
		var dialReleaseOnce sync.Once
		releaseDial := func() { dialReleaseOnce.Do(func() { close(dialRelease) }) }
		conn := newRuntimeConn()
		publication := newRuntimeForTest(t, wire.ProtocolV5, runtimeRemote, func(ctx context.Context, _ netip.AddrPort) (transport.Conn, error) {
			close(dialEntered)
			select {
			case <-dialRelease:
				return conn, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}, testclock.New(4_000_000_000, 1))
		startDone := make(chan error, 1)
		startFinished := make(chan struct{})
		go func() {
			defer close(startFinished)
			startDone <- publication.Start(context.Background())
		}()
		t.Cleanup(func() {
			releaseDial()
			select {
			case <-startFinished:
			case <-time.After(time.Second):
				t.Errorf("publication helper did not join")
			}
		})
		select {
		case <-dialEntered:
		case <-time.After(time.Second):
			t.Fatal("publication did not reach dial barrier")
		}
		observation := make(chan LifetimeSnapshot, 1)
		observationDone := make(chan struct{})
		go func() {
			defer close(observationDone)
			observation <- publication.Lifetime()
		}()
		t.Cleanup(func() {
			releaseDial()
			select {
			case <-observationDone:
			case <-time.After(time.Second):
				t.Errorf("publication observation helper did not join")
			}
		})
		select {
		case got := <-observation:
			if got != (LifetimeSnapshot{}) {
				t.Fatalf("during unpublished candidate Lifetime=%+v", got)
			}
		case <-time.After(time.Second):
			t.Fatal("Lifetime waited during publication dial")
		}
		releaseDial()
		select {
		case err := <-startDone:
			if err != nil {
				t.Fatalf("publication Start=%v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("publication did not finish after dial release")
		}
		if got := publication.Lifetime(); !got.Applicable {
			t.Fatalf("post-publication Lifetime=%+v", got)
		}
	})

	// Actual publication, admitted export, cancellation and bounded concurrent
	// Shutdown share the same runtime lifecycle lock. Closing the scripted
	// connection releases the held write, and no post-closing snapshot appears.
	entered := make(chan struct{})
	release := make(chan struct{})
	var writeReleaseOnce sync.Once
	releaseWrite := func() { writeReleaseOnce.Do(func() { close(release) }) }
	conn := newRuntimeConn(testtransport.WriteStep{N: 72, Started: entered, Wait: release})
	writeClock := testclock.New(4_000_000_000, 1)
	r := newRuntimeForTest(t, wire.ProtocolV5, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) {
		return conn, nil
	}, writeClock)
	if err := r.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	logs := validPackerLogs(t)
	packDone := make(chan error, 1)
	packFinished := make(chan struct{})
	go func() {
		defer close(packFinished)
		_, err := r.Pack(context.Background(), logs, nil)
		packDone <- err
	}()
	t.Cleanup(func() {
		releaseWrite()
		select {
		case <-packFinished:
		case <-time.After(time.Second):
			t.Errorf("held export helper did not join")
		}
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("admitted export did not reach held write")
	}
	observeDone := make(chan struct{})
	go func() {
		for i := 0; i < 64; i++ {
			_ = r.Lifetime()
		}
		close(observeDone)
	}()
	t.Cleanup(func() {
		releaseWrite()
		select {
		case <-observeDone:
		case <-time.After(time.Second):
			t.Errorf("observation helper did not join")
		}
	})
	select {
	case <-observeDone:
	case <-time.After(time.Second):
		t.Fatal("observation loop waited behind held export")
	}
	shutdownDone := make(chan error, 2)
	var shutdownRemaining atomic.Int32
	shutdownRemaining.Store(2)
	shutdownJoined := make(chan struct{})
	for range 2 {
		go func() {
			defer func() {
				if shutdownRemaining.Add(-1) == 0 {
					close(shutdownJoined)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			shutdownDone <- r.Shutdown(ctx)
		}()
	}
	t.Cleanup(func() {
		releaseWrite()
		select {
		case <-shutdownJoined:
		case <-time.After(3 * time.Second):
			t.Errorf("concurrent Shutdown helpers did not join")
		}
	})
	shutdownResults := make([]error, 0, 2)
	for range 2 {
		select {
		case err := <-shutdownDone:
			shutdownResults = append(shutdownResults, err)
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent Shutdown deadlocked behind export/Lifetime")
		}
	}
	for _, err := range shutdownResults {
		if err != nil {
			t.Fatalf("concurrent Shutdown=%v, want nil", err)
		}
	}
	select {
	case <-shutdownJoined:
	case <-time.After(time.Second):
		t.Fatal("concurrent Shutdown helpers did not finish")
	}
	releaseWrite()
	select {
	case <-packDone:
	case <-time.After(time.Second):
		t.Fatal("held export did not clean up")
	}
	select {
	case <-observeDone:
	case <-time.After(time.Second):
		t.Fatal("observation loop did not finish")
	}
	if got := r.Lifetime(); got != (LifetimeSnapshot{}) {
		t.Fatalf("post-shutdown Lifetime=%+v", got)
	}
	if conn.closes.Load() != 1 {
		t.Fatalf("socket closes=%d, want one owner", conn.closes.Load())
	}

	t.Run("held-refresh-and-concurrent-shutdown", func(t *testing.T) {
		templateLength, _ := runtimeLengths(wire.ProtocolV9)
		entered, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		releaseRefresh := func() { releaseOnce.Do(func() { close(release) }) }
		lookup := testtransport.NewResolver(testtransport.ResolverStep{Answers: []netip.Addr{runtimeRemote.Addr()}})
		conn := newRuntimeConn(append(runtimeBootstrapSteps(wire.ProtocolV9), testtransport.WriteStep{N: templateLength, Started: entered, Wait: release})...)
		fixture := newResourceRuntime(t, wire.ProtocolV9, lookup, conn)
		t.Cleanup(func() {
			releaseRefresh()
			_ = fixture.r.Close()
		})
		if err := fixture.r.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitDNSReset(t, fixture.timers[0], 1)
		waitRefreshReset(t, fixture.timers[1], 1)
		fixture.clock.Advance(0, uint64(time.Minute))
		if !fixture.timers[1].Fire() {
			t.Fatal("refresh timer not armed")
		}
		waitRuntimeSignal(t, entered)
		observation := make(chan LifetimeSnapshot, 1)
		observationDone := make(chan struct{})
		shutdownStarted := false
		shutdownDone := make(chan error, 2)
		var shutdownRemaining atomic.Int32
		shutdownJoined := make(chan struct{})
		go func() {
			defer close(observationDone)
			observation <- fixture.r.Lifetime()
		}()
		t.Cleanup(func() {
			releaseRefresh()
			if shutdownStarted {
				select {
				case <-shutdownJoined:
				case <-time.After(3 * time.Second):
					t.Errorf("refresh-held Shutdown helpers did not join")
				}
			}
			select {
			case <-observationDone:
			case <-time.After(time.Second):
				t.Errorf("refresh observation helper did not join")
			}
		})
		select {
		case got := <-observation:
			if !got.Applicable || !got.RemainingKnown || got.Exhausted {
				t.Fatalf("observation while refresh held=%+v", got)
			}
		case <-time.After(time.Second):
			t.Fatal("Lifetime waited on refresh send permit")
		}
		select {
		case <-observationDone:
		case <-time.After(time.Second):
			t.Fatal("refresh observation did not finish while write was held")
		}
		shutdownResults := make([]error, 0, 2)
		shutdownRemaining.Store(2)
		shutdownStarted = true
		for range 2 {
			go func() {
				defer func() {
					if shutdownRemaining.Add(-1) == 0 {
						close(shutdownJoined)
					}
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				shutdownDone <- fixture.r.Shutdown(ctx)
			}()
		}
		for range 2 {
			select {
			case err := <-shutdownDone:
				shutdownResults = append(shutdownResults, err)
			case <-time.After(2 * time.Second):
				t.Fatal("refresh-held concurrent Shutdown deadlocked")
			}
		}
		for _, err := range shutdownResults {
			if err != nil {
				t.Fatalf("refresh-held Shutdown=%v, want nil", err)
			}
		}
		select {
		case <-shutdownJoined:
		case <-time.After(time.Second):
			t.Fatal("refresh-held Shutdown helpers did not finish")
		}
		if got := fixture.r.Lifetime(); got != (LifetimeSnapshot{}) {
			t.Fatalf("post-closing refresh Lifetime=%+v", got)
		}
		assertResourceRuntimeClosed(t, fixture, 1)
	})

	t.Run("canceled-admitted-export", func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		releaseWrite := func() { releaseOnce.Do(func() { close(release) }) }
		conn := newRuntimeConn(testtransport.WriteStep{N: 72, Started: entered, Wait: release})
		r := newRuntimeForTest(t, wire.ProtocolV5, runtimeRemote, func(context.Context, netip.AddrPort) (transport.Conn, error) {
			return conn, nil
		}, testclock.New(4_000_000_000, 1))
		if err := r.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		logs := validPackerLogs(t)
		ctx, cancel := context.WithCancel(context.Background())
		packDone := make(chan error, 1)
		packFinished := make(chan struct{})
		go func() {
			defer close(packFinished)
			_, err := r.Pack(ctx, logs, nil)
			packDone <- err
		}()
		t.Cleanup(func() {
			cancel()
			releaseWrite()
			select {
			case <-packFinished:
			case <-time.After(time.Second):
				t.Errorf("canceled export helper did not join")
			}
			_ = r.Close()
		})
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("canceled export did not reach held write")
		}
		cancel()
		select {
		case err := <-packDone:
			if err == nil {
				t.Fatal("canceled admitted export unexpectedly succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("canceled admitted export did not drain")
		}
		if got := r.Lifetime(); !got.Applicable {
			t.Fatal("canceled export unpublished active epoch")
		}
	})
}
