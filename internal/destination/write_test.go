package destination

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/ipfix"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow5"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire/netflow9"
)

func TestWriteStreamingRealWriters(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol wire.Protocol
		writer   wire.ContractWriter
		sample   uint32
	}{
		{name: "v5", protocol: wire.ProtocolV5, writer: netflow5.Writer{}, sample: 1000},
		{name: "v9", protocol: wire.ProtocolV9, writer: netflow9.Writer{}},
		{name: "ipfix", protocol: wire.ProtocolIPFIX, writer: ipfix.Writer{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, err := NewState(compiledMapping(t, tc.protocol), tc.writer, streamConfig(tc.protocol))
			if err != nil {
				t.Fatal(err)
			}
			if tc.protocol != wire.ProtocolV5 {
				bootstrap(t, state, 3_000_000_000, 1)
			}
			sequenceBefore := state.Sequence()
			shape := mustShape(t, state, 0)
			record := testRecord(t, shape, 3_000_000_000)
			dst := make([]byte, state.Config().MaxDatagramSize)
			packet, err := state.BeginDataStream(3_000_000_000, 2, 0, dst, tc.sample)
			if err != nil {
				t.Fatalf("BeginDataStream: %v", err)
			}
			if err := packet.Append(record, tc.sample); err != nil {
				t.Fatalf("Append: %v", err)
			}
			n, err := packet.Finish()
			if err != nil {
				t.Fatalf("Finish: %v", err)
			}
			if n != int(packet.DatagramLength()) || n < 1 {
				t.Fatalf("length=(%d,%d)", n, packet.DatagramLength())
			}
			if tc.protocol == wire.ProtocolV5 && binary.BigEndian.Uint16(dst[2:4]) != 1 {
				t.Fatalf("v5 count=%d", binary.BigEndian.Uint16(dst[2:4]))
			}
			result, err := state.Commit(packet, n, nil)
			if err != nil || !result.Committed {
				t.Fatalf("Commit=(%+v,%v)", result, err)
			}
			wantSequence := sequenceBefore + 1
			if state.Sequence() != wantSequence {
				t.Fatalf("sequence=%d, want %d", state.Sequence(), wantSequence)
			}
		})
	}
}

func TestWriteStreamingV5SamplingAndAtomicAppend(t *testing.T) {
	state, err := NewState(compiledMapping(t, wire.ProtocolV5), netflow5.Writer{}, streamConfig(wire.ProtocolV5))
	if err != nil {
		t.Fatal(err)
	}
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, 3_000_000_000)
	badFamily, err := wire.NewWireRecord(wire.FamilyIPv6, []wire.Value{wire.UintValue(1)})
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, state.Config().MaxDatagramSize)
	packet, err := state.BeginDataStream(3_000_000_000, 1, 0, dst, 1000)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), dst...)
	if err := packet.Append(record, 1001); !errors.Is(err, ErrInvalidConfig) || !bytes.Equal(dst, before) {
		t.Fatalf("sampling rejection=(%v,%v)", err, !bytes.Equal(dst, before))
	}
	if err := packet.Append(badFamily, 1000); err == nil || !bytes.Equal(dst, before) {
		t.Fatalf("value rejection=(%v,%v)", err, !bytes.Equal(dst, before))
	}
	if err := packet.Append(record, 1000); err != nil {
		t.Fatalf("valid append: %v", err)
	}
	beforeSecond := append([]byte(nil), dst...)
	if err := packet.Append(record, 1001); !errors.Is(err, ErrInvalidConfig) || !bytes.Equal(dst, beforeSecond) {
		t.Fatalf("second sampling rejection=(%v,%v)", err, !bytes.Equal(dst, beforeSecond))
	}
	n, err := packet.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(dst[22:24]); got != 1000 {
		t.Fatalf("sampling=%d, want 1000", got)
	}
	if _, err := state.Commit(packet, n, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCommitStreamingFailureAndAbort(t *testing.T) {
	state, err := NewState(compiledMapping(t, wire.ProtocolV5), netflow5.Writer{}, streamConfig(wire.ProtocolV5))
	if err != nil {
		t.Fatal(err)
	}
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, 3_000_000_000)
	dst := make([]byte, state.Config().MaxDatagramSize)
	packet, err := state.BeginDataStream(3_000_000_000, 1, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := packet.Append(record, 0); err != nil {
		t.Fatal(err)
	}
	n, err := packet.Finish()
	if err != nil {
		t.Fatal(err)
	}
	result, err := state.Commit(packet, n-1, nil)
	if err != nil || result.Class != WriteShortNil || result.Committed || state.Sequence() != 0 {
		t.Fatalf("short commit=(%+v,%v), sequence=%d", result, err, state.Sequence())
	}
	if err := packet.Abort(); !errors.Is(err, ErrTransaction) {
		t.Fatalf("committed packet Abort=%v", err)
	}

	packet, err = state.BeginDataStream(2_000_000_000, 2, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := packet.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if _, err := state.BeginDataStream(2_000_000_000, 3, 0, dst, 0); err != nil {
		t.Fatalf("begin after Abort: %v", err)
	}
}

func TestFailureStreamingEmptyFinishAndRestartStaleHandle(t *testing.T) {
	state, err := NewState(compiledMapping(t, wire.ProtocolV5), netflow5.Writer{}, streamConfig(wire.ProtocolV5))
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, state.Config().MaxDatagramSize)
	packet, err := state.BeginDataStream(3_000_000_000, 1, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := packet.Finish(); !errors.Is(err, wire.ErrPacketEmpty) {
		t.Fatalf("empty Finish=%v", err)
	}
	active, err := state.BeginDataStream(3_000_000_000, 2, 0, dst, 0)
	if err != nil {
		t.Fatalf("begin after empty Finish: %v", err)
	}
	if _, err := state.BeginDataStream(3_000_000_000, 3, 0, dst, 0); !errors.Is(err, ErrTransaction) {
		t.Fatalf("second pending begin=%v", err)
	}
	if err := packet.Abort(); !errors.Is(err, ErrTransaction) {
		t.Fatalf("empty-finished stale Abort=%v", err)
	}
	state.Restart()
	if err := active.Abort(); !errors.Is(err, ErrTransaction) {
		t.Fatalf("restart stale Abort=%v", err)
	}
	active, err = state.BeginDataStream(3_000_000_000, 4, 0, dst, 0)
	if err != nil {
		t.Fatalf("begin after restart=(%+v,%v)", active, err)
	}
	_ = active.Abort()
}

func TestOversizeStreamingAndUnsupportedWriter(t *testing.T) {
	state, err := NewState(compiledMapping(t, wire.ProtocolIPFIX), &recordingWriter{}, streamConfig(wire.ProtocolIPFIX))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.BeginDataStream(3_000_000_000, 1, 0, make([]byte, 512), 0); !errors.Is(err, ErrStreamingUnsupported) {
		t.Fatalf("unsupported stream err=%v", err)
	}

	state, err = NewState(tinyCompiledMapping(t, wire.ProtocolIPFIX), ipfix.Writer{}, func() Config {
		config := streamConfig(wire.ProtocolIPFIX)
		config.MaxDatagramSize = 128
		return config
	}())
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, state, 3_000_000_000, 1)
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, 3_000_000_000)
	packet, err := state.BeginDataStream(3_000_000_000, 2, 0, make([]byte, 21), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := packet.Append(record, 0); !errors.Is(err, wire.ErrShortBuffer) {
		t.Fatalf("oversize append=%v, want short buffer", err)
	}
	if err := packet.Abort(); err != nil {
		t.Fatalf("oversize abort: %v", err)
	}
}

func TestWriteStreamingMultiRecordProtocolCounts(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV5, wire.ProtocolV9, wire.ProtocolIPFIX} {
		t.Run(protocol.String(), func(t *testing.T) {
			state := streamingStateWith(t, protocol, func(config *Config) {
				if protocol == wire.ProtocolV9 {
					config.V9RefreshPacketCount = 1
				}
				if protocol == wire.ProtocolIPFIX {
					config.IPFIXDataMessageRefreshCount = 1
				}
			})
			sequenceBefore := state.Sequence()
			shape := mustShape(t, state, 0)
			record := testRecord(t, shape, 3_000_000_000)
			dst := make([]byte, state.Config().MaxDatagramSize)
			packet, err := state.BeginDataStream(4_000_000_000, 2, 0, dst, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := packet.Append(record, 0); err != nil {
				t.Fatal(err)
			}
			if err := packet.Append(record, 0); err != nil {
				t.Fatal(err)
			}
			n, err := packet.Finish()
			if err != nil {
				t.Fatal(err)
			}
			if packet.DataRecords() != 2 || packet.DatagramLength() != uint64(n) {
				t.Fatalf("packet records/length=(%d,%d), want (2,%d)", packet.DataRecords(), packet.DatagramLength(), n)
			}
			if got := binary.BigEndian.Uint16(dst[2:4]); protocol == wire.ProtocolIPFIX {
				if int(got) != n {
					t.Fatalf("ipfix message length=%d, want %d", got, n)
				}
			} else if got != 2 {
				t.Fatalf("%s data count=%d, want 2", protocol, got)
			}
			result, err := state.Commit(packet, n, nil)
			if err != nil || !result.Committed {
				t.Fatalf("Commit=(%+v,%v)", result, err)
			}
			if protocol != wire.ProtocolV5 && !result.RefreshDue {
				t.Fatalf("%s refresh not due after configured data threshold", protocol)
			}
			wantSequence := sequenceBefore + 2
			if protocol == wire.ProtocolV9 {
				wantSequence = sequenceBefore + 1
			}
			if state.Sequence() != wantSequence {
				t.Fatalf("sequence=%d, want %d", state.Sequence(), wantSequence)
			}
		})
	}
}

func TestWriteStreamingCopiedHandleUsesPendingScalars(t *testing.T) {
	state := streamingState(t, wire.ProtocolV5)
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, 3_000_000_000)
	dst := make([]byte, state.Config().MaxDatagramSize)
	packet, err := state.BeginDataStream(3_000_000_000, 1, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	copyBeforeAppend := packet
	if err := packet.Append(record, 0); err != nil {
		t.Fatal(err)
	}
	if err := packet.Append(record, 0); err != nil {
		t.Fatal(err)
	}
	n, err := copyBeforeAppend.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if copyBeforeAppend.DataRecords() != 2 || copyBeforeAppend.DatagramLength() != uint64(n) {
		t.Fatalf("copied handle records/length=(%d,%d), want (2,%d)", copyBeforeAppend.DataRecords(), copyBeforeAppend.DatagramLength(), n)
	}
	result, err := state.Commit(copyBeforeAppend, n, nil)
	if err != nil || !result.Committed || state.Sequence() != 2 {
		t.Fatalf("copied Commit=(%+v,%v), sequence=%d", result, err, state.Sequence())
	}
	if err := copyBeforeAppend.Append(record, 0); !errors.Is(err, ErrTransaction) {
		t.Fatalf("stale copied Append=%v", err)
	}
}

func TestWriteStreamingAllWriteResultClasses(t *testing.T) {
	cases := []struct {
		name      string
		n         func(int) int
		writeErr  error
		class     WriteClass
		committed bool
		wantErr   error
	}{
		{name: "full-nil", n: func(length int) int { return length }, class: WriteFull, committed: true},
		{name: "short-nil", n: func(length int) int { return length - 1 }, class: WriteShortNil},
		{name: "zero-nil", n: func(int) int { return 0 }, class: WriteZeroNil},
		{name: "short-error", n: func(length int) int { return length - 1 }, writeErr: errors.New("write"), class: WriteShortError},
		{name: "zero-error", n: func(int) int { return 0 }, writeErr: errors.New("write"), class: WriteZeroError},
		{name: "full-error", n: func(length int) int { return length }, writeErr: errors.New("write"), class: WriteFullError},
		{name: "invalid-n", n: func(length int) int { return length + 1 }, class: WriteInvalid, wantErr: ErrInvalidWrite},
	}
	for _, protocol := range []wire.Protocol{wire.ProtocolV5, wire.ProtocolV9, wire.ProtocolIPFIX} {
		for _, tc := range cases {
			t.Run(protocol.String()+"/"+tc.name, func(t *testing.T) {
				state := streamingState(t, protocol)
				sequenceBefore := state.Sequence()
				shape := mustShape(t, state, 0)
				record := testRecord(t, shape, 3_000_000_000)
				dst := make([]byte, state.Config().MaxDatagramSize)
				packet, err := state.BeginDataStream(4_000_000_000, 2, 0, dst, 0)
				if err != nil {
					t.Fatal(err)
				}
				if err := packet.Append(record, 0); err != nil {
					t.Fatal(err)
				}
				if err := packet.Append(record, 0); err != nil {
					t.Fatal(err)
				}
				n, err := packet.Finish()
				if err != nil {
					t.Fatal(err)
				}
				result, err := state.Commit(packet, tc.n(n), tc.writeErr)
				if result.Class != tc.class || result.Committed != tc.committed || !errors.Is(err, tc.wantErr) {
					t.Fatalf("Commit=(%+v,%v), want class=%v committed=%v err=%v", result, err, tc.class, tc.committed, tc.wantErr)
				}
				wantSequence := sequenceBefore + 2
				if tc.committed {
					if protocol == wire.ProtocolV9 {
						wantSequence = sequenceBefore + 1
					}
				} else {
					wantSequence = sequenceBefore
				}
				if state.Sequence() != wantSequence {
					t.Fatalf("sequence=%d, want %d", state.Sequence(), wantSequence)
				}
			})
		}
	}
}

func TestWriteStreamingLogicalWallAmbiguousAndInvalidRollback(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV5, wire.ProtocolV9, wire.ProtocolIPFIX} {
		t.Run(protocol.String(), func(t *testing.T) {
			state := streamingState(t, protocol)
			shape := mustShape(t, state, 0)
			record := testRecord(t, shape, 3_000_000_000)
			dst := make([]byte, state.Config().MaxDatagramSize)
			ambiguous, err := state.BeginDataStream(4_000_000_000, 2, 0, dst, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := ambiguous.Append(record, 0); err != nil {
				t.Fatal(err)
			}
			n, err := ambiguous.Finish()
			if err != nil {
				t.Fatal(err)
			}
			result, err := state.Commit(ambiguous, n-1, nil)
			if err != nil || result.Class != WriteShortNil || result.Committed {
				t.Fatalf("ambiguous Commit=(%+v,%v)", result, err)
			}
			retry, err := state.BeginDataStream(3_000_000_000, 3, 0, dst, 0)
			if err != nil {
				t.Fatal(err)
			}
			if retry.LogicalSendInstant() != 4_000_000_000 {
				t.Fatalf("ambiguous retry instant=%d, want 4000000000", retry.LogicalSendInstant())
			}
			if err := retry.Abort(); err != nil {
				t.Fatal(err)
			}

			invalidState := streamingState(t, protocol)
			invalidShape := mustShape(t, invalidState, 0)
			invalidRecord := testRecord(t, invalidShape, 4_000_000_000)
			invalidDst := make([]byte, invalidState.Config().MaxDatagramSize)
			invalid, err := invalidState.BeginDataStream(4_000_000_000, 4, 0, invalidDst, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := invalid.Append(invalidRecord, 0); err != nil {
				t.Fatal(err)
			}
			n, err = invalid.Finish()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := invalidState.Commit(invalid, n+1, nil); !errors.Is(err, ErrInvalidWrite) {
				t.Fatalf("invalid Commit err=%v", err)
			}
			rolled, err := invalidState.BeginDataStream(3_000_000_000, 5, 0, invalidDst, 0)
			if err != nil {
				t.Fatal(err)
			}
			if rolled.LogicalSendInstant() != 3_000_000_000 {
				t.Fatalf("invalid retry instant=%d, want 3000000000", rolled.LogicalSendInstant())
			}
			if err := rolled.Abort(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWriteStreamingMixedSliceAndStreamTransactions(t *testing.T) {
	state := streamingState(t, wire.ProtocolV5)
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, 3_000_000_000)
	dst := make([]byte, state.Config().MaxDatagramSize)
	stream, err := state.BeginDataStream(3_000_000_000, 1, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	request := DataRequest{Records: []wire.WireRecord{record}, V5SamplingRates: []uint32{0}}
	if _, err := state.BeginData(3_000_000_000, 2, 0, request); !errors.Is(err, ErrTransaction) {
		t.Fatalf("slice Begin while stream pending=%v", err)
	}
	if err := stream.Abort(); err != nil {
		t.Fatal(err)
	}
	packet, err := state.BeginData(3_000_000_000, 3, 0, request)
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, packet)
}

func TestWriteStreamingResetLifecycle(t *testing.T) {
	resets := 0
	writer := &resetSpyWriter{resets: &resets}
	state, err := NewState(compiledMapping(t, wire.ProtocolV5), writer, streamConfig(wire.ProtocolV5))
	if err != nil {
		t.Fatal(err)
	}
	writer.appender.beginErr = errors.New("begin")
	if _, err := state.BeginDataStream(3_000_000_000, 1, 0, make([]byte, 65507), 0); !errors.Is(err, writer.appender.beginErr) {
		t.Fatalf("failed Begin=%v", err)
	}
	if resets < 2 {
		t.Fatalf("failed Begin resets=%d, want at least 2", resets)
	}
	writer.appender.beginErr = nil
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, 2_000_000_000)
	dst := make([]byte, state.Config().MaxDatagramSize)
	packet, err := state.BeginDataStream(2_000_000_000, 2, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := packet.Append(record, 0); err != nil {
		t.Fatal(err)
	}
	if packet.DatagramLength() >= uint64(len(dst)) {
		t.Fatalf("test buffer is not over-capacity: packet=%d buffer=%d", packet.DatagramLength(), len(dst))
	}
	beforeFailedFinish := resets
	if len(writer.appender.dst) != len(dst) {
		t.Fatalf("spy retained caller buffer length=%d, want %d", len(writer.appender.dst), len(dst))
	}
	writer.appender.finishErr = errors.New("finish")
	if _, err := packet.Finish(); !errors.Is(err, writer.appender.finishErr) {
		t.Fatalf("failed Finish=%v", err)
	}
	if resets != beforeFailedFinish+1 || writer.appender.dst != nil {
		t.Fatalf("failed Finish reset count/buffer=(%d,%v), want (%d,true)", resets, writer.appender.dst, beforeFailedFinish+1)
	}
	writer.appender.finishErr = nil
	packet, err = state.BeginDataStream(2_000_000_000, 3, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := packet.Append(record, 0); err != nil {
		t.Fatal(err)
	}
	beforeSuccessfulFinish := resets
	n, err := packet.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if resets != beforeSuccessfulFinish+1 || writer.appender.dst != nil {
		t.Fatalf("successful Finish reset count/buffer=(%d,%v), want (%d,true)", resets, writer.appender.dst, beforeSuccessfulFinish+1)
	}
	if result, err := state.Commit(packet, n, nil); err != nil || !result.Committed {
		t.Fatalf("successful Commit=(%+v,%v)", result, err)
	}
	packet, err = state.BeginDataStream(2_000_000_000, 4, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	beforeAbort := resets
	if err := packet.Abort(); err != nil {
		t.Fatal(err)
	}
	if resets != beforeAbort+1 || writer.appender.dst != nil {
		t.Fatalf("Abort reset count/buffer=(%d,%v), want (%d,true)", resets, writer.appender.dst, beforeAbort+1)
	}
	packet, err = state.BeginDataStream(2_000_000_000, 5, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	beforeRestart := resets
	state.Restart()
	if resets != beforeRestart+1 || writer.appender.dst != nil {
		t.Fatalf("Restart reset count/buffer=(%d,%v), want (%d,true)", resets, writer.appender.dst, beforeRestart+1)
	}
}

func TestWriteStreamingLifecycleInvariants(t *testing.T) {
	state := streamingState(t, wire.ProtocolV5)
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, 3_000_000_000)
	dst := make([]byte, state.Config().MaxDatagramSize)
	packet, err := state.BeginDataStream(3_000_000_000, 1, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Commit(packet, 0, nil); !errors.Is(err, ErrTransaction) {
		t.Fatalf("Commit before Finish=%v", err)
	}
	if err := packet.Append(record, 0); err != nil {
		t.Fatal(err)
	}
	if err := packet.Append(record, 0); err != nil {
		t.Fatal(err)
	}
	n, err := packet.Finish()
	if err != nil {
		t.Fatal(err)
	}
	afterFinish := append([]byte(nil), dst...)
	if err := packet.Append(record, 0); !errors.Is(err, ErrTransaction) || !bytes.Equal(dst, afterFinish) {
		t.Fatalf("Append after Finish=(%v,%v)", err, !bytes.Equal(dst, afterFinish))
	}
	if _, err := packet.Finish(); !errors.Is(err, ErrTransaction) || !bytes.Equal(dst, afterFinish) {
		t.Fatalf("second Finish=(%v,%v)", err, !bytes.Equal(dst, afterFinish))
	}
	result, err := state.Commit(packet, n, nil)
	if err != nil || !result.Committed || state.Sequence() != 2 {
		t.Fatalf("final Commit=(%+v,%v), sequence=%d", result, err, state.Sequence())
	}

	stale, err := state.BeginDataStream(3_000_000_000, 2, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	state.Restart()
	if err := stale.Append(record, 0); !errors.Is(err, ErrTransaction) {
		t.Fatalf("stale Append after Restart=%v", err)
	}
	if _, err := stale.Finish(); !errors.Is(err, ErrTransaction) {
		t.Fatalf("stale Finish after Restart=%v", err)
	}
	if _, err := state.Commit(stale, 0, nil); !errors.Is(err, ErrTransaction) {
		t.Fatalf("stale Commit after Restart=%v", err)
	}
	fresh, err := state.BeginDataStream(3_000_000_000, 3, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Append(record, 0); err != nil {
		t.Fatal(err)
	}
	n, err = fresh.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if result, err := state.Commit(fresh, n, nil); err != nil || !result.Committed || state.Sequence() != 1 {
		t.Fatalf("fresh Commit=(%+v,%v), sequence=%d", result, err, state.Sequence())
	}
}

func TestWriteStreamingFinishLengthInvariantRollback(t *testing.T) {
	cases := []struct {
		name string
		n    func(int) int
	}{
		{name: "zero", n: func(int) int { return 0 }},
		{name: "short", n: func(length int) int { return length - 1 }},
		{name: "overlong", n: func(length int) int { return length + 1 }},
		{name: "negative", n: func(int) int { return -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resets := 0
			writer := &resetSpyWriter{resets: &resets}
			state, err := NewState(compiledMapping(t, wire.ProtocolV5), writer, streamConfig(wire.ProtocolV5))
			if err != nil {
				t.Fatal(err)
			}
			shape := mustShape(t, state, 0)
			record := testRecord(t, shape, 3_000_000_000)
			dst := make([]byte, state.Config().MaxDatagramSize)
			packet, err := state.BeginDataStream(4_000_000_000, 1, 0, dst, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := packet.Append(record, 0); err != nil {
				t.Fatal(err)
			}
			const expected = 24 + 48 // NetFlow v5 header plus one mapped record.
			writer.appender.finishN = tc.n(expected)
			writer.appender.forceN = true
			before := resets
			if _, err := packet.Finish(); !errors.Is(err, ErrEncoding) {
				t.Fatalf("Finish=%v, want encoding failure", err)
			}
			if resets != before+1 || writer.appender.dst != nil {
				t.Fatalf("failed Finish reset count/buffer=(%d,%v), want (%d,true)", resets, writer.appender.dst, before+1)
			}
			retry, err := state.BeginDataStream(3_000_000_000, 2, 0, dst, 0)
			if err != nil {
				t.Fatal(err)
			}
			if retry.LogicalSendInstant() != 3_000_000_000 {
				t.Fatalf("rollback instant=%d, want 3000000000", retry.LogicalSendInstant())
			}
			if err := retry.Append(record, 0); err != nil {
				t.Fatal(err)
			}
			writer.appender.forceN = false
			n, err := retry.Finish()
			if err != nil {
				t.Fatal(err)
			}
			if result, err := state.Commit(retry, n, nil); err != nil || !result.Committed {
				t.Fatalf("retry Commit=(%+v,%v)", result, err)
			}
		})
	}
}

func TestWriteStreamingAppendZeroAllocations(t *testing.T) {
	state := streamingState(t, wire.ProtocolV5)
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, 3_000_000_000)
	dst := make([]byte, state.Config().MaxDatagramSize)
	packet, err := state.BeginDataStream(3_000_000_000, 1, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(8, func() {
		if err := packet.Append(record, 0); err != nil {
			panic(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("destination Append allocations=%v, want zero", allocs)
	}
	n, err := packet.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(dst[2:4]); got != 9 {
		t.Fatalf("appended record count=%d, want 9", got)
	}
	if result, err := state.Commit(packet, n, nil); err != nil || !result.Committed || state.Sequence() != 9 {
		t.Fatalf("allocation test Commit=(%+v,%v), sequence=%d", result, err, state.Sequence())
	}
	abortPacket, err := state.BeginDataStream(3_000_000_000, 2, 0, dst, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := abortPacket.Abort(); err != nil {
		t.Fatal(err)
	}
}

type resetSpyWriter struct {
	resets   *int
	appender *resetSpyAppender
}

func (w *resetSpyWriter) Write(dst []byte, request wire.PacketRequest) (int, error) {
	return (netflow5.Writer{}).Write(dst, request)
}

func (w *resetSpyWriter) NewDataPacket() wire.DataPacketAppender {
	w.appender = &resetSpyAppender{inner: (netflow5.Writer{}).NewDataPacket(), resets: w.resets}
	return w.appender
}

type resetSpyAppender struct {
	inner     wire.DataPacketAppender
	resets    *int
	dst       []byte
	beginErr  error
	finishErr error
	finishN   int
	forceN    bool
}

func (a *resetSpyAppender) Begin(dst []byte, request wire.DataPacketRequest) error {
	if a.beginErr != nil {
		return a.beginErr
	}
	if err := a.inner.Begin(dst, request); err != nil {
		return err
	}
	a.dst = dst
	return nil
}

func (a *resetSpyAppender) Append(record wire.WireRecord) error {
	return a.inner.Append(record)
}

func (a *resetSpyAppender) Finish() (int, error) {
	if a.finishErr != nil {
		return 0, a.finishErr
	}
	if a.forceN {
		return a.finishN, nil
	}
	return a.inner.Finish()
}

func (a *resetSpyAppender) Reset() {
	*a.resets++
	a.dst = nil
	a.inner.Reset()
}

func streamingState(t *testing.T, protocol wire.Protocol) *State {
	return streamingStateWith(t, protocol, nil)
}

func streamingStateWith(t *testing.T, protocol wire.Protocol, mutate func(*Config)) *State {
	t.Helper()
	var writer wire.ContractWriter
	switch protocol {
	case wire.ProtocolV5:
		writer = netflow5.Writer{}
	case wire.ProtocolV9:
		writer = netflow9.Writer{}
	case wire.ProtocolIPFIX:
		writer = ipfix.Writer{}
	default:
		t.Fatalf("unsupported protocol %v", protocol)
	}
	config := streamConfig(protocol)
	if mutate != nil {
		mutate(&config)
	}
	state, err := NewState(compiledMapping(t, protocol), writer, config)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != wire.ProtocolV5 {
		bootstrap(t, state, 3_000_000_000, 1)
	}
	return state
}

func streamConfig(protocol wire.Protocol) Config {
	config := DefaultConfig(protocol)
	config.MaxDatagramSize = 65507
	if protocol == wire.ProtocolV5 {
		config.HasUptimeOrigin = true
		config.UptimeOriginUnixNanos = 0
	} else if protocol == wire.ProtocolV9 {
		config.SourceID, config.ObservationDomainID = 42, 42
	} else {
		config.ObservationDomainID = 42
	}
	return config
}
