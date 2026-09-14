package destination

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

const (
	maxTemplateFuzzBytes = 4096
)

// FuzzTemplateCatalog exercises the immutable catalog seam and the bounded
// destination state transitions that consume it.  The catalog lane owns its
// acceptance table; it does not use NewCatalog's result as the oracle.  The
// state lane uses the existing compiler fixtures and drives one small,
// deterministic scenario at a time.  No scenario opens a socket.
func FuzzTemplateCatalog(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, protocolByte, shapeByte, fieldByte, idByte, operationByte, writeByte uint8) {
		if len(data) > maxTemplateFuzzBytes {
			t.Skip()
		}
		if operationByte&1 == 0 {
			checkTemplateFuzzCatalog(t, data, protocolByte, shapeByte, fieldByte, idByte, operationByte)
			return
		}
		checkTemplateFuzzState(t, data, templateFuzzProtocol(protocolByte), operationByte>>1, writeByte)
	})
}

func templateFuzzProtocol(selector uint8) wire.Protocol {
	switch selector % 3 {
	case 0:
		return wire.ProtocolV5
	case 1:
		return wire.ProtocolV9
	default:
		return wire.ProtocolIPFIX
	}
}

func templateFuzzByte(data []byte, index int) byte {
	if len(data) == 0 {
		return 0
	}
	return data[index%len(data)]
}

func checkTemplateFuzzCatalog(t *testing.T, data []byte, protocolByte, shapeByte, fieldByte, idByte, operationByte uint8) {
	t.Helper()
	protocol := templateFuzzProtocol(protocolByte)
	if protocol == wire.ProtocolV5 {
		compiled := compiledMapping(t, protocol)
		catalog, err := NewCatalogFromWire(compiled.Catalog())
		if err != nil {
			t.Fatal(err)
		}
		assertTemplateFuzzCatalog(t, catalog, protocol, compiled.Catalog().ShapeCount())
		return
	}

	spec, wantValid, wantIDs := templateFuzzCatalogSpec(data, protocol, shapeByte, fieldByte, idByte, operationByte)
	before, _, _ := templateFuzzCatalogSpec(data, protocol, shapeByte, fieldByte, idByte, operationByte)
	wireCatalog, err := wire.NewCatalog(spec)
	if (err == nil) != wantValid {
		t.Fatalf("catalog acceptance=%v want %v protocol=%s shapes=%d fields=%d id-mode=%d op=%d err=%v", err == nil, wantValid, protocol, len(spec.Shapes), len(spec.Shapes[0].Fields), idByte%5, operationByte, err)
	}
	if !reflect.DeepEqual(spec, before) {
		t.Fatal("catalog construction mutated caller specification")
	}
	if err != nil {
		adopted, adoptErr := NewCatalogFromWire(wireCatalog)
		if adoptErr == nil || !reflect.DeepEqual(adopted, Catalog{}) {
			t.Fatalf("rejected wire catalog was adoptable: catalog=%+v err=%v", adopted, adoptErr)
		}
		if len(err.Error()) > 96 || !templateFuzzKnownWireError(err) {
			t.Fatalf("catalog returned unstable diagnostic: %v", err)
		}
		return
	}

	catalog, err := NewCatalogFromWire(wireCatalog)
	if err != nil {
		t.Fatalf("adopt valid catalog: %v", err)
	}
	assertTemplateFuzzCatalog(t, catalog, protocol, len(spec.Shapes))
	for i, expected := range before.Shapes {
		shape, ok := catalog.ShapeAt(i)
		if !ok || shape.Family() != expected.Family || shape.RecordLength() != expected.RecordLength || shape.TemplateBytes() != expected.TemplateBytes || !reflect.DeepEqual(shape.Fields(), expected.Fields) {
			t.Fatalf("adopted shape %d differs from caller specification", i)
		}
		// Mutating constructor-owned inputs must not affect the adopted view.
		spec.Shapes[i].Fields[0].ID++
		again, _ := catalog.ShapeAt(i)
		if !reflect.DeepEqual(again.Fields(), expected.Fields) {
			t.Fatalf("adopted shape %d retained caller descriptor storage", i)
		}
	}
	if !reflect.DeepEqual(catalog.IDs(), wantIDs) {
		t.Fatalf("catalog IDs=%v want %v", catalog.IDs(), wantIDs)
	}
	repeat, err := NewCatalogFromWire(wireCatalog)
	if err != nil || !reflect.DeepEqual(catalog.IDs(), repeat.IDs()) {
		t.Fatalf("catalog adoption is not deterministic: first=%v second=%v err=%v", catalog.IDs(), repeat.IDs(), err)
	}
}

func templateFuzzCatalogSpec(data []byte, protocol wire.Protocol, shapeByte, fieldByte, idByte, operationByte uint8) (wire.CatalogSpec, bool, []uint16) {
	shapeCount := 1 + int(shapeByte%17) // 1..17; 17 is the destination boundary.
	fieldCount := 1 + int(fieldByte%65) // 1..65; 65 is the destination boundary.
	idMode := idByte % 5
	catalogMode := (operationByte >> 1) % 4
	idBase := uint32(256)
	shapes := make([]wire.ShapeSpec, shapeCount)
	offset := uint16(templateFuzzByte(data, 0) % 64)
	wantIDs := make([]uint16, shapeCount)
	for shapeIndex := range shapes {
		fields := make([]wire.FieldDescriptor, fieldCount)
		for fieldIndex := range fields {
			fields[fieldIndex] = wire.FieldDescriptor{
				Protocol: protocol,
				Field:    wire.FieldSourcePort,
				ID:       offset + uint16(fieldIndex) + 1,
				Length:   2,
				Encoding: wire.EncodingUnsigned16,
			}
		}
		id := uint32(0)
		switch idMode {
		case 1: // below the template ID minimum
			id = 255
		case 2: // explicit duplicate identity for a multi-shape catalog
			id = 256
		case 3: // outside the uint16 wire identity
			id = 65536
		case 4: // the highest usable base, valid only for one shape
			idBase = 65535
		}
		if idMode == 4 {
			wantIDs[shapeIndex] = uint16(idBase + uint32(shapeIndex))
		} else if idMode == 2 {
			wantIDs[shapeIndex] = 256
		} else {
			wantIDs[shapeIndex] = uint16(256 + shapeIndex)
		}
		templateBytes := uint64(8 + 4*fieldCount)
		recordLength := uint64(2 * fieldCount)
		switch catalogMode {
		case 1:
			templateBytes = 0
		case 2:
			templateBytes = 4097
		case 3:
			recordLength = 0
		}
		shapeProtocol := protocol
		if catalogMode == 3 && shapeIndex == 0 {
			shapeProtocol = wire.ProtocolV9
			if protocol == wire.ProtocolV9 {
				shapeProtocol = wire.ProtocolIPFIX
			}
		}
		shapes[shapeIndex] = wire.ShapeSpec{
			Protocol:      shapeProtocol,
			Family:        wire.FamilyIPv4,
			ID:            id,
			Fields:        fields,
			RecordLength:  recordLength,
			TemplateBytes: templateBytes,
		}
	}
	wantValid := shapeCount <= 16 && fieldCount <= 64 && catalogMode == 0
	switch idMode {
	case 1, 3:
		wantValid = false
	case 2:
		wantValid = wantValid && shapeCount == 1
	case 4:
		wantValid = wantValid && shapeCount == 1
	}
	return wire.CatalogSpec{Protocol: protocol, IDBase: idBase, Shapes: shapes}, wantValid, wantIDs
}

func assertTemplateFuzzCatalog(t *testing.T, catalog Catalog, protocol wire.Protocol, shapeCount int) {
	t.Helper()
	if catalog.Protocol() != protocol || catalog.ShapeCount() != shapeCount {
		t.Fatalf("catalog protocol/count=%s/%d want %s/%d", catalog.Protocol(), catalog.ShapeCount(), protocol, shapeCount)
	}
	if got, want := catalog.String(), fmt.Sprintf("%s catalog (%d shapes)", protocol, shapeCount); got != want {
		t.Fatalf("catalog diagnostic=%q want %q", got, want)
	}
	shape, ok := catalog.ShapeAt(0)
	if !ok || shape.FieldCount() == 0 {
		t.Fatal("catalog has no first shape")
	}
	fields := shape.Fields()
	originalID := fields[0].ID
	fields[0].ID++
	again, ok := catalog.ShapeAt(0)
	if !ok || again.Fields()[0].ID != originalID {
		t.Fatal("catalog accessor exposed mutable descriptor storage")
	}
}

func templateFuzzKnownWireError(err error) bool {
	for _, known := range []error{
		wire.ErrBounds,
		wire.ErrDuplicateIdentity,
		wire.ErrInvalidCatalog,
		wire.ErrInvalidDescriptor,
		wire.ErrInvalidShape,
	} {
		if errors.Is(err, known) {
			return true
		}
	}
	return false
}

func checkTemplateFuzzState(t *testing.T, data []byte, protocol wire.Protocol, operation, writeByte uint8) {
	t.Helper()
	scenario := operation % 10
	wall := uint64(3_000_000_000) + uint64(templateFuzzByte(data, 0))*1_000_000
	mono := uint64(1 + templateFuzzByte(data, 1)%8)
	state, writer := stateFor(t, protocol, func(config *Config) {
		config.MaxDatagramSize = 65507
		config.InitialCopies = 2 + operation%2
		config.RefreshInterval = time.Minute
		if protocol == wire.ProtocolV9 {
			config.V9RefreshPacketCount = 1000
			if (scenario >= 2 && scenario <= 5) || scenario == 9 {
				config.V9RefreshPacketCount = 1
			}
		}
		if protocol == wire.ProtocolIPFIX {
			config.IPFIXDataMessageRefreshCount = 1000
			if (scenario >= 2 && scenario <= 5) || scenario == 9 {
				config.IPFIXDataMessageRefreshCount = 1
			}
		}
	})

	switch scenario {
	case 0:
		templateFuzzBootstrap(t, state, wall, mono)
	case 1:
		templateFuzzOrdering(t, state, wall, mono)
	case 2:
		templateFuzzRefresh(t, state, wall, mono, writeByte, WriteFull)
	case 3:
		templateFuzzRefresh(t, state, wall, mono, writeByte, WriteShortError)
	case 4:
		templateFuzzRefresh(t, state, wall, mono, writeByte, WriteInvalid)
	case 5:
		templateFuzzEncodeFailure(t, state, writer, wall, mono)
	case 6:
		templateFuzzDataOutcome(t, state, wall, mono, writeByte)
	case 7:
		templateFuzzRestart(t, state, wall, mono)
	case 8:
		templateFuzzBootstrapFailure(t, state, writer, wall, mono, writeByte)
	case 9:
		templateFuzzPartialRefresh(t, state, wall, mono, writeByte)
	}
}

func templateFuzzBootstrap(t *testing.T, state *State, wall, mono uint64) {
	t.Helper()
	protocol := state.Config().Protocol
	if protocol != wire.ProtocolV5 {
		bootstrap(t, state, wall, mono)
	}
	if !state.Ready() {
		t.Fatalf("bootstrap did not produce ready state: epoch=%+v progress=%+v", state.Epoch(), state.Progress())
	}
	wantSequence := uint32(0)
	if protocol == wire.ProtocolV9 {
		wantSequence = uint32(state.Config().InitialCopies) * uint32(state.Catalog().ShapeCount())
	}
	if state.Sequence() != wantSequence {
		t.Fatalf("bootstrap sequence=%d want %d for %s", state.Sequence(), wantSequence, protocol)
	}
}

func templateFuzzOrdering(t *testing.T, state *State, wall, mono uint64) {
	t.Helper()
	if state.Config().Protocol == wire.ProtocolV5 {
		before := state.Progress()
		if _, err := state.BeginTemplate(wall, mono, 0); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("v5 template acceptance err=%v", err)
		}
		if state.Progress() != before {
			t.Fatalf("v5 rejected template changed progress: before=%+v after=%+v", before, state.Progress())
		}
		return
	}
	first, err := state.BeginTemplate(wall, mono, 0)
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, first)
	before := state.Progress()
	if _, err := state.BeginTemplate(wall, mono+1, 0); !errors.Is(err, ErrTemplateProgress) {
		t.Fatalf("out-of-order template err=%v", err)
	}
	if _, err := state.BeginTemplate(wall, mono+1, state.Catalog().ShapeCount()); !errors.Is(err, ErrShapeNotInCatalog) {
		t.Fatalf("out-of-range template err=%v", err)
	}
	if state.Progress() != before {
		t.Fatalf("rejected template changed progress: before=%+v after=%+v", before, state.Progress())
	}
}

func templateFuzzRefresh(t *testing.T, state *State, wall, mono uint64, writeByte uint8, want WriteClass) {
	t.Helper()
	if state.Config().Protocol == wire.ProtocolV5 {
		templateFuzzDataOutcome(t, state, wall, mono, writeByte)
		return
	}
	templateFuzzBootstrap(t, state, wall, mono)
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, wall)
	dataPacket, err := state.BeginData(wall, mono+1, 0, DataRequest{Records: []wire.WireRecord{record}})
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, dataPacket)
	if !state.RefreshDue(mono + 2) {
		t.Fatalf("refresh trigger was not due: %+v", state.Progress())
	}
	packet, err := state.BeginTemplate(wall+1_000_000, mono+2, 0)
	if err != nil {
		t.Fatal(err)
	}
	before := state.Progress()
	sequenceBefore := state.Sequence()
	n, err := encodePacket(t, packet)
	if err != nil {
		t.Fatal(err)
	}
	if want == WriteInvalid {
		result, commitErr := state.Commit(packet, -1, nil)
		if !errors.Is(commitErr, ErrInvalidWrite) || result.Class != WriteInvalid || result.Committed {
			t.Fatalf("invalid refresh result=%+v err=%v", result, commitErr)
		}
	} else if want == WriteShortError {
		result, commitErr := state.Commit(packet, n-1, errors.New("ambiguous"))
		if commitErr != nil || result.Class != WriteShortError || result.Committed {
			t.Fatalf("ambiguous refresh result=%+v err=%v", result, commitErr)
		}
	} else {
		result, commitErr := state.Commit(packet, n, nil)
		if commitErr != nil || result.Class != WriteFull || !result.Committed {
			t.Fatalf("full refresh result=%+v err=%v", result, commitErr)
		}
	}
	after := state.Progress()
	if want == WriteFull {
		if after.NextShape != 1 || !after.RefreshActive || !after.RefreshDue {
			t.Fatalf("full refresh progress=%+v", after)
		}
		return
	}
	if after.NextShape != before.NextShape || !after.RefreshActive || !after.RefreshDue || state.Ready() {
		t.Fatalf("failed published refresh changed state: before=%+v after=%+v ready=%v", before, after, state.Ready())
	}
	if state.Sequence() != sequenceBefore {
		t.Fatalf("failed refresh advanced sequence=%d/%d", state.Sequence(), sequenceBefore)
	}
}

func templateFuzzEncodeFailure(t *testing.T, state *State, writer *recordingWriter, wall, mono uint64) {
	t.Helper()
	if state.Config().Protocol == wire.ProtocolV5 {
		templateFuzzDataOutcome(t, state, wall, mono, 1)
		return
	}
	templateFuzzBootstrap(t, state, wall, mono)
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, wall)
	dataPacket, err := state.BeginData(wall, mono+1, 0, DataRequest{Records: []wire.WireRecord{record}})
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, dataPacket)
	if !state.RefreshDue(mono + 2) {
		t.Fatal("refresh not due before encoding failure")
	}
	packet, err := state.BeginTemplate(wall+1_000_000, mono+2, 0)
	if err != nil {
		t.Fatal(err)
	}
	writer.writeErr = errors.New("encoding failure")
	if _, err := packet.Encode(make([]byte, packet.DatagramLength())); !errors.Is(err, ErrEncoding) {
		t.Fatalf("template encoding error=%v", err)
	}
	writer.writeErr = nil
	progress := state.Progress()
	if progress.NextShape != 0 || progress.RefreshActive || !progress.RefreshDue || state.Ready() {
		t.Fatalf("encoding failure changed refresh state: %+v ready=%v", progress, state.Ready())
	}
}

func templateFuzzDataOutcome(t *testing.T, state *State, wall, mono uint64, writeByte uint8) {
	t.Helper()
	templateFuzzBootstrap(t, state, wall, mono)
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, wall)
	request := DataRequest{Records: []wire.WireRecord{record}}
	if state.Config().Protocol == wire.ProtocolV5 {
		request.V5SamplingRates = []uint32{0}
	}
	packet, err := state.BeginData(wall+1_000_000, mono+1, 0, request)
	if err != nil {
		t.Fatal(err)
	}
	sequence := state.Sequence()
	n, err := encodePacket(t, packet)
	if err != nil {
		t.Fatal(err)
	}
	switch writeByte % 3 {
	case 0:
		result, commitErr := state.Commit(packet, n, nil)
		if commitErr != nil || !result.Committed {
			t.Fatalf("full data result=%+v err=%v", result, commitErr)
		}
		want := sequence + 1
		if state.Sequence() != want {
			t.Fatalf("full data sequence=%d want %d", state.Sequence(), want)
		}
	case 1:
		result, commitErr := state.Commit(packet, n-1, errors.New("ambiguous"))
		if commitErr != nil || result.Committed || state.Sequence() != sequence {
			t.Fatalf("ambiguous data result=%+v err=%v sequence=%d/%d", result, commitErr, state.Sequence(), sequence)
		}
	default:
		result, commitErr := state.Commit(packet, -1, nil)
		if !errors.Is(commitErr, ErrInvalidWrite) || result.Committed || state.Sequence() != sequence {
			t.Fatalf("invalid data result=%+v err=%v sequence=%d/%d", result, commitErr, state.Sequence(), sequence)
		}
	}
}

func templateFuzzBootstrapFailure(t *testing.T, state *State, writer *recordingWriter, wall, mono uint64, writeByte uint8) {
	t.Helper()
	if state.Config().Protocol == wire.ProtocolV5 {
		templateFuzzDataOutcome(t, state, wall, mono, 2)
		return
	}
	first, err := state.BeginTemplate(wall, mono, 0)
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, first)
	second, err := state.BeginTemplate(wall+1_000_000, mono+1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if writeByte%8 == 0 {
		writer.writeErr = errors.New("encoding failure")
		if _, err := second.Encode(make([]byte, second.DatagramLength())); err != ErrEncoding {
			t.Fatalf("partial bootstrap encoding error=%v", err)
		}
		writer.writeErr = nil
	} else {
		n, err := encodePacket(t, second)
		if err != nil {
			t.Fatal(err)
		}
		var writeErr error
		switch writeByte % 8 {
		case 1:
			n--
		case 2:
			n = 0
		case 3:
			n--
			writeErr = errors.New("ambiguous")
		case 4:
			n = 0
			writeErr = errors.New("ambiguous")
		case 5:
			writeErr = errors.New("ambiguous")
		case 6:
			n = -1
		case 7:
			n++
		}
		result, commitErr := state.Commit(second, n, writeErr)
		invalid := writeByte%8 >= 6
		if result.Committed || (invalid && commitErr != ErrInvalidWrite) || (!invalid && commitErr != nil) {
			t.Fatalf("partial bootstrap failed write result=%+v err=%v", result, commitErr)
		}
	}
	if epoch, progress := state.Epoch(), state.Progress(); epoch.Ready || epoch.Sequence != 0 || epoch.HasStartOrigin || progress.NextShape != 0 || progress.CompletedRounds != 0 {
		t.Fatalf("failed bootstrap retained candidate: epoch=%+v progress=%+v", epoch, progress)
	}
	templateFuzzBootstrap(t, state, wall, mono+2)
}

func templateFuzzPartialRefresh(t *testing.T, state *State, wall, mono uint64, writeByte uint8) {
	t.Helper()
	if state.Config().Protocol == wire.ProtocolV5 {
		templateFuzzDataOutcome(t, state, wall, mono, writeByte)
		return
	}
	templateFuzzBootstrap(t, state, wall, mono)
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, wall)
	dataPacket, err := state.BeginData(wall, mono+1, 0, DataRequest{Records: []wire.WireRecord{record}})
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, dataPacket)
	if !state.RefreshDue(mono + 2) {
		t.Fatal("partial refresh was not due")
	}
	first, err := state.BeginTemplate(wall+1_000_000, mono+2, 0)
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, first)
	before := state.Progress()
	sequence := state.Sequence()
	second, err := state.BeginTemplate(wall+2_000_000, mono+3, 1)
	if err != nil {
		t.Fatal(err)
	}
	n, err := encodePacket(t, second)
	if err != nil {
		t.Fatal(err)
	}
	if writeByte&1 == 0 {
		result, commitErr := state.Commit(second, n-1, errors.New("ambiguous"))
		if commitErr != nil || result.Class != WriteShortError || result.Committed {
			t.Fatalf("partial refresh ambiguous result=%+v err=%v", result, commitErr)
		}
	} else {
		result, commitErr := state.Commit(second, -1, nil)
		if !errors.Is(commitErr, ErrInvalidWrite) || result.Class != WriteInvalid || result.Committed {
			t.Fatalf("partial refresh invalid result=%+v err=%v", result, commitErr)
		}
	}
	after := state.Progress()
	if after != before || state.Sequence() != sequence || state.Ready() {
		t.Fatalf("partial refresh failure changed state: before=%+v after=%+v sequence=%d/%d ready=%v", before, after, state.Sequence(), sequence, state.Ready())
	}
	retry, err := state.BeginTemplate(wall+3_000_000, mono+4, 1)
	if err != nil {
		t.Fatal(err)
	}
	commitFull(t, state, retry)
	if !state.Ready() {
		t.Fatalf("refresh retry did not complete: %+v", state.Progress())
	}
}

func templateFuzzRestart(t *testing.T, state *State, wall, mono uint64) {
	t.Helper()
	templateFuzzBootstrap(t, state, wall, mono)
	shape := mustShape(t, state, 0)
	record := testRecord(t, shape, wall)
	request := DataRequest{Records: []wire.WireRecord{record}}
	if state.Config().Protocol == wire.ProtocolV5 {
		request.V5SamplingRates = []uint32{0}
	}
	packet, err := state.BeginData(wall+1_000_000, mono+1, 0, request)
	if err != nil {
		t.Fatal(err)
	}
	n, err := encodePacket(t, packet)
	if err != nil {
		t.Fatal(err)
	}
	oldEpoch := state.Epoch()
	oldIDs := append([]uint16(nil), state.Catalog().IDs()...)
	restarted := state.Restart()
	if restarted.ID != oldEpoch.ID+1 || restarted.Sequence != 0 || restarted.HasStartOrigin || restarted.Ready != (state.Config().Protocol == wire.ProtocolV5) {
		t.Fatalf("restart snapshot=%+v old=%+v", restarted, oldEpoch)
	}
	if _, err := state.Commit(packet, n, nil); !errors.Is(err, ErrTransaction) {
		t.Fatalf("stale transaction commit err=%v", err)
	}
	if !reflect.DeepEqual(oldIDs, state.Catalog().IDs()) || state.Sequence() != 0 {
		t.Fatalf("stale transaction changed restart state: ids=%v/%v sequence=%d", oldIDs, state.Catalog().IDs(), state.Sequence())
	}
}
