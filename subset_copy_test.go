package netflowexporter

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumererror"
	"go.opentelemetry.io/collector/featuregate"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestReturnedSubsetPreservesJSONEnvelopeEntries(t *testing.T) {
	// JSON is the pinned public construction path for the Resource fields that
	// have no accessor in pdata, and it permits duplicate map entries. Keep
	// those entries in the source so the regression observes CopyTo's complete
	// envelope semantics while the exporter detaches byte leaves.
	encoded, err := (&plog.JSONMarshaler{}).MarshalLogs(testpdata.CanonicalLogs())
	if err != nil {
		t.Fatal(err)
	}
	const resource = `"resource":{}`
	const replacement = `"resource":{"attributes":[{"key":"duplicate","value":{"stringValue":"first"}},{"key":"duplicate","value":{"stringValue":"second"}}],"entityRefs":[{"schemaUrl":"https://example.invalid/schema","type":"host","idKeys":["host.id"],"descriptionKeys":["host.name"]}]}`
	input := strings.Replace(string(encoded), resource, replacement, 1)
	if input == string(encoded) {
		t.Fatal("canonical JSON resource envelope changed")
	}
	logs, err := (&plog.JSONUnmarshaler{}).UnmarshalLogs([]byte(input))
	if err != nil {
		t.Fatal(err)
	}

	c := validConfig("netflow_v5")
	c.MaxRecordsPerMessage = ptr(uint16(1))
	e, _ := fakeExporter(t, c, testtransport.WriteStep{N: packetLength("netflow_v5"), Err: errors.New("ambiguous")})
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	logs.MarkReadOnly()
	err = e.ConsumeLogs(context.Background(), logs)
	logsErr, ok := errors.AsType[consumererror.Logs](err)
	if !ok || consumererror.IsPermanent(err) {
		t.Fatalf("ConsumeLogs error = %v, want transient subset", err)
	}
	output, err := (&plog.JSONMarshaler{}).MarshalLogs(logsErr.Data())
	if err != nil {
		t.Fatal(err)
	}
	serializedSource, err := (&plog.JSONMarshaler{}).MarshalLogs(logs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output, serializedSource) {
		t.Fatalf("subset JSON changed source envelope or record:\n got %s\nwant %s", output, serializedSource)
	}
	if got := strings.Count(string(output), `"key":"duplicate"`); got != 2 {
		t.Fatalf("duplicate resource entries = %d, want 2", got)
	}
	first := strings.Index(string(output), `"key":"duplicate","value":{"stringValue":"first"}`)
	second := strings.Index(string(output), `"key":"duplicate","value":{"stringValue":"second"}`)
	if first < 0 || second < 0 || first >= second {
		t.Fatalf("duplicate resource order = %d/%d, want first before second", first, second)
	}
	for _, want := range []string{`"entityRefs":[`, `"schemaUrl":"https://example.invalid/schema"`, `"type":"host"`, `"idKeys":["host.id"]`, `"descriptionKeys":["host.name"]`} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("subset JSON missing %s: %s", want, output)
		}
	}
}

func TestReturnedSubsetDetachesByteValues(t *testing.T) {
	c := validConfig("netflow_v5")
	c.MaxRecordsPerMessage = ptr(uint16(1))
	e, _ := fakeExporter(t, c, testtransport.WriteStep{N: packetLength("netflow_v5"), Err: errors.New("ambiguous")})
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}

	logs := byteSubsetLogs()
	sourceLeaves := byteLeaves(logs)
	if len(sourceLeaves) != 18 {
		t.Fatalf("source byte leaves = %d, want 18", len(sourceLeaves))
	}
	original := snapshotByteLeaves(sourceLeaves)
	err := e.ConsumeLogs(context.Background(), logs)
	logsErr, ok := errors.AsType[consumererror.Logs](err)
	if !ok || consumererror.IsPermanent(err) {
		t.Fatalf("ConsumeLogs error = %v, want transient subset", err)
	}
	subset := logsErr.Data()
	subsetLeaves := byteLeaves(subset)
	if len(subsetLeaves) != len(sourceLeaves) {
		t.Fatalf("subset byte leaves = %d, want %d", len(subsetLeaves), len(sourceLeaves))
	}
	for i := range original {
		if !bytes.Equal(sourceLeaves[i].AsRaw(), original[i]) || !bytes.Equal(subsetLeaves[i].AsRaw(), original[i]) {
			t.Fatalf("byte leaf %d was not initially preserved", i)
		}
	}

	for i, value := range sourceLeaves {
		value.SetAt(0, original[i][0]+1)
	}
	for i, value := range subsetLeaves {
		if got := value.At(0); got != original[i][0] {
			t.Fatalf("subset leaf %d changed with source mutation: got %d, want %d", i, got, original[i][0])
		}
	}
	for i, value := range subsetLeaves {
		value.SetAt(0, original[i][0]+2)
	}
	for i, value := range sourceLeaves {
		if got := value.At(0); got != original[i][0]+1 {
			t.Fatalf("source leaf %d changed with subset mutation: got %d, want %d", i, got, original[i][0]+1)
		}
	}
}

func TestDetachLogsBytesCopiesBodyLeaves(t *testing.T) {
	source := plog.NewLogs()
	record := source.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	body := record.Body().SetEmptySlice()
	body.AppendEmpty().SetEmptyBytes().FromRaw([]byte{1, 2})
	nested := body.AppendEmpty().SetEmptyMap()
	nested.PutEmptyBytes("direct").FromRaw([]byte{3, 4})
	nested.PutEmptySlice("slice").AppendEmpty().SetEmptyBytes().FromRaw([]byte{5, 6})

	detached := plog.NewLogs()
	source.CopyTo(detached)
	sourceLeaves := byteLeaves(source)
	if len(sourceLeaves) != 3 || len(byteLeaves(detached)) != len(sourceLeaves) {
		t.Fatalf("body byte leaves = %d/%d, want 3/3", len(sourceLeaves), len(byteLeaves(detached)))
	}
	original := snapshotByteLeaves(sourceLeaves)
	detachLogsBytes(detached)
	detachedLeaves := byteLeaves(detached)
	for i, value := range sourceLeaves {
		value.SetAt(0, original[i][0]+10)
	}
	for i, value := range detachedLeaves {
		if got := value.At(0); got != original[i][0] {
			t.Fatalf("detached body leaf %d changed with source mutation: got %d, want %d", i, got, original[i][0])
		}
	}
	for i, value := range detachedLeaves {
		value.SetAt(0, original[i][0]+20)
	}
	for i, value := range sourceLeaves {
		if got := value.At(0); got != original[i][0]+10 {
			t.Fatalf("source body leaf %d changed with detached mutation: got %d, want %d", i, got, original[i][0]+10)
		}
	}
}

func TestDetachLogsBytesBeyondRetiredDepthBudget(t *testing.T) {
	source := plog.NewLogs()
	record := source.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	deep := record.Attributes().PutEmptyMap("deep")
	for depth := 0; depth < 1024; depth++ {
		deep = deep.PutEmptyMap("next")
	}
	sourceLeaf := deep.PutEmptyBytes("payload")
	sourceLeaf.FromRaw([]byte{7, 8, 9})

	detached := plog.NewLogs()
	source.CopyTo(detached)
	deepValue, ok := detached.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Get("deep")
	if !ok {
		t.Fatal("detached deep root missing")
	}
	for depth := 0; depth < 1024; depth++ {
		deepValue, ok = deepValue.Map().Get("next")
		if !ok {
			t.Fatalf("detached depth %d missing", depth)
		}
	}
	detachedLeaf, ok := deepValue.Map().Get("payload")
	if !ok {
		t.Fatal("detached byte leaf missing")
	}
	detachLogsBytes(detached)
	sourceLeaf.SetAt(0, 99)
	if got := detachedLeaf.Bytes().At(0); got != 7 {
		t.Fatalf("deep detached byte leaf changed with source mutation: got %d, want 7", got)
	}
}

func TestDetachLogsBytesWithProtoPooling(t *testing.T) {
	var gate *featuregate.Gate
	featuregate.GlobalRegistry().VisitAll(func(candidate *featuregate.Gate) {
		if candidate.ID() == "pdata.useProtoPooling" {
			gate = candidate
		}
	})
	if gate == nil {
		t.Fatal("pdata pooling feature gate is not registered")
	}
	wasEnabled := gate.IsEnabled()
	if err := featuregate.GlobalRegistry().Set(gate.ID(), true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = featuregate.GlobalRegistry().Set(gate.ID(), wasEnabled) })

	source := pooledByteSubsetLogs()
	detached := plog.NewLogs()
	source.CopyTo(detached)
	sourceLeaves := byteLeaves(source)
	original := snapshotByteLeaves(sourceLeaves)
	detachLogsBytes(detached)
	detachedLeaves := byteLeaves(detached)
	if len(sourceLeaves) != len(detachedLeaves) {
		t.Fatalf("pooled byte leaves = %d/%d, want equal", len(sourceLeaves), len(detachedLeaves))
	}
	for i, value := range detachedLeaves {
		if !bytes.Equal(value.AsRaw(), original[i]) {
			t.Fatalf("pooled detached leaf %d did not preserve its bytes", i)
		}
	}
	for i, value := range sourceLeaves {
		if value.Len() > 0 {
			value.SetAt(0, original[i][0]+1)
		}
	}
	for i, value := range detachedLeaves {
		if value.Len() > 0 && value.At(0) != original[i][0] {
			t.Fatalf("pooled detached leaf %d changed with source mutation: got %d, want %d", i, value.At(0), original[i][0])
		}
	}
	for i, value := range detachedLeaves {
		if value.Len() > 0 {
			value.SetAt(0, original[i][0]+2)
		}
	}
	for i, value := range sourceLeaves {
		if value.Len() > 0 && value.At(0) != original[i][0]+1 {
			t.Fatalf("pooled source leaf %d changed with detached mutation: got %d, want %d", i, value.At(0), original[i][0]+1)
		}
	}
}

func pooledByteSubsetLogs() plog.Logs {
	logs := plog.NewLogs()
	resource := logs.ResourceLogs().AppendEmpty()
	resourceAttrs := resource.Resource().Attributes()
	resourceAttrs.PutEmptyBytes("resource-empty-0")
	resourceAttrs.PutEmptyBytes("resource-full-1").FromRaw([]byte{1, 2})
	resourceAttrs.PutEmptyBytes("resource-empty-2")
	scope := resource.ScopeLogs().AppendEmpty()
	scopeAttrs := scope.Scope().Attributes()
	scopeAttrs.PutEmptyBytes("scope-full-0").FromRaw([]byte{3, 4})
	scopeAttrs.PutEmptyBytes("scope-empty-1")
	record := scope.LogRecords().AppendEmpty()
	recordAttrs := record.Attributes()
	recordAttrs.PutEmptyBytes("record-empty-0")
	recordAttrs.PutEmptyBytes("record-full-1").FromRaw([]byte{5, 6})
	recordAttrs.PutEmptyBytes("record-empty-2")
	body := record.Body().SetEmptySlice()
	body.AppendEmpty().SetEmptyBytes()
	body.AppendEmpty().SetEmptyBytes().FromRaw([]byte{7, 8})
	body.AppendEmpty().SetEmptyBytes()
	return logs
}

func byteSubsetLogs() plog.Logs {
	logs := plog.NewLogs()
	canonical := testpdata.CanonicalLogs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	for i := 0; i < 2; i++ {
		resource := logs.ResourceLogs().AppendEmpty()
		addByteAttributes(resource.Resource().Attributes(), byte(i))
		scope := resource.ScopeLogs().AppendEmpty()
		addByteAttributes(scope.Scope().Attributes(), byte(i+10))
		record := scope.LogRecords().AppendEmpty()
		canonical.CopyTo(record)
		addByteAttributes(record.Attributes(), byte(i+20))
	}
	return logs
}

func addByteAttributes(values pcommon.Map, seed byte) {
	values.PutEmptyBytes("direct").FromRaw([]byte{seed, seed + 1})
	nested := values.PutEmptyMap("nested")
	nested.PutEmptyBytes("direct").FromRaw([]byte{seed + 2, seed + 3})
	nested.PutEmptySlice("slice").AppendEmpty().SetEmptyBytes().FromRaw([]byte{seed + 4, seed + 5})
}

func byteLeaves(logs plog.Logs) []pcommon.ByteSlice {
	var leaves []pcommon.ByteSlice
	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		resource := logs.ResourceLogs().At(i)
		collectByteLeaves(resource.Resource().Attributes(), &leaves)
		for j := 0; j < resource.ScopeLogs().Len(); j++ {
			scope := resource.ScopeLogs().At(j)
			collectByteLeaves(scope.Scope().Attributes(), &leaves)
			for k := 0; k < scope.LogRecords().Len(); k++ {
				record := scope.LogRecords().At(k)
				collectByteLeaves(record.Attributes(), &leaves)
				collectByteValue(record.Body(), &leaves)
			}
		}
	}
	return leaves
}

func collectByteLeaves(values pcommon.Map, leaves *[]pcommon.ByteSlice) {
	values.Range(func(_ string, value pcommon.Value) bool {
		collectByteValue(value, leaves)
		return true
	})
}

func collectByteValue(value pcommon.Value, leaves *[]pcommon.ByteSlice) {
	switch value.Type() {
	case pcommon.ValueTypeBytes:
		*leaves = append(*leaves, value.Bytes())
	case pcommon.ValueTypeMap:
		collectByteLeaves(value.Map(), leaves)
	case pcommon.ValueTypeSlice:
		slice := value.Slice()
		for i := 0; i < slice.Len(); i++ {
			collectByteValue(slice.At(i), leaves)
		}
	}
}

func snapshotByteLeaves(leaves []pcommon.ByteSlice) [][]byte {
	snapshots := make([][]byte, len(leaves))
	for i, value := range leaves {
		snapshots[i] = value.AsRaw()
	}
	return snapshots
}
