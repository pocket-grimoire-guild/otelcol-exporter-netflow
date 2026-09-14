//go:build integration

package testpdata

import "go.opentelemetry.io/collector/pdata/plog"

const (
	// VariableOctetRecordCount keeps the packetization check large enough to
	// exercise repeated records without becoming a memory benchmark.
	VariableOctetRecordCount = 33
	// VariableOctetFieldCount is the number of enterprise variable-length
	// fields in VariableOctetLogs.
	VariableOctetFieldCount  = 32
	variableOctetFieldPrefix = "plan005.variable_octet_"
)

var variableOctetFieldNames = [...]string{
	variableOctetFieldPrefix + "00", variableOctetFieldPrefix + "01",
	variableOctetFieldPrefix + "02", variableOctetFieldPrefix + "03",
	variableOctetFieldPrefix + "04", variableOctetFieldPrefix + "05",
	variableOctetFieldPrefix + "06", variableOctetFieldPrefix + "07",
	variableOctetFieldPrefix + "08", variableOctetFieldPrefix + "09",
	variableOctetFieldPrefix + "10", variableOctetFieldPrefix + "11",
	variableOctetFieldPrefix + "12", variableOctetFieldPrefix + "13",
	variableOctetFieldPrefix + "14", variableOctetFieldPrefix + "15",
	variableOctetFieldPrefix + "16", variableOctetFieldPrefix + "17",
	variableOctetFieldPrefix + "18", variableOctetFieldPrefix + "19",
	variableOctetFieldPrefix + "20", variableOctetFieldPrefix + "21",
	variableOctetFieldPrefix + "22", variableOctetFieldPrefix + "23",
	variableOctetFieldPrefix + "24", variableOctetFieldPrefix + "25",
	variableOctetFieldPrefix + "26", variableOctetFieldPrefix + "27",
	variableOctetFieldPrefix + "28", variableOctetFieldPrefix + "29",
	variableOctetFieldPrefix + "30", variableOctetFieldPrefix + "31",
}

// CanonicalBatch returns count independent copies of the canonical receiver
// record. Callers may reuse a read-only batch for repeated ConsumeLogs calls.
func CanonicalBatch(count int) plog.Logs {
	if count < 1 {
		panic("testpdata: canonical batch must be positive")
	}
	logs, target, base := newLoadRecords()
	for i := 0; i < count; i++ {
		base.CopyTo(target.AppendEmpty())
	}
	return logs
}

// IgnoredMetadataLogs returns a small valid request with metadata that is not
// selected by the IPFIX mapping. The metadata is deliberately placed at the
// resource, scope, and record levels so the exporter must ignore it while
// accounting for every supported record.
func IgnoredMetadataLogs(count int) plog.Logs {
	if count < 1 {
		panic("testpdata: ignored-metadata count must be positive")
	}
	logs := CanonicalBatch(count)
	resource := logs.ResourceLogs().At(0)
	resource.Resource().Attributes().PutStr("plan005.ignored_resource", "resource metadata")
	scope := resource.ScopeLogs().At(0)
	scope.Scope().Attributes().PutStr("plan005.ignored_scope", "scope metadata")
	for i := 0; i < scope.LogRecords().Len(); i++ {
		scope.LogRecords().At(i).Attributes().PutStr("plan005.ignored_record", "record metadata")
	}
	return logs
}

// VariableOctetFieldNames returns the enterprise field names used by
// VariableOctetLogs. A fresh slice lets callers assemble a mapping freely.
func VariableOctetFieldNames() []string {
	return append([]string(nil), variableOctetFieldNames[:]...)
}

// VariableOctetLogs returns deterministic records with all 32 custom fields
// present. Each field is variable length and longer than the one-octet
// length form, while the complete record remains below the UDP payload limit.
func VariableOctetLogs() plog.Logs {
	logs, target, base := newLoadRecords()
	for recordIndex := 0; recordIndex < VariableOctetRecordCount; recordIndex++ {
		record := target.AppendEmpty()
		base.CopyTo(record)
		for fieldIndex, name := range variableOctetFieldNames {
			length := 1300 + (recordIndex*7+fieldIndex*13)%37
			record.Attributes().PutEmptyBytes(name).FromRaw(loadBytes(recordIndex*VariableOctetFieldCount+fieldIndex, length))
		}
	}
	return logs
}

func newLoadRecords() (plog.Logs, plog.LogRecordSlice, plog.LogRecord) {
	canonical := CanonicalLogs()
	sourceResource := canonical.ResourceLogs().At(0)
	sourceScope := sourceResource.ScopeLogs().At(0)
	logs := plog.NewLogs()
	targetResource := logs.ResourceLogs().AppendEmpty()
	sourceResource.Resource().CopyTo(targetResource.Resource())
	targetResource.SetSchemaUrl(sourceResource.SchemaUrl())
	targetScope := targetResource.ScopeLogs().AppendEmpty()
	sourceScope.Scope().CopyTo(targetScope.Scope())
	targetScope.SetSchemaUrl(sourceScope.SchemaUrl())
	return logs, targetScope.LogRecords(), sourceScope.LogRecords().At(0)
}

func loadBytes(seed, length int) []byte {
	value := make([]byte, length)
	for i := range value {
		value[i] = byte((seed + i) % 251)
	}
	return value
}
