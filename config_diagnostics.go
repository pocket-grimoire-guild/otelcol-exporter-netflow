package netflowexporter

import (
	"errors"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

// diagnosticRule selects an entire owned diagnostic, including its path. Neither
// the renderer nor its callers can supply arbitrary rule, path, or prose strings.
type diagnosticRule uint8

const (
	diagnosticQueue diagnosticRule = iota + 1
	diagnosticRetry
	diagnosticSchema
	diagnosticEndpoint
	diagnosticProtocol
	diagnosticIdentity
	diagnosticSamplingMode
	diagnosticUptimeOrigin
	diagnosticMaxDatagram
	diagnosticTemplateIDRange
	diagnosticTemplateAllocation
	diagnosticTemplateCopies
	diagnosticTemplateRefresh
	diagnosticTimeoutRange
	diagnosticTimeoutDrain
	diagnosticDrainRange
	diagnosticDNSTimeoutRange
	diagnosticDNSTimeoutDrain
	diagnosticDNSRefreshRange
	diagnosticDNSStaleRange
	diagnosticDNSStaleRefresh
	diagnosticRecordLimit
	diagnosticV9RefreshPackets
	diagnosticIPFIXRefreshPackets
	diagnosticPathMTU
	diagnosticMappingSelector
	diagnosticMappingPolicyRequired
	diagnosticCompileSelector
	diagnosticCompileSchema
	diagnosticCompileProfile
	diagnosticCompilePolicy
	diagnosticCompileToken
	diagnosticCompileProvenance
	diagnosticCompileUnsupported
	diagnosticCompileInapplicable
	diagnosticCompileCollision
	diagnosticCompileCustom
	diagnosticCompileBounds
	diagnosticCompilePMTU
	diagnosticCompileSelectorChoice
	diagnosticCompileSelectorCanonical
	diagnosticCompileSelectorTarget
	diagnosticCompileTokenNetwork
	diagnosticCompileProvenanceProtocol
	diagnosticCompileProvenanceNetwork
	diagnosticCompileProvenanceUptime
	diagnosticCompileUnsupportedFields
	diagnosticCompileCollisionCustom
	diagnosticCompileCustomSource
	diagnosticCompileCustomEncoding
	diagnosticCompileCustomFixedLength
	diagnosticCompileCustomLength
	diagnosticCompileCustomMaxLength
	diagnosticCompileBoundsPEN
	diagnosticCompileBoundsFields
	diagnosticCompileBoundsShapes
	diagnosticCompileBoundsTemplate
	diagnosticCompileBoundsRecord
	diagnosticCompileBoundsCatalog
	diagnosticCompileBoundsDatagram
	diagnosticCompilePMTUDatagram
	diagnosticRuleCount
)

type diagnosticSpec struct {
	rule        string
	path        string
	explanation string
	protocol    bool
}

func diagnosticError(rule diagnosticRule) error {
	return renderDiagnostic(rule, wire.ProtocolUnknown)
}

func renderDiagnostic(rule diagnosticRule, protocol wire.Protocol) error {
	spec, ok := diagnosticSpecFor(rule)
	if !ok {
		return configError()
	}
	if rule == diagnosticTemplateAllocation && protocol != wire.ProtocolV9 && protocol != wire.ProtocolIPFIX {
		return configError()
	}
	protocolText := ""
	if spec.protocol {
		text, valid := diagnosticProtocolText(protocol)
		if !valid {
			return configError()
		}
		protocolText = " protocol=" + text
	}
	message := "netflow: invalid configuration: rule=" + spec.rule + " path=" + spec.path + protocolText + "; " + spec.explanation
	if len(message) > 256 {
		return configError()
	}
	return errors.New(message)
}

func diagnosticProtocolText(protocol wire.Protocol) (string, bool) {
	switch protocol {
	case wire.ProtocolV5:
		return "v5", true
	case wire.ProtocolV9:
		return "v9", true
	case wire.ProtocolIPFIX:
		return "ipfix", true
	default:
		return "", false
	}
}

// Return literals by value, rather than keeping a mutable table of renderings.
func diagnosticSpecFor(rule diagnosticRule) (diagnosticSpec, bool) {
	switch rule {
	case diagnosticQueue:
		return diagnosticSpec{"queue", "sending_queue.enabled", "sending queue is not supported", false}, true
	case diagnosticRetry:
		return diagnosticSpec{"retry", "retry_on_failure.enabled", "retry is not supported", false}, true
	case diagnosticSchema:
		return diagnosticSpec{"schema", "schema", "unsupported schema", false}, true
	case diagnosticEndpoint:
		return diagnosticSpec{"endpoint", "endpoint", "invalid endpoint", false}, true
	case diagnosticProtocol:
		return diagnosticSpec{"protocol", "protocol", "unsupported protocol", false}, true
	case diagnosticIdentity:
		return diagnosticSpec{"identity", "identity", "identity fields are invalid for the protocol", false}, true
	case diagnosticSamplingMode:
		return diagnosticSpec{"identity_sampling_mode", "identity.sampling_mode", "expected 0..3", false}, true
	case diagnosticUptimeOrigin:
		return diagnosticSpec{"uptime_origin", "uptime_origin", "uptime origin is outside the supported range", false}, true
	case diagnosticMaxDatagram:
		return diagnosticSpec{"max_datagram_size", "max_datagram_size", "expected 128..65507", false}, true
	case diagnosticTemplateIDRange:
		return diagnosticSpec{"template_id_range", "templates.id_base", "expected 256..65535", false}, true
	case diagnosticTemplateAllocation:
		return diagnosticSpec{"template_allocation", "templates.id_base", "selected templates exceed the ID range", true}, true
	case diagnosticTemplateCopies:
		return diagnosticSpec{"template_initial_copies", "templates.initial_copies", "expected 2..8", false}, true
	case diagnosticTemplateRefresh:
		return diagnosticSpec{"template_refresh_interval", "templates.refresh_interval", "expected 30s..24h", false}, true
	case diagnosticTimeoutRange:
		return diagnosticSpec{"write_timeout_range", "timeout", "expected 100ms..30s", false}, true
	case diagnosticTimeoutDrain:
		return diagnosticSpec{"write_timeout_drain", "timeout", "must not exceed shutdown_drain_timeout", false}, true
	case diagnosticDrainRange:
		return diagnosticSpec{"drain_timeout_range", "shutdown_drain_timeout", "expected 1s..30s", false}, true
	case diagnosticDNSTimeoutRange:
		return diagnosticSpec{"dns_timeout_range", "dns.timeout", "expected 100ms..30s", false}, true
	case diagnosticDNSTimeoutDrain:
		return diagnosticSpec{"dns_timeout_drain", "dns.timeout", "must not exceed shutdown_drain_timeout", false}, true
	case diagnosticDNSRefreshRange:
		return diagnosticSpec{"dns_refresh_range", "dns.refresh_interval", "expected 1s..24h", false}, true
	case diagnosticDNSStaleRange:
		return diagnosticSpec{"dns_stale_range", "dns.stale_after", "expected at most 7d", false}, true
	case diagnosticDNSStaleRefresh:
		return diagnosticSpec{"dns_stale_refresh", "dns.stale_after", "must not precede dns.refresh_interval", false}, true
	case diagnosticRecordLimit:
		return diagnosticSpec{"record_limit", "max_records_per_message", "expected 1..1024, and at most 30 for v5", false}, true
	case diagnosticV9RefreshPackets:
		return diagnosticSpec{"v9_refresh_packets", "netflow_v9.template_refresh_packets", "requires netflow_v9 and expected 1..1000", false}, true
	case diagnosticIPFIXRefreshPackets:
		return diagnosticSpec{"ipfix_refresh_packets", "ipfix.template_refresh_data_packets", "requires ipfix and expected 1..1000", false}, true
	case diagnosticPathMTU:
		return diagnosticSpec{"path_mtu_range", "path_mtu", "expected 512..65535", false}, true
	case diagnosticMappingSelector:
		return diagnosticSpec{"mapping", "mapping", "exactly one nonempty selector is required", false}, true
	case diagnosticMappingPolicyRequired:
		return diagnosticSpec{"mapping_policy_required", "mapping.loss_policy", "loss policy is required", false}, true
	case diagnosticCompileSelector:
		return diagnosticSpec{"compile_selector", "mapping.fields", "invalid field selection or target", true}, true
	case diagnosticCompileSchema:
		return diagnosticSpec{"compile_schema", "schema", "unsupported schema", true}, true
	case diagnosticCompileProfile:
		return diagnosticSpec{"compile_profile", "mapping.profile", "missing, unknown, or incompatible profile", true}, true
	case diagnosticCompilePolicy:
		return diagnosticSpec{"compile_policy", "mapping.loss_policy", "loss policy is invalid or rejects selected fields", true}, true
	case diagnosticCompileToken:
		return diagnosticSpec{"compile_token", "mapping.protocol_identifiers", "invalid or conflicting token mapping", true}, true
	case diagnosticCompileProvenance:
		return diagnosticSpec{"compile_provenance", "mapping.input_guarantees.flow_io_bytes", "compiler rejected provenance or required mapping inputs", true}, true
	case diagnosticCompileUnsupported:
		return diagnosticSpec{"compile_unsupported", "mapping.profile", "selected fields cannot be encoded", true}, true
	case diagnosticCompileInapplicable:
		return diagnosticSpec{"compile_inapplicable", "mapping.fields", "selected field is inapplicable", true}, true
	case diagnosticCompileCollision:
		return diagnosticSpec{"compile_collision", "mapping.fields", "conflicting field selection", true}, true
	case diagnosticCompileCustom:
		return diagnosticSpec{"compile_custom", "mapping.custom", "invalid custom field specification", true}, true
	case diagnosticCompileBounds:
		return diagnosticSpec{"compile_bounds", "mapping.custom", "invalid mapping representation or bounds", true}, true
	case diagnosticCompilePMTU:
		return diagnosticSpec{"compile_pmtu", "path_mtu", "datagram and path MTU settings are incompatible", true}, true
	case diagnosticCompileSelectorChoice:
		return diagnosticSpec{"compile_selector", "mapping.selector", "invalid field selection or target", true}, true
	case diagnosticCompileSelectorCanonical:
		return diagnosticSpec{"compile_selector", "mapping.fields.canonical", "invalid field selection or target", true}, true
	case diagnosticCompileSelectorTarget:
		return diagnosticSpec{"compile_selector", "mapping.fields.target", "invalid field selection or target", true}, true
	case diagnosticCompileTokenNetwork:
		return diagnosticSpec{"compile_token", "mapping.network_type_versions", "invalid or conflicting token mapping", true}, true
	case diagnosticCompileProvenanceProtocol:
		return diagnosticSpec{"compile_provenance", "mapping.protocol_identifiers", "compiler rejected provenance or required mapping inputs", true}, true
	case diagnosticCompileProvenanceNetwork:
		return diagnosticSpec{"compile_provenance", "mapping.network_type_versions", "compiler rejected provenance or required mapping inputs", true}, true
	case diagnosticCompileProvenanceUptime:
		return diagnosticSpec{"compile_provenance", "uptime_origin", "compiler rejected provenance or required mapping inputs", true}, true
	case diagnosticCompileUnsupportedFields:
		return diagnosticSpec{"compile_unsupported", "mapping.fields", "selected fields cannot be encoded", true}, true
	case diagnosticCompileCollisionCustom:
		return diagnosticSpec{"compile_collision", "mapping.custom.source", "conflicting field selection", true}, true
	case diagnosticCompileCustomSource:
		return diagnosticSpec{"compile_custom", "mapping.custom.source", "invalid custom field specification", true}, true
	case diagnosticCompileCustomEncoding:
		return diagnosticSpec{"compile_custom", "mapping.custom.encoding", "invalid custom field specification", true}, true
	case diagnosticCompileCustomFixedLength:
		return diagnosticSpec{"compile_custom", "mapping.custom.fixed_length", "invalid custom field specification", true}, true
	case diagnosticCompileCustomLength:
		return diagnosticSpec{"compile_custom", "mapping.custom.length", "invalid custom field specification", true}, true
	case diagnosticCompileCustomMaxLength:
		return diagnosticSpec{"compile_custom", "mapping.custom.max_length", "invalid custom field specification", true}, true
	case diagnosticCompileBoundsPEN:
		return diagnosticSpec{"compile_bounds", "mapping.custom.pen", "invalid mapping representation or bounds", true}, true
	case diagnosticCompileBoundsFields:
		return diagnosticSpec{"compile_bounds", "mapping.fields", "invalid mapping representation or bounds", true}, true
	case diagnosticCompileBoundsShapes:
		return diagnosticSpec{"compile_bounds", "mapping.shapes", "invalid mapping representation or bounds", true}, true
	case diagnosticCompileBoundsTemplate:
		return diagnosticSpec{"compile_bounds", "mapping.template", "invalid mapping representation or bounds", true}, true
	case diagnosticCompileBoundsRecord:
		return diagnosticSpec{"compile_bounds", "mapping.record", "invalid mapping representation or bounds", true}, true
	case diagnosticCompileBoundsCatalog:
		return diagnosticSpec{"compile_bounds", "mapping.catalog", "invalid mapping representation or bounds", true}, true
	case diagnosticCompileBoundsDatagram:
		return diagnosticSpec{"compile_bounds", "max_datagram_size", "invalid mapping representation or bounds", true}, true
	case diagnosticCompilePMTUDatagram:
		return diagnosticSpec{"compile_pmtu", "max_datagram_size", "datagram and path MTU settings are incompatible", true}, true
	default:
		return diagnosticSpec{}, false
	}
}

// projectCompileError treats even direct compiler diagnostics as untrusted data.
// It snapshots their fields without invoking methods or traversing error chains;
// numeric fields are deliberately omitted. Recognized fabricated tuples can only
// select the same fixed text, so this does not authenticate a diagnostic's origin.
func projectCompileError(err error, protocol wire.Protocol) error {
	configErr, ok := err.(*mapping.ConfigError)
	if !ok || configErr == nil {
		return configError()
	}
	snapshot := *configErr
	if snapshot.Protocol != protocol {
		return configError()
	}
	if _, ok := diagnosticProtocolText(protocol); !ok {
		return configError()
	}
	return renderDiagnostic(compilerDiagnosticRule(snapshot.Code, snapshot.Path), protocol)
}

func compilerDiagnosticRule(code mapping.ErrorCode, path string) diagnosticRule {
	switch code {
	case mapping.ErrCodeSelector:
		switch path {
		case "mapping.fields":
			return diagnosticCompileSelector
		case "mapping.selector":
			return diagnosticCompileSelectorChoice
		case "mapping.fields.canonical":
			return diagnosticCompileSelectorCanonical
		case "mapping.fields.target":
			return diagnosticCompileSelectorTarget
		}
	case mapping.ErrCodeSchema:
		switch path {
		case "mapping.schema":
			return diagnosticCompileSchema
		}
	case mapping.ErrCodeProfile:
		switch path {
		case "mapping.profile":
			return diagnosticCompileProfile
		}
	case mapping.ErrCodePolicy:
		switch path {
		case "mapping.loss_policy":
			return diagnosticCompilePolicy
		}
	case mapping.ErrCodeToken:
		switch path {
		case "mapping.protocol_identifiers":
			return diagnosticCompileToken
		case "mapping.network_type_versions":
			return diagnosticCompileTokenNetwork
		}
	case mapping.ErrCodeProvenance:
		switch path {
		case "mapping.input_guarantees.flow_io_bytes":
			return diagnosticCompileProvenance
		case "mapping.protocol_identifiers":
			return diagnosticCompileProvenanceProtocol
		case "mapping.network_type_versions":
			return diagnosticCompileProvenanceNetwork
		case "mapping.uptime_origin":
			return diagnosticCompileProvenanceUptime
		}
	case mapping.ErrCodeUnsupported:
		switch path {
		case "mapping.profile":
			return diagnosticCompileUnsupported
		case "mapping.fields":
			return diagnosticCompileUnsupportedFields
		}
	case mapping.ErrCodeInapplicable:
		switch path {
		case "mapping.fields":
			return diagnosticCompileInapplicable
		}
	case mapping.ErrCodeCollision:
		switch path {
		case "mapping.fields":
			return diagnosticCompileCollision
		case "mapping.custom.source":
			return diagnosticCompileCollisionCustom
		}
	case mapping.ErrCodeCustom:
		switch path {
		case "mapping.custom":
			return diagnosticCompileCustom
		case "mapping.custom.source":
			return diagnosticCompileCustomSource
		case "mapping.custom.encoding":
			return diagnosticCompileCustomEncoding
		case "mapping.custom.fixed_length":
			return diagnosticCompileCustomFixedLength
		case "mapping.custom.length":
			return diagnosticCompileCustomLength
		case "mapping.custom.max_length":
			return diagnosticCompileCustomMaxLength
		}
	case mapping.ErrCodeBounds:
		switch path {
		case "mapping.custom":
			return diagnosticCompileBounds
		case "mapping.custom.pen":
			return diagnosticCompileBoundsPEN
		case "mapping.fields":
			return diagnosticCompileBoundsFields
		case "mapping.shapes":
			return diagnosticCompileBoundsShapes
		case "mapping.template":
			return diagnosticCompileBoundsTemplate
		case "mapping.record":
			return diagnosticCompileBoundsRecord
		case "mapping.catalog":
			return diagnosticCompileBoundsCatalog
		case "max_datagram_size":
			return diagnosticCompileBoundsDatagram
		case "templates.id_base":
			return diagnosticTemplateAllocation
		}
	case mapping.ErrCodePMTU:
		switch path {
		case "path_mtu":
			return diagnosticCompilePMTU
		case "max_datagram_size":
			return diagnosticCompilePMTUDatagram
		}
	}
	return 0 // Unknown code/path combinations always use the generic fallback.
}
