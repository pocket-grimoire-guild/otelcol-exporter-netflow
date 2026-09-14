package mapping

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

const (
	defaultMaxDatagramSize      uint64 = 464
	defaultMaxAttributeKeyBytes uint64 = 256
	hardMaxAttributeKeyBytes    uint64 = 1024
	// A mapped value is bounded by its protocol descriptor width and the
	// actual packet/path budget. The former 4096-byte default was an arbitrary
	// admission policy and is intentionally no longer used.
	defaultMaxMappedValueBytes uint64 = hardMaxMappedValueBytes
	hardMaxMappedValueBytes    uint64 = 65535
)

type selectedField struct {
	field  wire.CanonicalField
	target string
	class  conversionClass
}

// Compile validates one static profile or one explicit mapping and constructs
// every shape before returning. No record values are read during compilation.
func Compile(config Config) (CompiledMapping, error) {
	schema := config.Schema
	if schema == "" {
		schema = SchemaContribNetflowReceiverV0160
	}
	if schema != SchemaContribNetflowReceiverV0160 {
		return CompiledMapping{}, newConfigError(ErrCodeSchema, config.Protocol, "mapping.schema", 0, 1, 1)
	}
	protocol := config.Protocol
	if config.Profile != "" {
		profileProtocol, ok := validProfile(config.Profile)
		if !ok {
			return CompiledMapping{}, newConfigError(ErrCodeProfile, protocol, "mapping.profile", 0, 1, 5)
		}
		if protocol == wire.ProtocolUnknown {
			protocol = profileProtocol
		}
		if protocol != profileProtocol {
			return CompiledMapping{}, newConfigError(ErrCodeProfile, protocol, "mapping.profile", 0, uint64(protocol), uint64(profileProtocol))
		}
	}
	if protocol != wire.ProtocolV5 && protocol != wire.ProtocolV9 && protocol != wire.ProtocolIPFIX {
		return CompiledMapping{}, newConfigError(ErrCodeInvalidConfig, protocol, "mapping.protocol", 0, uint64(protocol), 3)
	}
	if config.LossPolicy != LossPolicyEncodeAndCount && config.LossPolicy != LossPolicyReject {
		return CompiledMapping{}, newConfigError(ErrCodePolicy, protocol, "mapping.loss_policy", 0, 0, 2)
	}
	if config.Profile != "" && (config.Fields != nil || config.FieldsSet) {
		return CompiledMapping{}, newConfigError(ErrCodeSelector, protocol, "mapping.fields", 0, 2, 1)
	}
	if config.Profile == "" && config.Fields == nil && !config.FieldsSet {
		return CompiledMapping{}, newConfigError(ErrCodeSelector, protocol, "mapping.selector", 0, 0, 1)
	}
	if config.Profile == "" && (config.Fields == nil || len(config.Fields) == 0) {
		return CompiledMapping{}, newConfigError(ErrCodeSelector, protocol, "mapping.fields", 0, uint64(len(config.Fields)), 1)
	}
	if protocol == wire.ProtocolV5 && config.Profile == "" {
		return CompiledMapping{}, newConfigError(ErrCodeProfile, protocol, "mapping.profile", 0, 0, 1)
	}
	if protocol == wire.ProtocolV5 && config.Profile != ProfileV5 {
		return CompiledMapping{}, newConfigError(ErrCodeProfile, protocol, "mapping.profile", 0, 1, 1)
	}
	if protocol != wire.ProtocolV5 && config.InputGuarantees.FlowIOBytes != "" {
		return CompiledMapping{}, newConfigError(ErrCodeProvenance, protocol, "mapping.input_guarantees.flow_io_bytes", 0, 1, 0)
	}
	if protocol == wire.ProtocolV5 && config.Custom != nil {
		return CompiledMapping{}, newConfigError(ErrCodeCustom, protocol, "mapping.custom", 0, uint64(len(config.Custom)), 0)
	}
	if protocol == wire.ProtocolV5 && config.IDBase != 0 {
		return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "templates.id_base", 0, 1, 0)
	}

	limits := config.Limits
	limits = mappingLimitsWithDefaults(limits)
	if err := validateMappingLimits(limits, protocol); err != nil {
		return CompiledMapping{}, err
	}
	maxDatagram := config.MaxDatagramSize
	if maxDatagram == 0 {
		maxDatagram = defaultMaxDatagramSize
	}
	if maxDatagram < 128 || maxDatagram > 65507 {
		return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "max_datagram_size", 0, maxDatagram, 65507)
	}
	if maxDatagram > limits.MaxMessageBytes {
		return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "max_datagram_size", 0, maxDatagram, limits.MaxMessageBytes)
	}
	if err := validatePMTU(config, maxDatagram, protocol); err != nil {
		return CompiledMapping{}, err
	}
	keyLimit := config.MaxAttributeKeyBytes
	if keyLimit == 0 {
		keyLimit = defaultMaxAttributeKeyBytes
	}
	if keyLimit > hardMaxAttributeKeyBytes {
		return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "mapping.max_attribute_key_bytes", 0, keyLimit, hardMaxAttributeKeyBytes)
	}
	maxMapped := config.MaxMappedValueBytes
	if maxMapped == 0 {
		maxMapped = defaultMaxMappedValueBytes
	}
	if maxMapped > hardMaxMappedValueBytes {
		return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "mapping.max_mapped_value_bytes", 0, maxMapped, hardMaxMappedValueBytes)
	}
	if config.HasUptimeOrigin && config.UptimeOriginUnixNanos > math.MaxInt64 {
		return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "mapping.uptime_origin", 0, config.UptimeOriginUnixNanos, math.MaxInt64)
	}

	var selected []selectedField
	var protocolMap, networkMap map[string]uint8
	var err error
	if config.Profile == "" {
		selected, err = compileSelections(config.Fields, protocol, config.LossPolicy, config.InputGuarantees, config.HasUptimeOrigin)
		if err != nil {
			return CompiledMapping{}, err
		}
	}
	protocolMap, networkMap, err = compileTokenMaps(config, protocol, config.Profile != "", config.Fields, config.Custom)
	if err != nil {
		return CompiledMapping{}, err
	}
	custom, err := compileCustom(config.Custom, protocol, keyLimit, maxMapped, limits)
	if err != nil {
		return CompiledMapping{}, err
	}

	var shapes []wire.ShapeSpec
	var bindings [][]shapeBinding
	familyAgnostic := false
	profileName := config.Profile
	if profileName != "" {
		if protocol == wire.ProtocolV5 && config.InputGuarantees.FlowIOBytes != "layer3_total_octets" {
			return CompiledMapping{}, newConfigError(ErrCodeProvenance, protocol, "mapping.input_guarantees.flow_io_bytes", 0, 0, 1)
		}
		if (protocol == wire.ProtocolV5 || profileName == ProfileV9Timed) && !config.HasUptimeOrigin {
			return CompiledMapping{}, newConfigError(ErrCodeProvenance, protocol, "mapping.uptime_origin", 0, 0, 1)
		}
		base := builtinCatalog(protocol, profileName)
		if base.ShapeCount() == 0 {
			return CompiledMapping{}, newConfigError(ErrCodeProfile, protocol, "mapping.profile", 0, 1, 5)
		}
		for index := 0; index < base.ShapeCount(); index++ {
			shape, _ := base.ShapeAt(index)
			fields := shape.Fields()
			bind := make([]shapeBinding, 0, len(fields)+len(custom))
			for _, descriptor := range fields {
				class := classFor(protocol, descriptor.Field, builtinTarget(protocol, descriptor))
				if descriptor.Constant {
					class = classExact
				}
				if class == classUnsupported || class == classInapplicable {
					return CompiledMapping{}, newConfigError(ErrCodeUnsupported, protocol, "mapping.profile", uint64(index+1), uint64(class), 0)
				}
				if config.LossPolicy == LossPolicyReject && class.lossy() {
					return CompiledMapping{}, newConfigError(ErrCodePolicy, protocol, "mapping.loss_policy", uint64(index+1), uint64(class), uint64(classExact))
				}
				bind = append(bind, shapeBinding{descriptor: descriptor, field: descriptor.Field, class: class})
			}
			for customIndex, entry := range custom {
				descriptor, err := customDescriptor(entry, protocol, shape.Family())
				if err != nil {
					return CompiledMapping{}, newConfigError(ErrCodeCustom, protocol, "mapping.custom", uint64(customIndex+1), uint64(customIndex+1), uint64(len(custom)))
				}
				bind = append(bind, shapeBinding{descriptor: descriptor, custom: true, class: classExact})
			}
			spec := wire.ShapeSpec{Protocol: protocol, Family: shape.Family(), ID: uint32(shape.ID()), Fields: bindDescriptors(bind), RecordLength: shape.RecordLength(), TemplateBytes: shape.TemplateBytes()}
			if len(custom) != 0 {
				var ok bool
				spec.RecordLength, ok = checkedSumLengths(spec.Fields)
				if !ok {
					return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "mapping.custom", uint64(index+1), math.MaxUint64, 65535)
				}
				spec.TemplateBytes, ok = templateBytes(protocol, spec.Fields)
				if !ok {
					return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "mapping.custom", uint64(index+1), math.MaxUint64, 4096)
				}
			}
			shapes = append(shapes, spec)
			bindings = append(bindings, bind)
		}
	} else {
		if uint64(len(selected))+uint64(len(custom)) > limits.MaxFieldsPerShape || uint64(len(selected))+uint64(len(custom)) > wire.DefaultMaxFieldsPerShape {
			return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "mapping.fields", 0, uint64(len(selected))+uint64(len(custom)), limits.MaxFieldsPerShape)
		}
		familyAgnostic = explicitMappingFamilyAgnostic(selected, custom, protocol)
		shapes, bindings, err = compileExplicitShapes(selected, custom, protocol, effectiveIDBase(config.IDBase, protocol))
		if err != nil {
			return CompiledMapping{}, err
		}
	}
	if len(shapes) == 0 || uint64(len(shapes)) > limits.MaxShapes || uint64(len(shapes)) > wire.DefaultMaxShapes {
		return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "mapping.shapes", 0, uint64(len(shapes)), limits.MaxShapes)
	}
	// Rebase built-in shapes only when explicitly requested; this is checked
	// before narrowing IDs and keeps the profile's field order immutable.
	if config.Profile != "" && protocol != wire.ProtocolV5 && config.IDBase != 0 {
		base := config.IDBase
		last, ok := checkedAdd(uint64(base), uint64(len(shapes)-1))
		if !ok || last > math.MaxUint16 || base < 256 {
			return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "templates.id_base", 0, 1, math.MaxUint16)
		}
		for i := range shapes {
			shapes[i].ID = uint32(base + uint32(i))
		}
	}
	for i := range shapes {
		if len(shapes[i].Fields) > int(limits.MaxFieldsPerShape) || uint64(len(shapes[i].Fields)) > wire.DefaultMaxFieldsPerShape {
			return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "mapping.fields", uint64(i+1), uint64(len(shapes[i].Fields)), limits.MaxFieldsPerShape)
		}
		if shapes[i].TemplateBytes > limits.MaxTemplateBytes || shapes[i].TemplateBytes > wire.DefaultMaxTemplateBytes {
			return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "mapping.template", uint64(i+1), shapes[i].TemplateBytes, limits.MaxTemplateBytes)
		}
		if shapes[i].RecordLength > limits.MaxRecordBytes || shapes[i].RecordLength > wire.DefaultMaxRecordBytes {
			return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "mapping.record", uint64(i+1), shapes[i].RecordLength, limits.MaxRecordBytes)
		}
		if err := validateShapeIdentity(shapes[i], protocol, uint64(i+1)); err != nil {
			return CompiledMapping{}, err
		}
		if err := shapeBudget(protocol, shapes[i], maxDatagram, uint64(i+1)); err != nil {
			return CompiledMapping{}, err
		}
	}
	catalog, err := wire.NewCatalog(wire.CatalogSpec{Protocol: protocol, IDBase: shapeIDBase(shapes, protocol), Shapes: shapes, Limits: limits})
	if err != nil {
		return CompiledMapping{}, newConfigError(ErrCodeBounds, protocol, "mapping.catalog", 0, 1, 0)
	}
	for i := range bindings {
		for j := range bindings[i] {
			bindings[i][j].descriptor = shapes[i].Fields[j]
		}
	}
	mapping := Mapper{schema: schema, protocol: protocol, profile: profileName, catalog: catalog, bindings: bindings, familyAgnostic: familyAgnostic, protocolNumbers: protocolMap, networkVersions: networkMap, limits: limits, maxDatagram: maxDatagram, maxMappedBytes: maxMapped, inputKeyLimit: keyLimit, hasOrigin: config.HasUptimeOrigin, origin: config.UptimeOriginUnixNanos}
	mapping.fingerprint = catalogFingerprint(schema, profileName, protocol, catalog, protocolMap, networkMap)
	return CompiledMapping{mapper: mapping}, nil
}

func validateShapeIdentity(shape wire.ShapeSpec, protocol wire.Protocol, ordinal uint64) error {
	type identity struct {
		id  uint16
		pen uint32
	}
	seen := make(map[identity]struct{}, len(shape.Fields))
	for index, descriptor := range shape.Fields {
		key := identity{id: descriptor.ID, pen: descriptor.PEN}
		if _, ok := seen[key]; ok {
			return newConfigError(ErrCodeCollision, protocol, "mapping.fields", ordinal, uint64(index+1), uint64(len(shape.Fields)))
		}
		seen[key] = struct{}{}
	}
	return nil
}

// DecodeJSON is a strict mapping-boundary decoder. It is useful to adapters
// that already decoded YAML into JSON-compatible bytes and rejects unknown
// object members before compilation.
func DecodeJSON(data []byte) (Config, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return Config{}, newConfigError(ErrCodeInvalidConfig, wire.ProtocolUnknown, "mapping", 0, 1, 0)
	}
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, newConfigError(ErrCodeInvalidConfig, wire.ProtocolUnknown, "mapping", 0, 1, 0)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Config{}, newConfigError(ErrCodeInvalidConfig, wire.ProtocolUnknown, "mapping", 0, 1, 0)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return Config{}, newConfigError(ErrCodeInvalidConfig, wire.ProtocolUnknown, "mapping", 0, 1, 0)
	}
	if _, present := members["fields"]; present {
		config.FieldsSet = true
		if bytes.Equal(bytes.TrimSpace(members["fields"]), []byte("null")) {
			config.Fields = []FieldSelection{}
		}
	}
	if _, present := members["protocol_identifiers"]; present && bytes.Equal(bytes.TrimSpace(members["protocol_identifiers"]), []byte("null")) {
		config.ProtocolIdentifiers = []ProtocolIdentifier{}
	}
	if _, present := members["network_type_versions"]; present && bytes.Equal(bytes.TrimSpace(members["network_type_versions"]), []byte("null")) {
		config.NetworkTypeVersions = []NetworkTypeVersion{}
	}
	if custom, present := members["custom"]; present {
		if bytes.Equal(bytes.TrimSpace(custom), []byte("null")) {
			config.Custom = []CustomField{}
		} else {
			var rawEntries []json.RawMessage
			if err := json.Unmarshal(custom, &rawEntries); err != nil || len(rawEntries) != len(config.Custom) {
				return Config{}, newConfigError(ErrCodeInvalidConfig, wire.ProtocolUnknown, "mapping", 0, 1, 0)
			}
			for index, rawEntry := range rawEntries {
				var entryMembers map[string]json.RawMessage
				if err := json.Unmarshal(rawEntry, &entryMembers); err != nil || entryMembers == nil {
					return Config{}, newConfigError(ErrCodeInvalidConfig, wire.ProtocolUnknown, "mapping", 0, 1, 0)
				}
				for _, rawMember := range entryMembers {
					if bytes.Equal(bytes.TrimSpace(rawMember), []byte("null")) {
						return Config{}, newConfigError(ErrCodeInvalidConfig, wire.ProtocolUnknown, "mapping.custom", uint64(index+1), 1, 0)
					}
				}
			}
		}
	}
	return config, nil
}

// DecodeObject applies the same strict member boundary to an object supplied
// by a YAML/Collector adapter. Marshaling is bounded by the caller's object;
// no root Collector configuration is constructed here.
func DecodeObject(object map[string]any) (Config, error) {
	data, err := json.Marshal(object)
	if err != nil {
		return Config{}, newConfigError(ErrCodeInvalidConfig, wire.ProtocolUnknown, "mapping", 0, 1, 0)
	}
	return DecodeJSON(data)
}

func effectiveIDBase(base uint32, protocol wire.Protocol) uint32 {
	if base == 0 && protocol != wire.ProtocolV5 {
		return 256
	}
	return base
}

func mappingLimitsWithDefaults(limits wire.Limits) wire.Limits {
	defaults := wire.DefaultLimits()
	if limits.MaxShapes == 0 {
		limits.MaxShapes = defaults.MaxShapes
	}
	if limits.MaxFieldsPerShape == 0 {
		limits.MaxFieldsPerShape = defaults.MaxFieldsPerShape
	}
	if limits.MaxTemplateBytes == 0 {
		limits.MaxTemplateBytes = defaults.MaxTemplateBytes
	}
	if limits.MaxCustomMappings == 0 {
		limits.MaxCustomMappings = defaults.MaxCustomMappings
	}
	if limits.MaxPENs == 0 {
		limits.MaxPENs = defaults.MaxPENs
	}
	if limits.MaxRecords == 0 {
		limits.MaxRecords = defaults.MaxRecords
	}
	if limits.MaxRecordBytes == 0 {
		limits.MaxRecordBytes = defaults.MaxRecordBytes
	}
	if limits.MaxSetBytes == 0 {
		limits.MaxSetBytes = defaults.MaxSetBytes
	}
	if limits.MaxMessageBytes == 0 {
		limits.MaxMessageBytes = defaults.MaxMessageBytes
	}
	return limits
}

func validateMappingLimits(limits wire.Limits, protocol wire.Protocol) error {
	defaults := wire.DefaultLimits()
	if limits.MaxShapes > defaults.MaxShapes || limits.MaxFieldsPerShape > defaults.MaxFieldsPerShape || limits.MaxTemplateBytes > defaults.MaxTemplateBytes || limits.MaxCustomMappings > defaults.MaxCustomMappings || limits.MaxPENs > defaults.MaxPENs || limits.MaxRecords > defaults.MaxRecords || limits.MaxRecordBytes > defaults.MaxRecordBytes || limits.MaxSetBytes > defaults.MaxSetBytes || limits.MaxMessageBytes > defaults.MaxMessageBytes {
		return newConfigError(ErrCodeBounds, protocol, "mapping.limits", 0, 1, 0)
	}
	return nil
}
func shapeIDBase(shapes []wire.ShapeSpec, protocol wire.Protocol) uint32 {
	if protocol == wire.ProtocolV5 {
		return 0
	}
	return shapes[0].ID
}

func compileTokenMaps(config Config, protocol wire.Protocol, profile bool, fields []FieldSelection, custom []CustomField) (map[string]uint8, map[string]uint8, error) {
	transportActive, networkActive := profile, profile && protocol != wire.ProtocolV5
	if !profile {
		for _, selection := range fields {
			field, ok := canonicalField(selection.Canonical)
			if !ok {
				continue
			}
			transportActive = transportActive || field == wire.FieldNetworkTransport || field == wire.FieldFlowICMPTypeCode || field == wire.FieldFlowICMPType || field == wire.FieldFlowICMPCode
			networkActive = networkActive || field == wire.FieldNetworkType
		}
	}
	if !transportActive && config.ProtocolIdentifiers != nil {
		return nil, nil, newConfigError(ErrCodeProvenance, protocol, "mapping.protocol_identifiers", 0, uint64(len(config.ProtocolIdentifiers)), 0)
	}
	if !networkActive && config.NetworkTypeVersions != nil {
		return nil, nil, newConfigError(ErrCodeProvenance, protocol, "mapping.network_type_versions", 0, uint64(len(config.NetworkTypeVersions)), 0)
	}
	var transport map[string]uint8
	if transportActive {
		if len(config.ProtocolIdentifiers) == 0 || len(config.ProtocolIdentifiers) > 32 {
			return nil, nil, newConfigError(ErrCodeProvenance, protocol, "mapping.protocol_identifiers", 0, uint64(len(config.ProtocolIdentifiers)), 32)
		}
		transport = make(map[string]uint8, len(config.ProtocolIdentifiers))
		seenNumber := make(map[uint8]struct{}, len(config.ProtocolIdentifiers))
		for i, entry := range config.ProtocolIdentifiers {
			expected, ok := protocolNumber(entry.Token)
			if !ok || expected != entry.Number {
				return nil, nil, newConfigError(ErrCodeToken, protocol, "mapping.protocol_identifiers", uint64(i+1), 1, 145)
			}
			if _, ok := transport[entry.Token]; ok {
				return nil, nil, newConfigError(ErrCodeToken, protocol, "mapping.protocol_identifiers", uint64(i+1), uint64(i+1), 32)
			}
			if _, ok := seenNumber[entry.Number]; ok {
				return nil, nil, newConfigError(ErrCodeToken, protocol, "mapping.protocol_identifiers", uint64(i+1), 1, 145)
			}
			transport[entry.Token] = entry.Number
			seenNumber[entry.Number] = struct{}{}
		}
	}
	var network map[string]uint8
	if networkActive {
		if len(config.NetworkTypeVersions) != 2 {
			return nil, nil, newConfigError(ErrCodeProvenance, protocol, "mapping.network_type_versions", 0, uint64(len(config.NetworkTypeVersions)), 2)
		}
		network = make(map[string]uint8, len(config.NetworkTypeVersions))
		for i, entry := range config.NetworkTypeVersions {
			expected, ok := networkVersions[entry.Token]
			if !ok || expected != entry.Version {
				return nil, nil, newConfigError(ErrCodeToken, protocol, "mapping.network_type_versions", uint64(i+1), 1, 6)
			}
			if _, ok := network[entry.Token]; ok {
				return nil, nil, newConfigError(ErrCodeToken, protocol, "mapping.network_type_versions", uint64(i+1), 1, 2)
			}
			network[entry.Token] = entry.Version
		}
		if _, ok := network["ipv4"]; !ok {
			return nil, nil, newConfigError(ErrCodeToken, protocol, "mapping.network_type_versions", 0, 1, 2)
		}
		if _, ok := network["ipv6"]; !ok {
			return nil, nil, newConfigError(ErrCodeToken, protocol, "mapping.network_type_versions", 0, 1, 2)
		}
	}
	if !profile {
		needICMP, needICMPv6 := false, false
		support4, support6 := true, true
		for _, selection := range fields {
			field, ok := canonicalField(selection.Canonical)
			if !ok {
				continue
			}
			v4, v6, _ := familySupport(protocol, field)
			support4, support6 = support4 && v4, support6 && v6
		}
		for _, entry := range custom {
			switch entry.Encoding {
			case "ipv4_address":
				support6 = false
			case "ipv6_address":
				support4 = false
			}
		}
		for _, selection := range fields {
			field, ok := canonicalField(selection.Canonical)
			if !ok {
				continue
			}
			if protocol == wire.ProtocolV9 && field == wire.FieldFlowICMPTypeCode {
				needICMP = support4
			}
			if protocol == wire.ProtocolIPFIX && (field == wire.FieldFlowICMPType || field == wire.FieldFlowICMPCode) {
				needICMP, needICMPv6 = support4, support6
			}
		}
		if (needICMP && transport["icmp"] != 1) || (needICMPv6 && transport["ipv6-icmp"] != 58) {
			return nil, nil, newConfigError(ErrCodeToken, protocol, "mapping.protocol_identifiers", 0, 1, 145)
		}
	}
	return transport, network, nil
}

func canonicalField(name string) (wire.CanonicalField, bool) {
	for field := wire.CanonicalField(0); int(field) < wire.CanonicalFieldCount; field++ {
		if field.CanonicalName() == name {
			return field, true
		}
	}
	if name == "flow.icmp_type_code" {
		return wire.FieldFlowICMPTypeCode, true
	}
	return wire.FieldInvalid, false
}

func compileSelections(fields []FieldSelection, protocol wire.Protocol, policy LossPolicy, guarantees InputGuarantees, hasOrigin bool) ([]selectedField, error) {
	if len(fields) == 0 || len(fields) > wire.DefaultMaxFieldsPerShape {
		return nil, newConfigError(ErrCodeBounds, protocol, "mapping.fields", 0, uint64(len(fields)), 64)
	}
	if protocol == wire.ProtocolV5 {
		return nil, newConfigError(ErrCodeProfile, protocol, "mapping.profile", 0, 1, 1)
	}
	selected := make([]selectedField, 0, len(fields))
	seenTimes := make(map[wire.CanonicalField]struct{}, 2)
	for i, item := range fields {
		field, ok := canonicalField(item.Canonical)
		if !ok {
			return nil, newConfigError(ErrCodeSelector, protocol, "mapping.fields.canonical", uint64(i+1), uint64(i+1), uint64(wire.CanonicalFieldCount))
		}
		if field == wire.FieldFlowStart || field == wire.FieldFlowEnd {
			if _, duplicate := seenTimes[field]; duplicate {
				return nil, newConfigError(ErrCodeCollision, protocol, "mapping.fields", uint64(i+1), uint64(i+1), uint64(len(fields)))
			}
			seenTimes[field] = struct{}{}
		}
		if item.Target != "" && !allowedTarget(protocol, field, item.Target) {
			return nil, newConfigError(ErrCodeSelector, protocol, "mapping.fields.target", uint64(i+1), uint64(i+1), 0)
		}
		if isAmbiguous(protocol, field) && item.Target == "" {
			return nil, newConfigError(ErrCodeSelector, protocol, "mapping.fields.target", uint64(i+1), 0, 1)
		}
		class := classFor(protocol, field, item.Target)
		if class == classUnsupported {
			return nil, newConfigError(ErrCodeUnsupported, protocol, "mapping.fields", uint64(i+1), uint64(class), 0)
		}
		if class == classInapplicable {
			return nil, newConfigError(ErrCodeInapplicable, protocol, "mapping.fields", uint64(i+1), uint64(class), 0)
		}
		if policy == LossPolicyReject && class.lossy() {
			return nil, newConfigError(ErrCodePolicy, protocol, "mapping.loss_policy", uint64(i+1), uint64(class), uint64(classExact))
		}
		if field == wire.FieldFlowStart || field == wire.FieldFlowEnd {
			if protocol == wire.ProtocolV9 && !hasOrigin {
				return nil, newConfigError(ErrCodeProvenance, protocol, "mapping.uptime_origin", uint64(i+1), 0, 1)
			}
		}
		if protocol == wire.ProtocolV5 && field == wire.FieldFlowIOBytes && guarantees.FlowIOBytes != "layer3_total_octets" {
			return nil, newConfigError(ErrCodeProvenance, protocol, "mapping.input_guarantees.flow_io_bytes", uint64(i+1), 0, 1)
		}
		selected = append(selected, selectedField{field: field, target: item.Target, class: class})
	}
	return selected, nil
}

func explicitMappingFamilyAgnostic(selected []selectedField, custom []CustomField, protocol wire.Protocol) bool {
	support4, support6, dependent := true, true, false
	for _, item := range selected {
		v4, v6, isDependent := familySupport(protocol, item.field)
		support4, support6 = support4 && v4, support6 && v6
		dependent = dependent || isDependent
	}
	for _, entry := range custom {
		encoding, ok := encodingFromName(entry.Encoding)
		if !ok {
			return false
		}
		if encoding == wire.EncodingIPv4Address {
			support6 = false
		}
		if encoding == wire.EncodingIPv6Address {
			support4 = false
		}
		if encoding == wire.EncodingIPv4Address || encoding == wire.EncodingIPv6Address {
			dependent = dependent || support4 && support6
		}
	}
	return support4 && support6 && !dependent
}

func compileExplicitShapes(selected []selectedField, custom []CustomField, protocol wire.Protocol, base uint32) ([]wire.ShapeSpec, [][]shapeBinding, error) {
	support4, support6, dependent := true, true, false
	for _, item := range selected {
		v4, v6, isDependent := familySupport(protocol, item.field)
		support4, support6 = support4 && v4, support6 && v6
		dependent = dependent || isDependent
	}
	for _, entry := range custom {
		encoding, ok := encodingFromName(entry.Encoding)
		if !ok {
			return nil, nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom.encoding", 0, 1, 14)
		}
		if encoding == wire.EncodingIPv4Address {
			support6 = false
		}
		if encoding == wire.EncodingIPv6Address {
			support4 = false
		}
		if encoding == wire.EncodingIPv4Address || encoding == wire.EncodingIPv6Address {
			dependent = dependent || support4 && support6
		}
	}
	if !support4 && !support6 {
		return nil, nil, newConfigError(ErrCodeInapplicable, protocol, "mapping.fields", 0, 0, 1)
	}
	families := make([]wire.Family, 0, 2)
	if support4 && support6 && dependent {
		families = append(families, wire.FamilyIPv4, wire.FamilyIPv6)
	} else if support4 {
		families = append(families, wire.FamilyIPv4)
	} else {
		families = append(families, wire.FamilyIPv6)
	}
	if len(families) > 1 && base > math.MaxUint16-1 {
		return nil, nil, newConfigError(ErrCodeBounds, protocol, "templates.id_base", 0, 1, math.MaxUint16)
	}
	if base < 256 || base > math.MaxUint16 {
		return nil, nil, newConfigError(ErrCodeBounds, protocol, "templates.id_base", 0, 1, math.MaxUint16)
	}
	shapes := make([]wire.ShapeSpec, 0, len(families))
	bindings := make([][]shapeBinding, 0, len(families))
	for index, family := range families {
		bind := make([]shapeBinding, 0, len(selected)+len(custom))
		for _, item := range selected {
			descriptor, err := descriptorFor(protocol, item.field, item.target, family)
			if err != nil {
				return nil, nil, newConfigError(ErrCodeUnsupported, protocol, "mapping.fields", uint64(index+1), uint64(item.field), 0)
			}
			bind = append(bind, shapeBinding{descriptor: descriptor, field: item.field, class: item.class})
		}
		for customIndex, entry := range custom {
			descriptor, err := customDescriptor(entry, protocol, family)
			if err != nil {
				return nil, nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom", uint64(customIndex+1), uint64(customIndex+1), uint64(len(custom)))
			}
			bind = append(bind, shapeBinding{descriptor: descriptor, custom: true, class: classExact})
		}
		fields := bindDescriptors(bind)
		length, ok := checkedSumLengths(fields)
		if !ok || length == 0 {
			return nil, nil, newConfigError(ErrCodeBounds, protocol, "mapping.fields", uint64(index+1), length, 65535)
		}
		template, ok := templateBytes(protocol, fields)
		if !ok {
			return nil, nil, newConfigError(ErrCodeBounds, protocol, "mapping.template", uint64(index+1), math.MaxUint64, 4096)
		}
		shapes = append(shapes, wire.ShapeSpec{Protocol: protocol, Family: family, ID: base + uint32(index), Fields: fields, RecordLength: length, TemplateBytes: template})
		bindings = append(bindings, bind)
	}
	return shapes, bindings, nil
}

func bindDescriptors(bindings []shapeBinding) []wire.FieldDescriptor {
	out := make([]wire.FieldDescriptor, len(bindings))
	for i, binding := range bindings {
		out[i] = binding.descriptor
	}
	return out
}
func checkedSumLengths(fields []wire.FieldDescriptor) (uint64, bool) {
	var sum uint64
	for _, field := range fields {
		var ok bool
		sum, ok = checkedAdd(sum, uint64(field.MinimumLength()))
		if !ok || sum > 65535 {
			return sum, false
		}
	}
	return sum, true
}
func templateBytes(protocol wire.Protocol, fields []wire.FieldDescriptor) (uint64, bool) {
	if protocol == wire.ProtocolV5 {
		return 0, true
	}
	total := uint64(8)
	for _, field := range fields {
		extra := uint64(4)
		if protocol == wire.ProtocolIPFIX && field.Enterprise {
			extra = 8
		}
		var ok bool
		total, ok = checkedAdd(total, extra)
		if !ok || total > wire.DefaultMaxTemplateBytes {
			return total, false
		}
	}
	return total, true
}

func builtinTarget(protocol wire.Protocol, descriptor wire.FieldDescriptor) string {
	if protocol == wire.ProtocolV9 {
		if descriptor.Field == wire.FieldFlowIOBytes {
			return "in_bytes"
		}
		if descriptor.Field == wire.FieldFlowIOPackets {
			return "in_packets"
		}
	}
	if protocol == wire.ProtocolIPFIX {
		if descriptor.Field == wire.FieldFlowIOBytes {
			return "octet_delta_count"
		}
		if descriptor.Field == wire.FieldFlowIOPackets {
			return "packet_delta_count"
		}
		if descriptor.Field == wire.FieldNetworkType {
			return "ip_version"
		}
	}
	return ""
}

func customDescriptor(entry CustomField, protocol wire.Protocol, family wire.Family) (wire.FieldDescriptor, error) {
	encoding, ok := encodingFromName(entry.Encoding)
	if !ok {
		return wire.FieldDescriptor{}, wire.ErrInvalidDescriptor
	}
	if !utf8.ValidString(entry.Source) || entry.Source == "" || len(entry.Source) > int(hardMaxAttributeKeyBytes) {
		return wire.FieldDescriptor{}, wire.ErrInvalidDescriptor
	}
	if protocol == wire.ProtocolV9 {
		if entry.FieldType == nil || entry.FixedLength == nil || entry.AllowPrivate == nil || !*entry.AllowPrivate || *entry.FieldType < 256 || *entry.FieldType > math.MaxUint16 || entry.PEN != nil || entry.ElementID != nil || entry.Variable != nil || entry.MaxLength != nil || *entry.FixedLength == 0 {
			return wire.FieldDescriptor{}, wire.ErrInvalidDescriptor
		}
		fixedLength := *entry.FixedLength
		if !customLengthAllowed(encoding, uint64(fixedLength)) {
			return wire.FieldDescriptor{}, wire.ErrInvalidDescriptor
		}
		if natural := naturalLength(encoding); natural != 0 && fixedLength != natural {
			return wire.FieldDescriptor{}, wire.ErrInvalidDescriptor
		}
		if (encoding == wire.EncodingIPv4Address && family != wire.FamilyIPv4) || (encoding == wire.EncodingIPv6Address && family != wire.FamilyIPv6) {
			return wire.FieldDescriptor{}, wire.ErrInvalidFamily
		}
		return wire.NewV9PrivateDescriptor(entry.Source, *entry.FieldType, encoding, fixedLength)
	}
	if protocol != wire.ProtocolIPFIX || entry.PEN == nil || entry.ElementID == nil || *entry.PEN == 0 || *entry.ElementID < 1 || *entry.ElementID > 32767 || entry.FieldType != nil || entry.AllowPrivate != nil {
		return wire.FieldDescriptor{}, wire.ErrInvalidDescriptor
	}
	if entry.Variable != nil {
		if !*entry.Variable || entry.FixedLength != nil || entry.MaxLength == nil || *entry.MaxLength == 0 || uint64(*entry.MaxLength) > hardMaxMappedValueBytes || !customLengthAllowed(encoding, uint64(*entry.MaxLength)) || (encoding != wire.EncodingString && encoding != wire.EncodingOctetArray) {
			return wire.FieldDescriptor{}, wire.ErrInvalidDescriptor
		}
		return wire.NewIPFIXEnterpriseDescriptor(entry.Source, *entry.PEN, *entry.ElementID, encoding, true, 65535, *entry.MaxLength)
	}
	if entry.FixedLength == nil || entry.MaxLength != nil {
		return wire.FieldDescriptor{}, wire.ErrInvalidDescriptor
	}
	fixedLength := *entry.FixedLength
	if !customLengthAllowed(encoding, uint64(fixedLength)) {
		return wire.FieldDescriptor{}, wire.ErrInvalidDescriptor
	}
	if natural := naturalLength(encoding); natural != 0 && fixedLength != natural {
		return wire.FieldDescriptor{}, wire.ErrInvalidDescriptor
	}
	if (encoding == wire.EncodingIPv4Address && family != wire.FamilyIPv4) || (encoding == wire.EncodingIPv6Address && family != wire.FamilyIPv6) {
		return wire.FieldDescriptor{}, wire.ErrInvalidFamily
	}
	return wire.NewIPFIXEnterpriseDescriptor(entry.Source, *entry.PEN, *entry.ElementID, encoding, false, fixedLength, 0)
}

func customLengthAllowed(encoding wire.DescriptorEncoding, length uint64) bool {
	if encoding == wire.EncodingString || encoding == wire.EncodingOctetArray {
		return length >= 1 && length <= hardMaxMappedValueBytes
	}
	return true
}

func compileCustom(entries []CustomField, protocol wire.Protocol, keyLimit, maxMapped uint64, limits wire.Limits) ([]CustomField, error) {
	if uint64(len(entries)) > limits.MaxCustomMappings || uint64(len(entries)) > wire.DefaultMaxCustomMappings {
		return nil, newConfigError(ErrCodeBounds, protocol, "mapping.custom", 0, uint64(len(entries)), limits.MaxCustomMappings)
	}
	seenPENs := make(map[uint32]struct{}, len(entries))
	for i, entry := range entries {
		if entry.Source == "" || !utf8.ValidString(entry.Source) || reservedCustomSource(entry.Source) || uint64(len(entry.Source)) > keyLimit || uint64(len(entry.Source)) > hardMaxAttributeKeyBytes {
			return nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom.source", uint64(i+1), uint64(len(entry.Source)), keyLimit)
		}
		if _, ok := canonicalField(entry.Source); ok {
			return nil, newConfigError(ErrCodeCollision, protocol, "mapping.custom.source", uint64(i+1), uint64(i+1), 0)
		}
		encoding, ok := encodingFromName(entry.Encoding)
		if !ok || encoding == wire.EncodingDateTimeNanoseconds {
			return nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom.encoding", uint64(i+1), 1, 14)
		}
		if entry.FixedLength != nil && (uint64(*entry.FixedLength) > maxMapped || uint64(*entry.FixedLength) > hardMaxMappedValueBytes) {
			return nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom.fixed_length", uint64(i+1), uint64(*entry.FixedLength), maxMapped)
		}
		if protocol == wire.ProtocolV9 {
			if entry.FieldType == nil || entry.FixedLength == nil || entry.AllowPrivate == nil || !*entry.AllowPrivate || *entry.FieldType < 256 || *entry.FieldType > math.MaxUint16 || entry.PEN != nil || entry.ElementID != nil || entry.Variable != nil || entry.MaxLength != nil || *entry.FixedLength == 0 {
				return nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom", uint64(i+1), 1, 65535)
			}
			if !customLengthAllowed(encoding, uint64(*entry.FixedLength)) {
				return nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom.fixed_length", uint64(i+1), uint64(*entry.FixedLength), 4096)
			}
			if natural := naturalLength(encoding); natural != 0 && *entry.FixedLength != natural {
				return nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom.fixed_length", uint64(i+1), uint64(*entry.FixedLength), uint64(natural))
			}
		} else if protocol == wire.ProtocolIPFIX {
			if entry.PEN == nil || entry.ElementID == nil || entry.FieldType != nil || entry.AllowPrivate != nil || *entry.PEN == 0 || *entry.ElementID < 1 || *entry.ElementID > 32767 {
				return nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom", uint64(i+1), 1, 32767)
			}
			fixedPresent := entry.FixedLength != nil
			variablePresent := entry.Variable != nil
			maxPresent := entry.MaxLength != nil
			if fixedPresent && (variablePresent || maxPresent) {
				return nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom.length", uint64(i+1), 2, 1)
			}
			if variablePresent {
				if !*entry.Variable || fixedPresent || !maxPresent || *entry.MaxLength == 0 || uint64(*entry.MaxLength) > maxMapped || uint64(*entry.MaxLength) > hardMaxMappedValueBytes || !customLengthAllowed(encoding, uint64(*entry.MaxLength)) || (encoding != wire.EncodingString && encoding != wire.EncodingOctetArray) {
					actual := uint64(0)
					if maxPresent {
						actual = uint64(*entry.MaxLength)
					}
					return nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom.max_length", uint64(i+1), actual, maxMapped)
				}
			} else if !fixedPresent || *entry.FixedLength == 0 || maxPresent {
				return nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom.fixed_length", uint64(i+1), 0, 1)
			} else if !customLengthAllowed(encoding, uint64(*entry.FixedLength)) {
				return nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom.fixed_length", uint64(i+1), uint64(*entry.FixedLength), 4096)
			} else if natural := naturalLength(encoding); natural != 0 && *entry.FixedLength != natural {
				return nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom.fixed_length", uint64(i+1), uint64(*entry.FixedLength), uint64(natural))
			}
			seenPENs[*entry.PEN] = struct{}{}
			if uint64(len(seenPENs)) > limits.MaxPENs || uint64(len(seenPENs)) > wire.DefaultMaxPENs {
				return nil, newConfigError(ErrCodeBounds, protocol, "mapping.custom.pen", uint64(i+1), uint64(len(seenPENs)), limits.MaxPENs)
			}
		} else {
			return nil, newConfigError(ErrCodeCustom, protocol, "mapping.custom", uint64(i+1), 1, 0)
		}
	}
	return append([]CustomField(nil), entries...), nil
}

func reservedCustomSource(source string) bool {
	for _, prefix := range []string{"body", "resource", "scope"} {
		if source == prefix || strings.HasPrefix(source, prefix+".") {
			return true
		}
	}
	return false
}

func shapeBudget(protocol wire.Protocol, shape wire.ShapeSpec, maxDatagram, ordinal uint64) error {
	header := uint64(0)
	switch protocol {
	case wire.ProtocolV5:
		header = 24
	case wire.ProtocolV9:
		header = 20
	case wire.ProtocolIPFIX:
		header = 16
	default:
		return newConfigError(ErrCodeBounds, protocol, "mapping.protocol", 0, 1, 3)
	}
	if protocol != wire.ProtocolV5 {
		if total, ok := checkedAdd(header, shape.TemplateBytes); !ok || total > maxDatagram {
			return newConfigError(ErrCodeBounds, protocol, "mapping.template", ordinal, total, maxDatagram)
		}
	}
	data, ok := mappingDataBytes(protocol, shape.RecordLength)
	if !ok || data > maxDatagram {
		return newConfigError(ErrCodeBounds, protocol, "mapping.record", ordinal, data, maxDatagram)
	}
	return nil
}

func mappingDataBytes(protocol wire.Protocol, recordLength uint64) (uint64, bool) {
	if protocol == wire.ProtocolV5 {
		return checkedAdd(mappingHeaderBytes(protocol), recordLength)
	}
	return mappingDataBytesForMinimum(protocol, recordLength, recordLength)
}

func mappingDataBytesForMinimum(protocol wire.Protocol, recordLength, minimumRecordLength uint64) (uint64, bool) {
	if protocol == wire.ProtocolV5 {
		return checkedAdd(mappingHeaderBytes(protocol), recordLength)
	}
	data, ok := checkedAdd(mappingHeaderBytes(protocol), 4)
	if !ok {
		return 0, false
	}
	data, ok = checkedAdd(data, recordLength)
	if !ok {
		return data, ok
	}
	setBytes, ok := checkedAdd(4, recordLength)
	if !ok {
		return 0, false
	}
	if remainder := setBytes & 3; remainder != 0 {
		padding := uint64(4 - remainder)
		if padding < minimumRecordLength {
			data, ok = checkedAdd(data, padding)
		}
	}
	return data, ok
}

func validatePMTU(config Config, payload uint64, protocol wire.Protocol) error {
	if config.PathMTU == 0 {
		if payload > defaultMaxDatagramSize {
			return newConfigError(ErrCodePMTU, protocol, "path_mtu", 0, payload, defaultMaxDatagramSize)
		}
		return nil
	}
	if config.PathMTU < 512 || config.PathMTU > 65535 {
		return newConfigError(ErrCodePMTU, protocol, "path_mtu", 0, config.PathMTU, 65535)
	}
	reserve := uint64(48)
	host := config.Endpoint
	if host != "" {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if address, err := netip.ParseAddr(host); err == nil && address.Is4() {
			reserve = 28
		}
	}
	budget, ok := checkedAdd(payload, reserve)
	if !ok || budget > config.PathMTU {
		return newConfigError(ErrCodePMTU, protocol, "max_datagram_size", 0, budget, config.PathMTU)
	}
	return nil
}

func checkedAdd(a, b uint64) (uint64, bool) {
	if b > math.MaxUint64-a {
		return 0, false
	}
	return a + b, true
}
