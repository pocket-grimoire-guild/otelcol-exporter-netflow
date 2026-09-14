package wire

import (
	"math"
	"unicode/utf8"
)

const (
	protocolV5HeaderBytes    = uint64(24)
	protocolV9HeaderBytes    = uint64(20)
	protocolIPFIXHeaderBytes = uint64(16)
	flowSetHeaderBytes       = uint64(4)
)

// ShapeSpec is the construction form for an immutable Shape.  Lengths are
// widened before they are narrowed into wire-sized fields.
type ShapeSpec struct {
	Protocol      Protocol
	Family        Family
	ID            uint32
	Fields        []FieldDescriptor
	RecordLength  uint64 // fixed length, or minimum length for variable fields
	TemplateBytes uint64 // encoded Template FlowSet/Set bytes; zero for v5
	Options       bool   // Options templates are intentionally not in this contract
}

// Shape is an immutable ordered static data shape.  Fields returns a copy;
// there is no operation that mutates a compiled shape.
type Shape struct {
	protocol      Protocol
	family        Family
	id            uint16
	fields        []FieldDescriptor
	recordLength  uint64
	templateBytes uint64
}

// ValidateShape is a function-form constructor for callers that prefer a
// contract-named API.
func ValidateShape(spec ShapeSpec) (Shape, error) { return NewShape(spec) }

// NewShape validates and copies one static shape.  Catalog-level ceilings and
// ID uniqueness are checked by NewCatalog; direct construction still checks
// all descriptor, family, width, and sum invariants.
func NewShape(spec ShapeSpec) (Shape, error) {
	if spec.Protocol != ProtocolV5 && spec.Protocol != ProtocolV9 && spec.Protocol != ProtocolIPFIX {
		return Shape{}, ErrInvalidProtocol
	}
	if spec.Family != FamilyIPv4 && spec.Family != FamilyIPv6 {
		return Shape{}, ErrInvalidFamily
	}
	if spec.Protocol == ProtocolV5 && spec.Family != FamilyIPv4 {
		return Shape{}, ErrInvalidShape
	}
	if spec.Options {
		return Shape{}, ErrInvalidShape
	}
	if spec.ID > math.MaxUint16 {
		return Shape{}, ErrInvalidShape
	}
	if spec.Protocol != ProtocolV5 && (spec.ID < 256 || spec.ID > math.MaxUint16) {
		return Shape{}, ErrInvalidShape
	}
	if spec.Protocol == ProtocolV5 && spec.ID != 1 {
		return Shape{}, ErrInvalidShape
	}
	if len(spec.Fields) == 0 || uint64(len(spec.Fields)) > DefaultMaxFieldsPerShape {
		return Shape{}, ErrInvalidShape
	}
	if spec.TemplateBytes > DefaultMaxTemplateBytes {
		return Shape{}, ErrBounds
	}
	if spec.Protocol == ProtocolV5 && spec.TemplateBytes != 0 {
		return Shape{}, ErrInvalidShape
	}
	if spec.Protocol != ProtocolV5 && spec.TemplateBytes == 0 {
		return Shape{}, ErrInvalidShape
	}

	fields := make([]FieldDescriptor, len(spec.Fields))
	copy(fields, spec.Fields)
	seen := make(map[wireIdentity]struct{}, len(fields))
	var sum uint64
	for i, field := range fields {
		if err := field.Validate(); err != nil {
			return Shape{}, err
		}
		if field.Protocol != spec.Protocol {
			return Shape{}, ErrInvalidDescriptor
		}
		if (field.Encoding == EncodingIPv4Address && spec.Family != FamilyIPv4) || (field.Encoding == EncodingIPv6Address && spec.Family != FamilyIPv6) {
			return Shape{}, ErrInvalidShape
		}
		identity := field.identity()
		if _, ok := seen[identity]; ok {
			return Shape{}, ErrDuplicateIdentity
		}
		seen[identity] = struct{}{}
		width := field.MinimumLength()
		var ok bool
		sum, ok = checkedAdd(sum, uint64(width))
		if !ok {
			return Shape{}, ErrBounds
		}
		fields[i] = field
	}
	if spec.RecordLength == 0 || spec.RecordLength != sum || spec.RecordLength > DefaultMaxRecordBytes {
		return Shape{}, ErrInvalidShape
	}
	if spec.Protocol == ProtocolV5 && !isExactV5Shape(spec.Family, spec.ID, fields, spec.RecordLength) {
		return Shape{}, ErrInvalidShape
	}
	expectedTemplate, ok := templateBytesFor(spec.Protocol, fields)
	if !ok || expectedTemplate != spec.TemplateBytes {
		return Shape{}, ErrInvalidShape
	}
	return Shape{
		protocol:      spec.Protocol,
		family:        spec.Family,
		id:            uint16(spec.ID),
		fields:        fields,
		recordLength:  spec.RecordLength,
		templateBytes: spec.TemplateBytes,
	}, nil
}

// Protocol reports the shape protocol.
func (s Shape) Protocol() Protocol { return s.protocol }

// Family reports the shape address family.
func (s Shape) Family() Family { return s.family }

// ID reports the precompiled template ID or fixed-profile ordinal.
func (s Shape) ID() uint16 { return s.id }

// Fields returns an independent copy of the ordered field descriptors.
func (s Shape) Fields() []FieldDescriptor {
	return append([]FieldDescriptor(nil), s.fields...)
}

// DescriptorAt returns one ordered descriptor without allocating.  Callers
// can use Fields for diagnostic copies, while writers stay on this hot path.
func (s Shape) DescriptorAt(index int) (FieldDescriptor, bool) {
	if index < 0 || index >= len(s.fields) {
		return FieldDescriptor{}, false
	}
	return s.fields[index], true
}

// FieldAt is a concise alias for DescriptorAt used by mapping adapters.
func (s Shape) FieldAt(index int) (FieldDescriptor, bool) { return s.DescriptorAt(index) }

// FieldCount reports the number of fields in this shape.
func (s Shape) FieldCount() int { return len(s.fields) }

// RecordLength reports the fixed or minimum encoded Data Record length.
func (s Shape) RecordLength() uint64 { return s.recordLength }

// TemplateBytes reports the encoded Template FlowSet/Set bytes, or zero for
// NetFlow v5's fixed profile.
func (s Shape) TemplateBytes() uint64 { return s.templateBytes }

// CatalogSpec is the construction form for an immutable shape catalog.
type CatalogSpec struct {
	Protocol Protocol
	IDBase   uint32
	Shapes   []ShapeSpec
	Limits   Limits
}

// Catalog is an immutable ordered catalog of precompiled family shapes.
type Catalog struct {
	protocol Protocol
	shapes   []Shape
	limits   Limits
}

// ValidateCatalog is the function-form catalog constructor.
func ValidateCatalog(spec CatalogSpec) (Catalog, error) { return NewCatalog(spec) }

// NewCatalog validates every shape and all aggregate bounds before copying the
// catalog.  IDs need not be consecutive for a custom catalog, but are always
// unique and fit in the protocol's 16-bit identity space.
func NewCatalog(spec CatalogSpec) (Catalog, error) {
	if spec.Protocol != ProtocolV5 && spec.Protocol != ProtocolV9 && spec.Protocol != ProtocolIPFIX {
		return Catalog{}, ErrInvalidProtocol
	}
	limits := spec.Limits.withDefaults()
	if limits.MaxShapes == 0 || uint64(len(spec.Shapes)) == 0 || uint64(len(spec.Shapes)) > limits.MaxShapes || uint64(len(spec.Shapes)) > DefaultMaxShapes {
		return Catalog{}, ErrBounds
	}
	if spec.Protocol == ProtocolV5 && len(spec.Shapes) != 1 {
		return Catalog{}, ErrInvalidCatalog
	}
	if spec.IDBase > math.MaxUint16 {
		return Catalog{}, ErrBounds
	}
	if spec.Protocol != ProtocolV5 && spec.IDBase < 256 {
		return Catalog{}, ErrBounds
	}
	if spec.Protocol != ProtocolV5 {
		lastID, ok := checkedAdd(uint64(spec.IDBase), uint64(len(spec.Shapes)-1))
		if !ok || lastID > math.MaxUint16 {
			return Catalog{}, ErrBounds
		}
	}
	shapes := make([]Shape, len(spec.Shapes))
	ids := make(map[uint16]struct{}, len(spec.Shapes))
	penSet := make(map[uint32]struct{})
	customMappings := make(map[mappingIdentity]struct{})
	for i, raw := range spec.Shapes {
		if raw.Protocol == ProtocolUnknown {
			raw.Protocol = spec.Protocol
		}
		if raw.Protocol != spec.Protocol {
			return Catalog{}, ErrInvalidShape
		}
		if raw.ID == 0 && spec.Protocol != ProtocolV5 {
			next, ok := checkedAdd(uint64(spec.IDBase), uint64(i))
			if !ok || next > math.MaxUint16 {
				return Catalog{}, ErrBounds
			}
			raw.ID = uint32(next)
		}
		shape, err := NewShape(raw)
		if err != nil {
			return Catalog{}, err
		}
		if uint64(shape.FieldCount()) > limits.MaxFieldsPerShape || shape.RecordLength() > limits.MaxRecordBytes || shape.TemplateBytes() > limits.MaxTemplateBytes {
			return Catalog{}, ErrBounds
		}
		if _, ok := ids[shape.id]; ok {
			return Catalog{}, ErrDuplicateIdentity
		}
		ids[shape.id] = struct{}{}
		for _, field := range shape.fields {
			if field.Custom {
				customMappings[field.mappingIdentity()] = struct{}{}
				if field.Protocol == ProtocolIPFIX && field.PEN != 0 {
					penSet[field.PEN] = struct{}{}
				}
			}
		}
		shapes[i] = shape
	}
	if uint64(len(customMappings)) > limits.MaxCustomMappings || uint64(len(customMappings)) > DefaultMaxCustomMappings || uint64(len(penSet)) > limits.MaxPENs || uint64(len(penSet)) > DefaultMaxPENs {
		return Catalog{}, ErrBounds
	}
	return Catalog{protocol: spec.Protocol, shapes: shapes, limits: limits}, nil
}

// Protocol reports the catalog protocol.
func (c Catalog) Protocol() Protocol { return c.protocol }

// ShapeCount reports the number of precompiled shapes.
func (c Catalog) ShapeCount() int { return len(c.shapes) }

// Shapes returns independent shape values with independent descriptor slices.
func (c Catalog) Shapes() []Shape {
	out := make([]Shape, len(c.shapes))
	for i, shape := range c.shapes {
		out[i] = shape
		out[i].fields = append([]FieldDescriptor(nil), shape.fields...)
	}
	return out
}

// ShapeAt returns an immutable shape by index.
//
// The returned value shares the catalog's private descriptor slice. Shape has
// no mutator for that slice, and Fields, Shapes, and the descriptor accessors
// return independent copies where a slice crosses the API boundary. Keeping
// the immutable slice shared avoids a per-record allocation on hot lookup
// paths while preserving catalog ownership.
func (c Catalog) ShapeAt(index int) (Shape, bool) {
	if index < 0 || index >= len(c.shapes) {
		return Shape{}, false
	}
	return c.shapes[index], true
}

// Validate checks an already-compiled catalog.  It is useful at writer
// boundaries where a catalog may have crossed an API seam.
func (c Catalog) Validate() error {
	if c.protocol == ProtocolUnknown || len(c.shapes) == 0 {
		return ErrInvalidCatalog
	}
	specs := make([]ShapeSpec, len(c.shapes))
	for i, shape := range c.shapes {
		specs[i] = ShapeSpec{
			Protocol:      shape.protocol,
			Family:        shape.family,
			ID:            uint32(shape.id),
			Fields:        shape.Fields(),
			RecordLength:  shape.recordLength,
			TemplateBytes: shape.templateBytes,
		}
	}
	spec := CatalogSpec{Protocol: c.protocol, Shapes: specs, Limits: c.limits}
	if c.protocol != ProtocolV5 {
		spec.IDBase = uint32(c.shapes[0].id)
	}
	_, err := NewCatalog(spec)
	return err
}

// Validate validates a protocol descriptor independently of a shape.
func (d FieldDescriptor) Validate() error {
	if d.Protocol != ProtocolV5 && d.Protocol != ProtocolV9 && d.Protocol != ProtocolIPFIX {
		return ErrInvalidDescriptor
	}
	if d.Custom {
		if d.Source == "" || len(d.Source) > 1024 || !utf8.ValidString(d.Source) || d.Constant || d.Field != FieldInvalid {
			return ErrInvalidDescriptor
		}
		for _, canonical := range canonicalNames {
			if d.Source == canonical {
				return ErrInvalidDescriptor
			}
		}
		if d.Source == "flow.icmp_type_code" {
			return ErrInvalidDescriptor
		}
	} else if d.Constant {
		if d.Protocol != ProtocolV5 || d.Field != FieldInvalid || d.Source != "" {
			return ErrInvalidDescriptor
		}
	} else if !d.Field.Valid() || d.Source != "" {
		return ErrInvalidDescriptor
	}
	if d.Field == FieldFlowICMPTypeCode {
		if d.Protocol != ProtocolV9 || d.ID != 32 || d.Length != 2 || d.Encoding != EncodingUnsigned16 {
			return ErrInvalidDescriptor
		}
	}
	if d.Encoding == EncodingUnspecified || d.Encoding > EncodingDateTimeMilliseconds {
		return ErrInvalidDescriptor
	}
	if d.Encoding == EncodingDateTimeNanoseconds && d.Protocol != ProtocolIPFIX {
		return ErrInvalidDescriptor
	}
	if d.Encoding == EncodingDateTimeMilliseconds {
		if d.Protocol != ProtocolIPFIX || d.Custom || d.Length != 8 ||
			(d.Field != FieldFlowStart && d.Field != FieldFlowEnd) ||
			(d.Field == FieldFlowStart && d.ID != 152) ||
			(d.Field == FieldFlowEnd && d.ID != 153) {
			return ErrInvalidDescriptor
		}
	}
	switch d.Protocol {
	case ProtocolV5:
		if d.Custom || d.ID == 0 || d.PEN != 0 || d.Enterprise || d.Private || d.Variable || d.MaxLength != 0 || d.Length == 0 {
			return ErrInvalidDescriptor
		}
		if d.Constant && !((d.ID == 12 && d.Length == 1 && d.Encoding == EncodingUnsigned8) || (d.ID == 20 && d.Length == 2 && d.Encoding == EncodingUnsigned16)) {
			return ErrInvalidDescriptor
		}
	case ProtocolV9:
		if d.ID == 0 || d.PEN != 0 || d.Enterprise || d.Variable || d.MaxLength != 0 || d.Length == 0 {
			return ErrInvalidDescriptor
		}
		if d.Private != d.Custom {
			return ErrInvalidDescriptor
		}
		if d.Private {
			if d.ID < 256 {
				return ErrInvalidDescriptor
			}
		} else if d.ID > 255 {
			return ErrInvalidDescriptor
		}
	case ProtocolIPFIX:
		if d.ID == 0 || d.ID > 32767 || d.Private {
			return ErrInvalidDescriptor
		}
		if d.Enterprise != d.Custom {
			return ErrInvalidDescriptor
		}
		if d.Enterprise {
			if d.PEN == 0 {
				return ErrInvalidDescriptor
			}
		} else if d.PEN != 0 {
			return ErrInvalidDescriptor
		}
		if d.Variable {
			if !d.Custom {
				return ErrInvalidDescriptor
			}
			if d.Length != 65535 || d.MaxLength == 0 || d.MaxLength > HardMaxMappedValueBytes {
				return ErrInvalidDescriptor
			}
		} else if d.Length == 0 || d.Length == 65535 || d.MaxLength != 0 {
			return ErrInvalidDescriptor
		}
		if !d.Enterprise && (d.ID == 152 || d.ID == 153) && d.Encoding != EncodingDateTimeMilliseconds {
			return ErrInvalidDescriptor
		}
		if !d.Enterprise && d.Encoding == EncodingDateTimeMilliseconds && d.ID != 152 && d.ID != 153 {
			return ErrInvalidDescriptor
		}
	}
	if natural := naturalEncodingLength(d.Encoding); natural != 0 && uint16(natural) != d.Length && !d.Variable {
		return ErrInvalidDescriptor
	}
	if d.Custom && d.Variable && d.Protocol != ProtocolIPFIX {
		return ErrInvalidDescriptor
	}
	if d.Custom && d.Protocol == ProtocolV9 && !d.Private {
		return ErrInvalidDescriptor
	}
	if d.Custom && d.Protocol == ProtocolIPFIX && !d.Enterprise {
		return ErrInvalidDescriptor
	}
	if d.Custom && !d.Variable && (d.Encoding == EncodingString || d.Encoding == EncodingOctetArray) && d.Length == 0 {
		return ErrInvalidDescriptor
	}
	if d.Custom && d.Variable && d.Encoding != EncodingString && d.Encoding != EncodingOctetArray {
		return ErrInvalidDescriptor
	}
	if d.Custom && d.Encoding == EncodingDateTimeNanoseconds {
		return ErrInvalidDescriptor
	}
	return nil
}

// ValidateDescriptor is the function-form descriptor validator.
func ValidateDescriptor(d FieldDescriptor) error { return d.Validate() }

// MinimumLength returns the minimum bytes occupied by a field in a data
// record.  IPFIX variable fields have a one-byte prefix for values <255 and
// therefore contribute one byte to a static minimum.
func (d FieldDescriptor) MinimumLength() uint16 {
	if d.Variable {
		return 1
	}
	return d.Length
}

type wireIdentity struct {
	protocol Protocol
	id       uint16
	pen      uint32
}

type mappingIdentity struct {
	protocol   Protocol
	source     string
	id         uint16
	pen        uint32
	encoding   DescriptorEncoding
	length     uint16
	variable   bool
	maxLength  uint16
	private    bool
	enterprise bool
}

func (d FieldDescriptor) identity() wireIdentity {
	return wireIdentity{protocol: d.Protocol, id: d.ID, pen: d.PEN}
}

func (d FieldDescriptor) mappingIdentity() mappingIdentity {
	return mappingIdentity{
		protocol: d.Protocol, source: d.Source, id: d.ID, pen: d.PEN,
		encoding: d.Encoding, length: d.Length, variable: d.Variable,
		maxLength: d.MaxLength, private: d.Private, enterprise: d.Enterprise,
	}
}

// Identity returns the protocol, numeric field ID, and enterprise PEN that
// participate in duplicate-wire-identity checks.
func (d FieldDescriptor) Identity() (Protocol, uint16, uint32) {
	identity := d.identity()
	return identity.protocol, identity.id, identity.pen
}

// NewV9PrivateDescriptor constructs the explicit private numeric v9 form.

func NewV9PrivateDescriptor(source string, fieldType uint32, encoding DescriptorEncoding, length uint16) (FieldDescriptor, error) {
	if fieldType > math.MaxUint16 {
		return FieldDescriptor{}, ErrInvalidDescriptor
	}
	d := FieldDescriptor{
		Protocol: ProtocolV9,
		Field:    FieldInvalid,
		Source:   source,
		Custom:   true,
		ID:       uint16(fieldType),
		Private:  true,
		Length:   length,
		Encoding: encoding,
	}
	return d, d.Validate()
}

// NewIPFIXEnterpriseDescriptor constructs an explicit enterprise Field
// Specifier.  Variable fields carry the IPFIX 65535 template marker and a
// bounded maximum runtime value length.
func NewIPFIXEnterpriseDescriptor(source string, pen uint32, elementID uint32, encoding DescriptorEncoding, variable bool, length uint16, maxLength uint32) (FieldDescriptor, error) {
	if elementID > 32767 {
		return FieldDescriptor{}, ErrInvalidDescriptor
	}
	if maxLength > HardMaxMappedValueBytes {
		return FieldDescriptor{}, ErrInvalidDescriptor
	}
	d := FieldDescriptor{
		Protocol:   ProtocolIPFIX,
		Field:      FieldInvalid,
		Source:     source,
		Custom:     true,
		ID:         uint16(elementID),
		PEN:        pen,
		Enterprise: true,
		Variable:   variable,
		Length:     length,
		MaxLength:  uint16(maxLength),
		Encoding:   encoding,
	}
	return d, d.Validate()
}

// HeaderMetadata.Validate checks generic metadata before a writer can mutate
// the caller buffer.  Times remain Unix-epoch nanoseconds until the
// protocol-specific writer applies its exact wire conversion.
func (h HeaderMetadata) Validate() error {
	if h.Protocol != ProtocolV5 && h.Protocol != ProtocolV9 && h.Protocol != ProtocolIPFIX {
		return ErrInvalidHeader
	}
	if err := ValidateUnixNanos(h.ExportTimeUnixNanos); err != nil {
		return ErrInvalidHeader
	}
	if h.HasUptimeOrigin {
		if err := ValidateUnixNanos(h.UptimeOriginUnixNanos); err != nil || h.UptimeOriginUnixNanos > h.ExportTimeUnixNanos {
			return ErrInvalidHeader
		}
	}
	if h.SamplingMode > 3 || h.SamplingInterval > 16383 {
		return ErrInvalidHeader
	}
	return nil
}

// PacketRequest describes the bounded bytes a future writer will emit.  The
// request carries already-computed complete Template and Data Set/FlowSet
// lengths; no writer is permitted to infer a destination identity from a
// normalized record.
type PacketRequest struct {
	Header          HeaderMetadata
	Shape           Shape
	Records         []WireRecord
	TemplateRecords uint64
	TemplateBytes   uint64
	DataBytes       uint64
	// MaxDatagramBytes is an optional caller-selected message budget.  Zero
	// means the protocol's 16-bit pure-writer ceiling only.
	MaxDatagramBytes uint64
}

// DataSetSize is the checked encoded length of one Data FlowSet/Set.  The
// result is immutable and carries the padding count needed by a future
// protocol writer without exposing packet storage or permitting byte writes.
type DataSetSize struct {
	length  uint64
	padding uint8
}

// Length reports the complete Data FlowSet/Set length, including its set
// header and any permitted alignment padding for v9/IPFIX.
func (s DataSetSize) Length() uint64 { return s.length }

// Padding reports the number of alignment bytes included in Length.
func (s DataSetSize) Padding() uint8 { return s.padding }

// DataSetSize validates ordered records and computes the complete checked
// Data FlowSet/Set length.  It is allocation free after shape construction;
// no packet or padding bytes are written here.  NetFlow v5 has no set header
// or set padding in this contract.
func (s Shape) DataSetSize(records []WireRecord) (DataSetSize, error) {
	if err := s.Validate(); err != nil {
		return DataSetSize{}, err
	}
	return s.dataSetSize(records)
}

// RecordSize validates one record against this shape and returns its encoded
// data-record width.  It is the allocation-free sizing primitive used by
// incremental writers before they mutate a caller-owned packet.
func (s Shape) RecordSize(record WireRecord) (uint64, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}
	return s.recordSize(record)
}

// recordSize validates one record after the caller has validated the static
// shape.  Keeping this private path separate avoids repeating the quadratic
// duplicate-identity scan for every record in a slice writer.
func (s Shape) recordSize(record WireRecord) (uint64, error) {
	if err := record.Validate(); err != nil {
		return 0, err
	}
	if record.family != s.family {
		return 0, ErrInvalidFamily
	}
	if int(record.count) != len(s.fields) {
		return 0, ErrInvalidValue
	}
	return s.recordLengthFor(record)
}

// DataSetSizeForEncoded computes one checked data FlowSet/Set size from a
// cumulative record-byte total.  Callers must validate each record and add
// its RecordSize before invoking this helper.  The helper centralizes the
// padding and protocol maximum arithmetic shared by incremental writers.
func (s Shape) DataSetSizeForEncoded(recordBytes, recordCount uint64) (DataSetSize, error) {
	if err := s.Validate(); err != nil {
		return DataSetSize{}, err
	}
	limits := Limits{}.withDefaults()
	if recordCount > limits.MaxRecords {
		return DataSetSize{}, ErrBounds
	}
	if recordCount == 0 {
		if recordBytes != 0 {
			return DataSetSize{}, ErrBounds
		}
		return DataSetSize{}, nil
	}
	minimumBytes, ok := checkedMul(recordCount, s.recordLength)
	if !ok || recordBytes < minimumBytes {
		return DataSetSize{}, ErrBounds
	}
	if !s.HasVariableFields() && recordBytes != minimumBytes {
		return DataSetSize{}, ErrBounds
	}
	if s.protocol == ProtocolV5 {
		if recordBytes > limits.MaxSetBytes {
			return DataSetSize{}, ErrBounds
		}
		return DataSetSize{length: recordBytes}, nil
	}
	rawLength, ok := checkedAdd(flowSetHeaderBytes, recordBytes)
	if !ok || rawLength > limits.MaxSetBytes {
		return DataSetSize{}, ErrBounds
	}
	var padding uint64
	if remainder := rawLength & 3; remainder != 0 {
		candidate := 4 - remainder
		if candidate < s.recordLength {
			padding = candidate
		}
	}
	length, ok := checkedAdd(rawLength, padding)
	if !ok || length > limits.MaxSetBytes {
		return DataSetSize{}, ErrBounds
	}
	return DataSetSize{length: length, padding: uint8(padding)}, nil
}

// Preflight validates all contract-level lengths and caller capacity before a
// writer is allowed to mutate dst.  Any rejection returns n=0 and leaves dst
// untouched.  A successful result is the exact message byte count.
func Preflight(dst []byte, req PacketRequest) (int, error) {
	if err := req.Header.Validate(); err != nil {
		return 0, err
	}
	if err := req.Shape.Validate(); err != nil {
		return 0, err
	}
	if req.Shape.protocol != req.Header.Protocol {
		return 0, ErrInvalidShape
	}
	limits := Limits{}.withDefaults()
	recordCount := uint64(len(req.Records))
	if recordCount > limits.MaxRecords || req.TemplateRecords > limits.MaxRecords {
		return 0, ErrBounds
	}
	if req.Shape.protocol == ProtocolV5 && (recordCount == 0 || recordCount > 30) {
		return 0, ErrBounds
	}
	if req.Shape.protocol == ProtocolV5 && (req.TemplateRecords != 0 || req.TemplateBytes != 0) {
		return 0, ErrInvalidShape
	}
	if req.Shape.protocol == ProtocolV9 {
		count, ok := checkedAdd(recordCount, req.TemplateRecords)
		if !ok || uint64(req.Header.Count) != count {
			return 0, ErrInvalidHeader
		}
	}
	if req.Shape.protocol == ProtocolV5 && uint64(req.Header.Count) != recordCount {
		return 0, ErrInvalidHeader
	}
	if req.Shape.protocol == ProtocolIPFIX && req.Header.Count != 0 {
		return 0, ErrInvalidHeader
	}
	if req.TemplateBytes > limits.MaxTemplateBytes || req.TemplateBytes > limits.MaxMessageBytes {
		return 0, ErrBounds
	}
	if req.TemplateRecords == 0 && req.TemplateBytes != 0 {
		return 0, ErrInvalidShape
	}
	if req.TemplateRecords != 0 {
		expected, ok := checkedMul(req.TemplateRecords, req.Shape.templateBytes)
		if !ok || req.TemplateBytes != expected {
			return 0, ErrInvalidShape
		}
	}
	if req.TemplateBytes != 0 && req.TemplateBytes != req.Shape.templateBytes && req.TemplateRecords == 0 {
		return 0, ErrInvalidShape
	}
	dataSet, err := req.Shape.dataSetSize(req.Records)
	if err != nil {
		return 0, err
	}
	dataBytes := dataSet.Length()
	if req.DataBytes != 0 && req.DataBytes != dataBytes {
		return 0, ErrBounds
	}
	if dataBytes > limits.MaxSetBytes {
		return 0, ErrBounds
	}
	if req.Shape.protocol != ProtocolV5 && dataBytes != 0 && dataBytes < flowSetHeaderBytes {
		return 0, ErrBounds
	}
	if recordCount == 0 && dataBytes != 0 {
		return 0, ErrBounds
	}
	headerBytes := protocolHeaderLength(req.Header.Protocol)
	message, ok := checkedAdd(headerBytes, req.TemplateBytes)
	if !ok {
		return 0, ErrBounds
	}
	message, ok = checkedAdd(message, dataBytes)
	if !ok || message > limits.MaxMessageBytes || message > math.MaxUint16 {
		return 0, ErrBounds
	}
	if err := ValidatePayloadLength(message, req.MaxDatagramBytes); err != nil {
		return 0, err
	}
	if message > uint64(len(dst)) {
		return 0, ErrShortBuffer
	}
	return int(message), nil
}

// ValidatePayloadLength checks a pure writer payload against the 16-bit wire
// maximum and an optional caller budget.  Transport PMTU/UDP policy is owned by
// the destination layer and is not inferred here.
func ValidatePayloadLength(payload, budget uint64) error {
	if payload > math.MaxUint16 {
		return ErrBounds
	}
	if budget != 0 && (budget > math.MaxUint16 || payload > budget) {
		return ErrBounds
	}
	return nil
}

// MinimumDataRecordLength exposes the static minimum record width used by
// preflight calculations.
func (s Shape) MinimumDataRecordLength() uint64 { return s.recordLength }

// HasVariableFields reports whether a static shape admits a runtime-sized
// field.  Variable fields are IPFIX-only and contribute a one-byte minimum.
func (s Shape) HasVariableFields() bool {
	for _, field := range s.fields {
		if field.Variable {
			return true
		}
	}
	return false
}

func (s Shape) dataSetSize(records []WireRecord) (DataSetSize, error) {
	limits := Limits{}.withDefaults()
	if uint64(len(records)) > limits.MaxRecords {
		return DataSetSize{}, ErrBounds
	}
	var recordsBytes uint64
	for _, record := range records {
		recordBytes, err := s.recordSize(record)
		if err != nil {
			return DataSetSize{}, err
		}
		var ok bool
		recordsBytes, ok = checkedAdd(recordsBytes, recordBytes)
		if !ok {
			return DataSetSize{}, ErrBounds
		}
	}
	return s.DataSetSizeForEncoded(recordsBytes, uint64(len(records)))
}

func (s Shape) recordLengthFor(record WireRecord) (uint64, error) {
	var total uint64
	for i, descriptor := range s.fields {
		value, ok := record.valueAt(i)
		if !ok {
			return 0, ErrInvalidValue
		}
		length, err := descriptor.ValueLength(value)
		if err != nil {
			return 0, err
		}
		var fits bool
		total, fits = checkedAdd(total, length)
		if !fits {
			return 0, ErrBounds
		}
	}
	return total, nil
}

// ValueLength validates a value against a descriptor and returns its encoded
// data-record width.  This is structural value validation; mapping semantics
// and source lookup belong to the mapping adapter.
func (d FieldDescriptor) ValueLength(value Value) (uint64, error) {
	if err := d.Validate(); err != nil {
		return 0, err
	}
	if err := validateValue(value); err != nil {
		return 0, err
	}
	if isAbsoluteTimeField(d.Field) && value.kind != ValueUnixNanos {
		return 0, ErrInvalidValue
	}
	if d.Constant {
		if value.kind != ValueUint || value.uintValue != 0 {
			return 0, ErrInvalidValue
		}
		return uint64(d.Length), nil
	}
	if d.Variable {
		var length int
		switch d.Encoding {
		case EncodingString:
			if value.kind != ValueString {
				return 0, ErrInvalidValue
			}
			if !utf8.ValidString(value.text) {
				return 0, ErrInvalidValue
			}
			length = len(value.text)
		case EncodingOctetArray:
			if value.kind != ValueBytes {
				return 0, ErrInvalidValue
			}
			length = value.ByteLen()
		default:
			return 0, ErrInvalidDescriptor
		}
		if length > int(d.MaxLength) {
			return 0, ErrBounds
		}
		prefix := uint64(1)
		if length >= 255 {
			prefix = 3
		}
		return checkedLength(prefix, uint64(length))
	}

	switch d.Encoding {
	case EncodingUnsigned8:
		if !unsignedFitsDescriptor(d, value, 8) {
			return 0, ErrInvalidValue
		}
	case EncodingUnsigned16:
		if !unsignedFitsDescriptor(d, value, 16) {
			return 0, ErrInvalidValue
		}
	case EncodingUnsigned32:
		if !unsignedFitsDescriptor(d, value, 32) {
			return 0, ErrInvalidValue
		}
	case EncodingUnsigned64:
		if !unsignedFitsDescriptor(d, value, 64) {
			return 0, ErrInvalidValue
		}
	case EncodingSigned8:
		if !signedFits(value, 8) {
			return 0, ErrInvalidValue
		}
	case EncodingSigned16:
		if !signedFits(value, 16) {
			return 0, ErrInvalidValue
		}
	case EncodingSigned32:
		if !signedFits(value, 32) {
			return 0, ErrInvalidValue
		}
	case EncodingSigned64:
		if !signedFits(value, 64) {
			return 0, ErrInvalidValue
		}
	case EncodingIPv4Address, EncodingIPv6Address:
		if value.kind != ValueIP {
			return 0, ErrInvalidValue
		}
		if d.Encoding == EncodingIPv4Address && !value.ip.Is4() {
			return 0, ErrInvalidValue
		}
		if d.Encoding == EncodingIPv6Address && (!value.ip.Is6() || value.ip.Is4()) {
			return 0, ErrInvalidValue
		}
	case EncodingMACAddress:
		if value.kind != ValueMAC {
			return 0, ErrInvalidValue
		}
	case EncodingString:
		if value.kind != ValueString || !utf8.ValidString(value.text) || len(value.text) != int(d.Length) {
			return 0, ErrInvalidValue
		}
	case EncodingOctetArray:
		if value.kind != ValueBytes || value.ByteLen() != int(d.Length) {
			return 0, ErrInvalidValue
		}
	case EncodingDateTimeNanoseconds:
		if !timestampFits(value) {
			return 0, ErrInvalidValue
		}
	case EncodingDateTimeMilliseconds:
		if !timestampFits(value) {
			return 0, ErrInvalidValue
		}
	case EncodingUnspecified:
		// Canonical descriptors may defer representation checks to the mapping
		// adapter; the static length remains authoritative here.
	default:
		return 0, ErrInvalidDescriptor
	}
	return uint64(d.Length), nil
}

func checkedLength(a, b uint64) (uint64, error) {
	total, ok := checkedAdd(a, b)
	if !ok || total > math.MaxUint16 {
		return 0, ErrBounds
	}
	return total, nil
}

func unsignedFits(value Value, bits uint) bool {
	var n uint64
	switch value.kind {
	case ValueUint:
		n = value.uintValue
	case ValueInt:
		if value.intValue < 0 {
			return false
		}
		n = uint64(value.intValue)
	default:
		return false
	}
	if bits == 64 {
		return true
	}
	return n < uint64(1)<<bits
}

func unsignedFitsDescriptor(d FieldDescriptor, value Value, bits uint) bool {
	if isAbsoluteTimeField(d.Field) {
		return value.kind == ValueUnixNanos && ValidateUnixNanos(value.uintValue) == nil
	}
	return unsignedFits(value, bits)
}

func signedFits(value Value, bits uint) bool {
	if value.kind != ValueInt {
		return false
	}
	if bits == 64 {
		return true
	}
	minimum := -(int64(1) << (bits - 1))
	maximum := (int64(1) << (bits - 1)) - 1
	return value.intValue >= minimum && value.intValue <= maximum
}

func timestampFits(value Value) bool {
	return value.kind == ValueUnixNanos && ValidateUnixNanos(value.uintValue) == nil
}

// ContractWriter is the narrow future writer boundary.  Implementations must
// call Preflight (or equivalent checked validation) before the first write to
// dst; on contract rejection they return (0, error) and leave dst unchanged.
type ContractWriter interface {
	Write(dst []byte, request PacketRequest) (n int, err error)
}

func protocolHeaderLength(protocol Protocol) uint64 {
	switch protocol {
	case ProtocolV5:
		return protocolV5HeaderBytes
	case ProtocolV9:
		return protocolV9HeaderBytes
	case ProtocolIPFIX:
		return protocolIPFIXHeaderBytes
	default:
		return 0
	}
}

func (s Shape) Validate() error {
	if s.protocol == ProtocolUnknown || s.family == FamilyUnknown || len(s.fields) == 0 || len(s.fields) > DefaultMaxFieldsPerShape || s.recordLength == 0 {
		return ErrInvalidShape
	}
	if s.recordLength > DefaultMaxRecordBytes || s.templateBytes > DefaultMaxTemplateBytes {
		return ErrBounds
	}
	if s.protocol == ProtocolV5 && s.family != FamilyIPv4 {
		return ErrInvalidShape
	}
	if s.protocol == ProtocolV5 && !isExactV5Shape(s.family, uint32(s.id), s.fields, s.recordLength) {
		return ErrInvalidShape
	}
	if s.protocol != ProtocolV5 && s.id < 256 {
		return ErrInvalidShape
	}
	var sum uint64
	for i, field := range s.fields {
		if err := field.Validate(); err != nil {
			return err
		}
		if field.Protocol != s.protocol {
			return ErrInvalidDescriptor
		}
		if (field.Encoding == EncodingIPv4Address && s.family != FamilyIPv4) || (field.Encoding == EncodingIPv6Address && s.family != FamilyIPv6) {
			return ErrInvalidShape
		}
		identity := field.identity()
		for j := 0; j < i; j++ {
			if s.fields[j].identity() == identity {
				return ErrDuplicateIdentity
			}
		}
		var ok bool
		sum, ok = checkedAdd(sum, uint64(field.MinimumLength()))
		if !ok {
			return ErrBounds
		}
	}
	if sum != s.recordLength {
		return ErrInvalidShape
	}
	expectedTemplate, ok := templateBytesFor(s.protocol, s.fields)
	if !ok || expectedTemplate != s.templateBytes {
		return ErrInvalidShape
	}
	return nil
}

func templateBytesFor(protocol Protocol, fields []FieldDescriptor) (uint64, bool) {
	if protocol == ProtocolV5 {
		return 0, true
	}
	// Four bytes for the Template ID and field count, plus a four-byte Set
	// header.  IPFIX enterprise specifiers append a four-byte PEN.
	total := uint64(8)
	for _, field := range fields {
		width := uint64(4)
		if protocol == ProtocolIPFIX && field.Enterprise {
			width = 8
		}
		var ok bool
		total, ok = checkedAdd(total, width)
		if !ok {
			return 0, false
		}
	}
	return total, true
}

func checkedAdd(a, b uint64) (uint64, bool) {
	if b > math.MaxUint64-a {
		return 0, false
	}
	return a + b, true
}

func checkedMul(a, b uint64) (uint64, bool) {
	if a != 0 && b > math.MaxUint64/a {
		return 0, false
	}
	return a * b, true
}

func naturalEncodingLength(enc DescriptorEncoding) uint {
	switch enc {
	case EncodingUnsigned8, EncodingSigned8:
		return 1
	case EncodingUnsigned16, EncodingSigned16:
		return 2
	case EncodingUnsigned32, EncodingSigned32:
		return 4
	case EncodingUnsigned64, EncodingSigned64:
		return 8
	case EncodingIPv4Address:
		return 4
	case EncodingIPv6Address:
		return 16
	case EncodingMACAddress:
		return 6
	case EncodingDateTimeNanoseconds:
		return 8
	case EncodingDateTimeMilliseconds:
		return 8
	default:
		return 0
	}
}

// BuiltinV5 returns the immutable one-shape Cisco fixed profile.
func BuiltinV5() Catalog { return mustBuiltin(builtinV5Spec()) }

// BuiltinV9 returns the immutable two-shape NetFlow v9 core profile.
func BuiltinV9() Catalog { return mustBuiltin(builtinV9Spec()) }

// BuiltinV9Timed returns the immutable two-shape NetFlow v9 profile with
// RFC 3954 uptime-relative first/last switched times appended to the core
// field order. The profile remains bounded by the configured uptime origin;
// callers must provide that origin when compiling and writing it.
func BuiltinV9Timed() Catalog { return mustBuiltin(builtinV9TimedSpec()) }

// BuiltinIPFIX returns the immutable two-shape IPFIX core profile.
func BuiltinIPFIX() Catalog { return mustBuiltin(builtinIPFIXSpec()) }

// BuiltinIPFIXGeneral returns the two-shape IPFIX profile with Unix epoch
// millisecond flow start/end timestamps (IANA IE 152/153).  The profile keeps
// the core field order and widths while avoiding the legacy NTP-era encoding.
func BuiltinIPFIXGeneral() Catalog { return mustBuiltin(builtinIPFIXGeneralSpec()) }

func mustBuiltin(spec CatalogSpec) Catalog {
	catalog, err := NewCatalog(spec)
	if err != nil {
		panic(err)
	}
	return catalog
}

func builtinV5Spec() CatalogSpec {
	fields := builtinV5Fields()
	return CatalogSpec{Protocol: ProtocolV5, Shapes: []ShapeSpec{{Protocol: ProtocolV5, Family: FamilyIPv4, ID: 1, Fields: fields, RecordLength: 48}}}
}

func builtinV5Fields() []FieldDescriptor {
	return builtinV5ExactFields[:]
}

var builtinV5ExactFields = [...]FieldDescriptor{
	{Protocol: ProtocolV5, Field: FieldSourceAddress, ID: 1, Length: 4, Encoding: EncodingIPv4Address},
	{Protocol: ProtocolV5, Field: FieldDestinationAddress, ID: 2, Length: 4, Encoding: EncodingIPv4Address},
	{Protocol: ProtocolV5, Field: FieldFlowNextHop, ID: 3, Length: 4, Encoding: EncodingIPv4Address},
	{Protocol: ProtocolV5, Field: FieldFlowInIf, ID: 4, Length: 2, Encoding: EncodingUnsigned16},
	{Protocol: ProtocolV5, Field: FieldFlowOutIf, ID: 5, Length: 2, Encoding: EncodingUnsigned16},
	{Protocol: ProtocolV5, Field: FieldFlowIOPackets, ID: 6, Length: 4, Encoding: EncodingUnsigned32},
	{Protocol: ProtocolV5, Field: FieldFlowIOBytes, ID: 7, Length: 4, Encoding: EncodingUnsigned32},
	{Protocol: ProtocolV5, Field: FieldFlowStart, ID: 8, Length: 4, Encoding: EncodingUnsigned32},
	{Protocol: ProtocolV5, Field: FieldFlowEnd, ID: 9, Length: 4, Encoding: EncodingUnsigned32},
	{Protocol: ProtocolV5, Field: FieldSourcePort, ID: 10, Length: 2, Encoding: EncodingUnsigned16},
	{Protocol: ProtocolV5, Field: FieldDestinationPort, ID: 11, Length: 2, Encoding: EncodingUnsigned16},
	{Protocol: ProtocolV5, Field: FieldInvalid, Constant: true, ID: 12, Length: 1, Encoding: EncodingUnsigned8},
	{Protocol: ProtocolV5, Field: FieldFlowTCPFlags, ID: 13, Length: 1, Encoding: EncodingUnsigned8},
	{Protocol: ProtocolV5, Field: FieldNetworkTransport, ID: 14, Length: 1, Encoding: EncodingUnsigned8},
	{Protocol: ProtocolV5, Field: FieldFlowIPTOS, ID: 15, Length: 1, Encoding: EncodingUnsigned8},
	{Protocol: ProtocolV5, Field: FieldFlowSrcAS, ID: 16, Length: 2, Encoding: EncodingUnsigned16},
	{Protocol: ProtocolV5, Field: FieldFlowDstAS, ID: 17, Length: 2, Encoding: EncodingUnsigned16},
	{Protocol: ProtocolV5, Field: FieldFlowSrcNet, ID: 18, Length: 1, Encoding: EncodingUnsigned8},
	{Protocol: ProtocolV5, Field: FieldFlowDstNet, ID: 19, Length: 1, Encoding: EncodingUnsigned8},
	{Protocol: ProtocolV5, Field: FieldInvalid, Constant: true, ID: 20, Length: 2, Encoding: EncodingUnsigned16},
}

func isExactV5Shape(family Family, id uint32, fields []FieldDescriptor, recordLength uint64) bool {
	if family != FamilyIPv4 || id != 1 || recordLength != 48 || len(fields) != 20 {
		return false
	}
	for i := range builtinV5ExactFields {
		if fields[i] != builtinV5ExactFields[i] {
			return false
		}
	}
	return true
}

func builtinV9Spec() CatalogSpec {
	return CatalogSpec{Protocol: ProtocolV9, IDBase: 256, Shapes: []ShapeSpec{
		{Protocol: ProtocolV9, Family: FamilyIPv4, ID: 256, TemplateBytes: 80, RecordLength: 43, Fields: v9Fields(FamilyIPv4)},
		{Protocol: ProtocolV9, Family: FamilyIPv6, ID: 257, TemplateBytes: 80, RecordLength: 67, Fields: v9Fields(FamilyIPv6)},
	}}
}

func builtinV9TimedSpec() CatalogSpec {
	return CatalogSpec{Protocol: ProtocolV9, IDBase: 256, Shapes: []ShapeSpec{
		{Protocol: ProtocolV9, Family: FamilyIPv4, ID: 256, TemplateBytes: 88, RecordLength: 51, Fields: v9TimedFields(FamilyIPv4)},
		{Protocol: ProtocolV9, Family: FamilyIPv6, ID: 257, TemplateBytes: 88, RecordLength: 75, Fields: v9TimedFields(FamilyIPv6)},
	}}
}

func v9Fields(family Family) []FieldDescriptor {
	addressSourceID, addressDestID := uint16(8), uint16(12)
	sourceMaskID, destMaskID := uint16(9), uint16(13)
	if family == FamilyIPv6 {
		addressSourceID, addressDestID = 27, 28
		sourceMaskID, destMaskID = 29, 30
	}
	lengths := []uint16{4, 4, 1, 1, 1, 2, 4, 1, 2, 2, 4, 1, 2, 4, 4, 4, 1, 1}
	if family == FamilyIPv6 {
		lengths[6], lengths[10] = 16, 16
	}
	fields := []FieldDescriptor{
		{Protocol: ProtocolV9, Field: FieldFlowIOBytes, ID: 1, Length: lengths[0], Encoding: EncodingUnsigned32},
		{Protocol: ProtocolV9, Field: FieldFlowIOPackets, ID: 2, Length: lengths[1], Encoding: EncodingUnsigned32},
		{Protocol: ProtocolV9, Field: FieldNetworkTransport, ID: 4, Length: lengths[2], Encoding: EncodingUnsigned8},
		{Protocol: ProtocolV9, Field: FieldFlowIPTOS, ID: 5, Length: lengths[3], Encoding: EncodingUnsigned8},
		{Protocol: ProtocolV9, Field: FieldFlowTCPFlags, ID: 6, Length: lengths[4], Encoding: EncodingUnsigned8},
		{Protocol: ProtocolV9, Field: FieldSourcePort, ID: 7, Length: lengths[5], Encoding: EncodingUnsigned16},
		{Protocol: ProtocolV9, Field: FieldSourceAddress, ID: addressSourceID, Length: lengths[6], Encoding: mapAddressEncoding(family)},
		{Protocol: ProtocolV9, Field: FieldFlowSrcNet, ID: sourceMaskID, Length: lengths[7], Encoding: EncodingUnsigned8},
		{Protocol: ProtocolV9, Field: FieldFlowInIf, ID: 10, Length: lengths[8], Encoding: EncodingUnsigned16},
		{Protocol: ProtocolV9, Field: FieldDestinationPort, ID: 11, Length: lengths[9], Encoding: EncodingUnsigned16},
		{Protocol: ProtocolV9, Field: FieldDestinationAddress, ID: addressDestID, Length: lengths[10], Encoding: mapAddressEncoding(family)},
		{Protocol: ProtocolV9, Field: FieldFlowDstNet, ID: destMaskID, Length: lengths[11], Encoding: EncodingUnsigned8},
		{Protocol: ProtocolV9, Field: FieldFlowOutIf, ID: 14, Length: lengths[12], Encoding: EncodingUnsigned16},
		{Protocol: ProtocolV9, Field: FieldFlowSrcAS, ID: 16, Length: lengths[13], Encoding: EncodingUnsigned32},
		{Protocol: ProtocolV9, Field: FieldFlowDstAS, ID: 17, Length: lengths[14], Encoding: EncodingUnsigned32},
		{Protocol: ProtocolV9, Field: FieldFlowSamplingRate, ID: 34, Length: lengths[15], Encoding: EncodingUnsigned32},
		{Protocol: ProtocolV9, Field: FieldFlowIPTTL, ID: 52, Length: lengths[16], Encoding: EncodingUnsigned8},
		{Protocol: ProtocolV9, Field: FieldNetworkType, ID: 60, Length: lengths[17], Encoding: EncodingUnsigned8},
	}
	return fields
}

func v9TimedFields(family Family) []FieldDescriptor {
	fields := v9Fields(family)
	return append(fields,
		FieldDescriptor{Protocol: ProtocolV9, Field: FieldFlowStart, ID: 22, Length: 4, Encoding: EncodingUnsigned32},
		FieldDescriptor{Protocol: ProtocolV9, Field: FieldFlowEnd, ID: 21, Length: 4, Encoding: EncodingUnsigned32},
	)
}

func builtinIPFIXSpec() CatalogSpec {
	return CatalogSpec{Protocol: ProtocolIPFIX, IDBase: 256, Shapes: []ShapeSpec{
		{Protocol: ProtocolIPFIX, Family: FamilyIPv4, ID: 256, TemplateBytes: 88, RecordLength: 72, Fields: ipfixFields(FamilyIPv4)},
		{Protocol: ProtocolIPFIX, Family: FamilyIPv6, ID: 257, TemplateBytes: 88, RecordLength: 96, Fields: ipfixFields(FamilyIPv6)},
	}}
}

func builtinIPFIXGeneralSpec() CatalogSpec {
	return CatalogSpec{Protocol: ProtocolIPFIX, IDBase: 256, Shapes: []ShapeSpec{
		{Protocol: ProtocolIPFIX, Family: FamilyIPv4, ID: 256, TemplateBytes: 88, RecordLength: 72, Fields: ipfixGeneralFields(FamilyIPv4)},
		{Protocol: ProtocolIPFIX, Family: FamilyIPv6, ID: 257, TemplateBytes: 88, RecordLength: 96, Fields: ipfixGeneralFields(FamilyIPv6)},
	}}
}

func ipfixFields(family Family) []FieldDescriptor {
	addressSourceID, addressDestID := uint16(8), uint16(12)
	sourceMaskID, destMaskID := uint16(9), uint16(13)
	if family == FamilyIPv6 {
		addressSourceID, addressDestID = 27, 28
		sourceMaskID, destMaskID = 29, 30
	}
	fields := []FieldDescriptor{
		{Protocol: ProtocolIPFIX, Field: FieldFlowIOBytes, ID: 1, Length: 8, Encoding: EncodingUnsigned64},
		{Protocol: ProtocolIPFIX, Field: FieldFlowIOPackets, ID: 2, Length: 8, Encoding: EncodingUnsigned64},
		{Protocol: ProtocolIPFIX, Field: FieldNetworkTransport, ID: 4, Length: 1, Encoding: EncodingUnsigned8},
		{Protocol: ProtocolIPFIX, Field: FieldFlowIPTOS, ID: 5, Length: 1, Encoding: EncodingUnsigned8},
		{Protocol: ProtocolIPFIX, Field: FieldFlowTCPFlags, ID: 6, Length: 2, Encoding: EncodingUnsigned16},
		{Protocol: ProtocolIPFIX, Field: FieldSourcePort, ID: 7, Length: 2, Encoding: EncodingUnsigned16},
		{Protocol: ProtocolIPFIX, Field: FieldSourceAddress, ID: addressSourceID, Length: uint16(addressWidth(family)), Encoding: mapAddressEncoding(family)},
		{Protocol: ProtocolIPFIX, Field: FieldFlowSrcNet, ID: sourceMaskID, Length: 1, Encoding: EncodingUnsigned8},
		{Protocol: ProtocolIPFIX, Field: FieldFlowInIf, ID: 10, Length: 4, Encoding: EncodingUnsigned32},
		{Protocol: ProtocolIPFIX, Field: FieldDestinationPort, ID: 11, Length: 2, Encoding: EncodingUnsigned16},
		{Protocol: ProtocolIPFIX, Field: FieldDestinationAddress, ID: addressDestID, Length: uint16(addressWidth(family)), Encoding: mapAddressEncoding(family)},
		{Protocol: ProtocolIPFIX, Field: FieldFlowDstNet, ID: destMaskID, Length: 1, Encoding: EncodingUnsigned8},
		{Protocol: ProtocolIPFIX, Field: FieldFlowOutIf, ID: 14, Length: 4, Encoding: EncodingUnsigned32},
		{Protocol: ProtocolIPFIX, Field: FieldFlowSrcAS, ID: 16, Length: 4, Encoding: EncodingUnsigned32},
		{Protocol: ProtocolIPFIX, Field: FieldFlowDstAS, ID: 17, Length: 4, Encoding: EncodingUnsigned32},
		{Protocol: ProtocolIPFIX, Field: FieldFlowSamplingRate, ID: 34, Length: 4, Encoding: EncodingUnsigned32},
		{Protocol: ProtocolIPFIX, Field: FieldFlowIPTTL, ID: 52, Length: 1, Encoding: EncodingUnsigned8},
		{Protocol: ProtocolIPFIX, Field: FieldNetworkType, ID: 60, Length: 1, Encoding: EncodingUnsigned8},
		{Protocol: ProtocolIPFIX, Field: FieldFlowStart, ID: 156, Length: 8, Encoding: EncodingDateTimeNanoseconds},
		{Protocol: ProtocolIPFIX, Field: FieldFlowEnd, ID: 157, Length: 8, Encoding: EncodingDateTimeNanoseconds},
	}
	return fields
}

func ipfixGeneralFields(family Family) []FieldDescriptor {
	fields := ipfixFields(family)
	fields[18] = FieldDescriptor{Protocol: ProtocolIPFIX, Field: FieldFlowStart, ID: 152, Length: 8, Encoding: EncodingDateTimeMilliseconds}
	fields[19] = FieldDescriptor{Protocol: ProtocolIPFIX, Field: FieldFlowEnd, ID: 153, Length: 8, Encoding: EncodingDateTimeMilliseconds}
	return fields
}

func mapAddressEncoding(family Family) DescriptorEncoding {
	if family == FamilyIPv6 {
		return EncodingIPv6Address
	}
	return EncodingIPv4Address
}

func addressWidth(family Family) uint64 {
	if family == FamilyIPv6 {
		return 16
	}
	return 4
}
