package mapping

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

type shapeBinding struct {
	descriptor wire.FieldDescriptor
	field      wire.CanonicalField
	custom     bool
	class      conversionClass
}

// Mapper is an immutable per-record adapter. Its maps, shape bindings, and
// catalog are all constructed before Compile returns; no callback or pdata is
// stored. Map calls are safe to execute concurrently.
type Mapper struct {
	schema          string
	protocol        wire.Protocol
	profile         string
	catalog         wire.Catalog
	bindings        [][]shapeBinding
	familyAgnostic  bool
	protocolNumbers map[string]uint8
	networkVersions map[string]uint8
	limits          wire.Limits
	maxDatagram     uint64
	maxMappedBytes  uint64
	inputKeyLimit   uint64
	hasOrigin       bool
	origin          uint64
	fingerprint     string
}

// CompiledMapping is the compiler result. It is a value type so callers may
// pass it to independent destinations without sharing mutable state.
type CompiledMapping struct{ mapper Mapper }

// Catalog returns the immutable wire catalog by value. ShapeAt shares the
// catalog's private immutable descriptor storage for hot lookups; Fields and
// Shapes remain defensive-copy accessors, so callers cannot mutate the mapper.
func (m CompiledMapping) Catalog() wire.Catalog       { return m.mapper.catalog }
func (m CompiledMapping) Protocol() wire.Protocol     { return m.mapper.protocol }
func (m CompiledMapping) Profile() string             { return m.mapper.profile }
func (m CompiledMapping) Schema() string              { return m.mapper.schema }
func (m CompiledMapping) ShapeCount() int             { return m.mapper.catalog.ShapeCount() }
func (m CompiledMapping) MaxDatagramSize() uint64     { return m.mapper.maxDatagram }
func (m CompiledMapping) Fingerprint() string         { return m.mapper.fingerprint }
func (m Mapper) Catalog() wire.Catalog                { return m.catalog }
func (m Mapper) Protocol() wire.Protocol              { return m.protocol }
func (m Mapper) Profile() string                      { return m.profile }
func (m Mapper) Schema() string                       { return m.schema }
func (m Mapper) Fingerprint() string                  { return m.fingerprint }
func (m Mapper) ShapeCount() int                      { return m.catalog.ShapeCount() }
func (m Mapper) ShapeAt(index int) (wire.Shape, bool) { return m.catalog.ShapeAt(index) }

// UptimeOrigin returns the compiler-validated origin used for uptime-relative
// fields. The boolean distinguishes an explicitly configured zero origin from
// an absent origin.
func (m CompiledMapping) UptimeOrigin() (uint64, bool) { return m.mapper.origin, m.mapper.hasOrigin }

func catalogFingerprint(schema, profile string, protocol wire.Protocol, catalog wire.Catalog, protocolMap map[string]uint8, networkMap map[string]uint8) string {
	h := sha256.New()
	write := func(bytes []byte) { _, _ = h.Write(bytes) }
	write([]byte("otel-netflow-mapping-catalog-v1"))
	write([]byte(schema))
	write([]byte{0})
	write([]byte(profile))
	write([]byte{0, byte(protocol)})
	for i := 0; i < catalog.ShapeCount(); i++ {
		shape, ok := catalog.ShapeAt(i)
		if !ok {
			continue
		}
		var fixed [8]byte
		binary.BigEndian.PutUint16(fixed[:2], shape.ID())
		write(fixed[:2])
		write([]byte{byte(shape.Family())})
		binary.BigEndian.PutUint64(fixed[:], shape.RecordLength())
		write(fixed[:])
		binary.BigEndian.PutUint64(fixed[:], shape.TemplateBytes())
		write(fixed[:])
		for j := 0; j < shape.FieldCount(); j++ {
			d, _ := shape.DescriptorAt(j)
			binary.BigEndian.PutUint16(fixed[:2], d.ID)
			write(fixed[:2])
			binary.BigEndian.PutUint32(fixed[:4], d.PEN)
			write(fixed[:4])
			write([]byte{byte(d.Field), byte(d.Encoding), boolByte(d.Custom), boolByte(d.Constant), boolByte(d.Variable), boolByte(d.Enterprise), boolByte(d.Private)})
			binary.BigEndian.PutUint16(fixed[:2], d.Length)
			write(fixed[:2])
			binary.BigEndian.PutUint16(fixed[:2], d.MaxLength)
			write(fixed[:2])
			write([]byte(d.Source))
			write([]byte{0})
		}
	}
	for _, token := range sortedProtocolTokens(protocolMap) {
		write([]byte(token))
		write([]byte{protocolMap[token]})
	}
	for _, token := range []string{"ipv4", "ipv6"} {
		if version, ok := networkMap[token]; ok {
			write([]byte(token))
			write([]byte{version})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func boolByte(value bool) byte {
	if value {
		return 1
	}
	return 0
}

func sortedProtocolTokens(values map[string]uint8) []string {
	// The compiler inserts protocol entries in input order into a map. A
	// deterministic sort is required for a stable configuration fingerprint.
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
