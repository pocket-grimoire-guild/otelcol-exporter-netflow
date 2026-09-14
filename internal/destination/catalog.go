// Package destination owns the mutable protocol state surrounding the pure
// wire writers.  Catalog is the small immutable bridge from mapping's
// compiler-owned catalog to that state; it deliberately does not assign IDs
// or rebuild shapes.
package destination

import (
	"fmt"
	"math"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

const (
	maxCatalogShapes = uint64(wire.DefaultMaxShapes)
	maxCatalogFields = uint64(wire.DefaultMaxFieldsPerShape)
	maxCatalogBytes  = uint64(wire.DefaultMaxTemplateBytes)
)

// Catalog is an immutable view of the shapes compiled by mapping.  Shape
// order and IDs are retained exactly as supplied by the compiler.  In
// particular, this type never allocates a second template catalog.
type Catalog struct {
	wire wire.Catalog
}

// NewCatalog adopts the immutable catalog from a compiled mapping after
// checking the destination-owned static limits.  The mapping compiler owns
// custom-mapping and PEN cardinality checks; wire owns descriptor arithmetic.
func NewCatalog(compiled mapping.CompiledMapping) (Catalog, error) {
	return NewCatalogFromWire(compiled.Catalog())
}

// NewCatalogFromWire is useful to internal callers that already hold a
// validated compiler catalog.  It performs the same fail-closed checks as
// NewCatalog and does not copy or renumber shapes.
func NewCatalogFromWire(c wire.Catalog) (Catalog, error) {
	if err := c.Validate(); err != nil {
		return Catalog{}, err
	}
	count := c.ShapeCount()
	if count == 0 || uint64(count) > maxCatalogShapes {
		return Catalog{}, wire.ErrBounds
	}
	for index := 0; index < count; index++ {
		shape, ok := c.ShapeAt(index)
		if !ok {
			return Catalog{}, wire.ErrInvalidCatalog
		}
		if uint64(shape.FieldCount()) > maxCatalogFields || shape.TemplateBytes() > maxCatalogBytes {
			return Catalog{}, wire.ErrBounds
		}
		if err := validateTemplateBytesBudget(c.Protocol(), shape.TemplateBytes()); err != nil {
			return Catalog{}, err
		}
		if shape.Protocol() != c.Protocol() {
			return Catalog{}, wire.ErrInvalidShape
		}
		if c.Protocol() != wire.ProtocolV5 && (shape.ID() < 256 || uint64(shape.ID()) > math.MaxUint16) {
			return Catalog{}, wire.ErrInvalidShape
		}
	}
	return Catalog{wire: c}, nil
}

// validateTemplateBytesBudget is the destination-owned template policy.  The
// wire constructor proves exact template arithmetic; this helper keeps the
// destination's 4096-byte ceiling executable even where a 64-field shape
// cannot structurally produce that exact encoded size.
func validateTemplateBytesBudget(protocol wire.Protocol, templateBytes uint64) error {
	if protocol == wire.ProtocolV5 {
		if templateBytes != 0 {
			return wire.ErrInvalidShape
		}
		return nil
	}
	if protocol != wire.ProtocolV9 && protocol != wire.ProtocolIPFIX {
		return wire.ErrInvalidShape
	}
	if templateBytes == 0 {
		return wire.ErrInvalidShape
	}
	if templateBytes > maxCatalogBytes {
		return wire.ErrBounds
	}
	return nil
}

func validateCatalogBudget(c Catalog, maxDatagram uint64) error {
	header, ok := protocolHeaderBytes(c.Protocol())
	if !ok {
		return wire.ErrInvalidShape
	}
	for index := 0; index < c.ShapeCount(); index++ {
		shape, ok := c.ShapeAt(index)
		if !ok {
			return wire.ErrInvalidCatalog
		}
		if c.Protocol() != wire.ProtocolV5 {
			templatePacket, fits := checkedDestinationAdd(header, shape.TemplateBytes())
			if !fits || templatePacket > maxDatagram {
				return wire.ErrBounds
			}
		}
		dataPacket, fits := minimumDataPacketBytes(c.Protocol(), shape.MinimumDataRecordLength())
		if !fits || dataPacket > maxDatagram {
			return wire.ErrBounds
		}
	}
	return nil
}

func protocolHeaderBytes(protocol wire.Protocol) (uint64, bool) {
	switch protocol {
	case wire.ProtocolV5:
		return 24, true
	case wire.ProtocolV9:
		return 20, true
	case wire.ProtocolIPFIX:
		return 16, true
	default:
		return 0, false
	}
}

func minimumDataPacketBytes(protocol wire.Protocol, minimumRecordLength uint64) (uint64, bool) {
	header, ok := protocolHeaderBytes(protocol)
	if !ok {
		return 0, false
	}
	if protocol == wire.ProtocolV5 {
		return checkedDestinationAdd(header, minimumRecordLength)
	}
	rawSet, ok := checkedDestinationAdd(4, minimumRecordLength)
	if !ok {
		return 0, false
	}
	total, ok := checkedDestinationAdd(header, rawSet)
	if !ok {
		return 0, false
	}
	if remainder := rawSet & 3; remainder != 0 {
		padding := uint64(4 - remainder)
		if padding < minimumRecordLength {
			total, ok = checkedDestinationAdd(total, padding)
			if !ok {
				return 0, false
			}
		}
	}
	return total, true
}

func checkedDestinationAdd(left, right uint64) (uint64, bool) {
	if left > math.MaxUint64-right {
		return 0, false
	}
	return left + right, true
}

// Protocol returns the catalog's protocol.
func (c Catalog) Protocol() wire.Protocol { return c.wire.Protocol() }

// ShapeCount returns the number of compiler-assigned shapes.
func (c Catalog) ShapeCount() int { return c.wire.ShapeCount() }

// ShapeAt returns a shape by compiler order. The wire package shares its
// private immutable descriptor storage for hot lookups; Fields and Shapes
// remain defensive-copy accessors, so callers cannot mutate this catalog.
func (c Catalog) ShapeAt(index int) (wire.Shape, bool) { return c.wire.ShapeAt(index) }

// Wire returns the immutable wire catalog value for writer-facing callers.
func (c Catalog) Wire() wire.Catalog { return c.wire }

// IDs returns the compiler-assigned template IDs in order.  It is intended
// for diagnostics and deterministic tests; no IDs are generated here.
func (c Catalog) IDs() []uint16 {
	ids := make([]uint16, c.ShapeCount())
	for i := range ids {
		shape, _ := c.ShapeAt(i)
		ids[i] = shape.ID()
	}
	return ids
}

// String is deliberately limited to protocol and cardinality; it does not
// expose endpoint-sensitive or field-source data in diagnostics.
func (c Catalog) String() string {
	return fmt.Sprintf("%s catalog (%d shapes)", c.Protocol(), c.ShapeCount())
}
