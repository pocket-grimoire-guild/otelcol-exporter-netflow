package wire

// DataPacketRequest selects one static data shape and the caller-owned
// capacity limits for an incremental packet.  Templates are deliberately not
// part of this request; destination state emits them through ContractWriter.
type DataPacketRequest struct {
	Header           HeaderMetadata
	Shape            Shape
	MaxDatagramBytes uint64
	MaxRecords       uint64
}

// DataPacketAppender incrementally encodes one data packet into one caller
// owned datagram.  Begin, Append, and Finish are allocation-free after the
// protocol writer's setup factory has returned.  The caller must serialize
// operations on one appender and keep the destination buffer and input record
// values valid for the synchronous call; the appender retains neither record
// nor value views.
type DataPacketAppender interface {
	// Begin validates the request before touching either buffer or appender
	// state.  A rejected Begin preserves the active packet and both buffers.  A
	// successful Begin atomically discards any unfinished packet and starts the
	// selected request in dst.
	Begin(dst []byte, request DataPacketRequest) error
	// Append validates and encodes one record atomically.  A rejected Append
	// leaves the buffer and active packet unchanged.  Append is invalid before
	// Begin and after Finish.
	Append(record WireRecord) error
	// Finish finalizes counts, lengths, and padding atomically.  It rejects an
	// empty, unbegun, or already finished packet without changing state.
	Finish() (int, error)
	// Reset releases the active caller buffer and invalidates the packet. It is
	// allocation-free and required after every terminal destination operation.
	Reset()
}

// StreamingWriter is the optional setup surface implemented by protocol
// writers that can create reusable data appenders.
type StreamingWriter interface {
	NewDataPacket() DataPacketAppender
}

const (
	ErrPacketNotBegun ContractError = "wire: data packet not begun"
	ErrPacketFinished ContractError = "wire: data packet already finished"
	ErrPacketEmpty    ContractError = "wire: data packet has no records"
)

// Validate checks the common lifecycle-independent portion of a streaming
// request and returns its effective record cap.  Protocol writers add their
// protocol-specific header and shape gates before mutating the destination.
func (r DataPacketRequest) Validate() (uint64, error) {
	if err := r.Header.Validate(); err != nil {
		return 0, err
	}
	if err := r.Shape.Validate(); err != nil {
		return 0, err
	}
	if r.Shape.protocol != r.Header.Protocol {
		return 0, ErrInvalidShape
	}
	if r.Header.Count != 0 {
		return 0, ErrInvalidHeader
	}
	if err := ValidatePayloadLength(0, r.MaxDatagramBytes); err != nil {
		return 0, err
	}
	limit := uint64(DefaultMaxRecords)
	if r.Shape.protocol == ProtocolV5 {
		limit = 30
	}
	if r.MaxRecords != 0 {
		if r.MaxRecords > limit {
			return 0, ErrBounds
		}
		limit = r.MaxRecords
	}
	return limit, nil
}
