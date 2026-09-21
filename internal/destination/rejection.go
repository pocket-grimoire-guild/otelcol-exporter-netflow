package destination

import (
	"reflect"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/normalize"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

// RejectionReason is the closed set of source-record rejection causes. The
// zero value is deliberately other so fabricated or future values cannot
// escape the fixed vocabulary.
type RejectionReason uint8

const (
	RejectionOther RejectionReason = iota
	RejectionUnsupportedBody
	RejectionMissingField
	RejectionInvalidType
	RejectionInvalidValue
	RejectionMapMiss
	RejectionFamilyMismatch
	RejectionProtocolMismatch
	RejectionTimeInvalid
	RejectionCustomUnavailable
	RejectionCustomInvalid
	RejectionRecordTooLarge
	RejectionRecordInvalid
)

const RejectionReasonCount = 13

// RejectionCounts is the fixed histogram returned by PackResult. Its array
// representation makes snapshots value copies and prevents callers from
// retaining ledger storage.
type RejectionCounts [RejectionReasonCount]uint64

// Label returns the exact stable label for a reason. Unknown values are
// intentionally redacted to other.
func (r RejectionReason) Label() string {
	switch r {
	case RejectionUnsupportedBody:
		return "unsupported_body"
	case RejectionMissingField:
		return "missing_field"
	case RejectionInvalidType:
		return "invalid_type"
	case RejectionInvalidValue:
		return "invalid_value"
	case RejectionMapMiss:
		return "map_miss"
	case RejectionFamilyMismatch:
		return "family_mismatch"
	case RejectionProtocolMismatch:
		return "protocol_mismatch"
	case RejectionTimeInvalid:
		return "time_invalid"
	case RejectionCustomUnavailable:
		return "custom_unavailable"
	case RejectionCustomInvalid:
		return "custom_invalid"
	case RejectionRecordTooLarge:
		return "record_too_large"
	case RejectionRecordInvalid:
		return "record_invalid"
	default:
		return "other"
	}
}

// sameTrustedError compares only comparable dynamic values. In particular,
// it never invokes Error, Is, As, Unwrap, or any method on an arbitrary error.
func sameTrustedError(err, sentinel error) bool {
	if err == nil || sentinel == nil {
		return err == sentinel
	}
	typ := reflect.TypeOf(err)
	return typ.Comparable() && err == sentinel
}

func classifyNormalizeError(err error) RejectionReason {
	switch {
	case sameTrustedError(err, normalize.ErrUnsupportedBody):
		return RejectionUnsupportedBody
	case sameTrustedError(err, normalize.ErrMissingRequired):
		return RejectionMissingField
	case sameTrustedError(err, normalize.ErrInvalidType):
		return RejectionInvalidType
	case sameTrustedError(err, normalize.ErrInvalidValue):
		return RejectionInvalidValue
	case sameTrustedError(err, normalize.ErrMalformed):
		return RejectionRecordInvalid
	default:
		return RejectionOther
	}
}

func classifyMappingError(err error) RejectionReason {
	// MapWithStats returns this concrete pointer. A type assertion inspects no
	// error methods and therefore remains safe for hostile or typed-nil inputs.
	var runtimeReason mapping.RuntimeReason
	switch runtimeErr := err.(type) {
	case *mapping.RuntimeError:
		if runtimeErr == nil {
			return RejectionOther
		}
		runtimeReason = runtimeErr.Reason
	case mapping.RuntimeError:
		runtimeReason = runtimeErr.Reason
	default:
		return RejectionOther
	}
	switch runtimeReason {
	case mapping.RuntimeMissingField:
		return RejectionMissingField
	case mapping.RuntimeMapMiss:
		return RejectionMapMiss
	case mapping.RuntimeFamilyMismatch:
		return RejectionFamilyMismatch
	case mapping.RuntimeProtocolMismatch:
		return RejectionProtocolMismatch
	case mapping.RuntimeValueInvalid, mapping.RuntimeValueOverflow:
		return RejectionInvalidValue
	case mapping.RuntimeTimeInvalid:
		return RejectionTimeInvalid
	case mapping.RuntimeCustomMissing:
		return RejectionCustomUnavailable
	case mapping.RuntimeCustomInvalid:
		return RejectionCustomInvalid
	case mapping.RuntimeRecordInvalid, mapping.RuntimeCallbackInvalid:
		return RejectionRecordInvalid
	case mapping.RuntimeBudgetExceeded:
		return RejectionRecordTooLarge
	default:
		return RejectionOther
	}
}

func classifyWireError(err error) RejectionReason {
	switch {
	case sameTrustedError(err, wire.ErrInvalidFamily):
		return RejectionFamilyMismatch
	case sameTrustedError(err, wire.ErrRecordValueLimit):
		return RejectionRecordTooLarge
	case sameTrustedError(err, wire.ErrInvalidValue):
		return RejectionRecordInvalid
	case sameTrustedError(err, wire.ErrBounds),
		sameTrustedError(err, wire.ErrShortBuffer):
		return RejectionRecordTooLarge
	default:
		return RejectionOther
	}
}
