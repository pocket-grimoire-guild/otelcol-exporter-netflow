package mapping

import (
	"errors"
	"fmt"
	"math"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

// ConfigError is a bounded compiler diagnostic. Path is always one of the
// static mapping paths below; user keys, identifiers, values, and wrapped
// library errors never enter Error.
type ConfigError struct {
	Code     ErrorCode
	Protocol wire.Protocol
	Path     string
	Ordinal  uint64
	Actual   uint64
	Limit    uint64
}

type ErrorCode uint8

const ErrorLedgerSummary = "config=13 fixed codes; runtime=12 fixed reasons; max_error_bytes=256; labels=none"

const (
	ErrCodeInvalidConfig ErrorCode = iota + 1
	ErrCodeSelector
	ErrCodeSchema
	ErrCodeProfile
	ErrCodePolicy
	ErrCodeToken
	ErrCodeProvenance
	ErrCodeUnsupported
	ErrCodeInapplicable
	ErrCodeCollision
	ErrCodeCustom
	ErrCodeBounds
	ErrCodePMTU
)

func (c ConfigError) Error() string {
	// All components are closed values or bounded counters. Keep a defensive
	// cap even if a future caller supplies an unusually long static path.
	path := c.Path
	if len(path) > 64 {
		path = path[:64]
	}
	text := fmt.Sprintf("mapping config code=%d protocol=%s path=%s ordinal=%d actual=%d limit=%d", c.Code, c.Protocol.String(), path, c.Ordinal, c.Actual, c.Limit)
	if len(text) > 256 {
		return text[:256]
	}
	return text
}

func (c ConfigError) Unwrap() error { return ErrCompile }

func newConfigError(code ErrorCode, protocol wire.Protocol, path string, ordinal, actual, limit uint64) error {
	return &ConfigError{Code: code, Protocol: protocol, Path: path, Ordinal: ordinal, Actual: actual, Limit: limit}
}

// RuntimeReason is a fixed, bounded per-record reason. Names and values are
// intentionally absent so callback data cannot become telemetry cardinality.
type RuntimeReason uint8

const (
	RuntimeMissingField RuntimeReason = iota + 1
	RuntimeMapMiss
	RuntimeFamilyMismatch
	RuntimeProtocolMismatch
	RuntimeValueInvalid
	RuntimeValueOverflow
	RuntimeTimeInvalid
	RuntimeCustomMissing
	RuntimeCustomInvalid
	RuntimeRecordInvalid
	RuntimeCallbackInvalid
	RuntimeBudgetExceeded
)

// RuntimeError exposes only the fixed reason and safe ordinal.
type RuntimeError struct {
	Reason  RuntimeReason
	Ordinal uint16
}

func (e RuntimeError) Error() string {
	return fmt.Sprintf("mapping runtime reason=%d ordinal=%d", e.Reason, e.Ordinal)
}

func (e RuntimeError) Unwrap() error { return ErrRuntime }

func (e RuntimeError) Is(target error) bool {
	switch e.Reason {
	case RuntimeMapMiss:
		return target == ErrMapMiss
	case RuntimeMissingField:
		return target == ErrMissingField
	case RuntimeCustomMissing:
		return target == ErrCustomMissing
	case RuntimeCustomInvalid:
		return target == ErrCustomInvalid
	case RuntimeCallbackInvalid:
		return target == ErrCallbackInvalid
	case RuntimeFamilyMismatch:
		return target == ErrFamilyMismatch
	case RuntimeProtocolMismatch:
		return target == ErrProtocolMismatch
	case RuntimeValueInvalid, RuntimeValueOverflow:
		return target == ErrInvalidValue
	case RuntimeTimeInvalid:
		return target == ErrTimeInvalid
	case RuntimeBudgetExceeded:
		return target == wire.ErrBounds
	default:
		return false
	}
}

func runtimeError(reason RuntimeReason, ordinal int) error {
	if ordinal < 0 {
		ordinal = 0
	}
	if ordinal > math.MaxUint16 {
		ordinal = math.MaxUint16
	}
	return &RuntimeError{Reason: reason, Ordinal: uint16(ordinal)}
}

// Fixed error sentinels are useful to callers that do not need the bounded
// diagnostic. They contain no dynamic text.
var (
	ErrCompile         = errors.New("mapping: configuration rejected")
	ErrRuntime         = errors.New("mapping: record rejected")
	ErrMapMiss         = errors.New("mapping: configured map miss")
	ErrMissingField    = errors.New("mapping: selected field missing")
	ErrCustomMissing   = errors.New("mapping: selected custom field missing")
	ErrCustomInvalid   = errors.New("mapping: selected custom value invalid")
	ErrCallbackInvalid = errors.New("mapping: lookup callback invalid")
)

// ErrorLedger returns the stable compiler/runtime error-series summary used
// by diagnostics and terminal evidence. The returned value is immutable to
// callers because strings are value types.
func ErrorLedger() string {
	return ErrorLedgerSummary
}

// Reason returns a stable redacted series string for either compiler or
// runtime failures. It deliberately ignores all dynamic error text.
func Reason(err error) string {
	if errors.Is(err, ErrCompile) {
		return "mapping: configuration rejected"
	}
	if errors.Is(err, ErrRuntime) {
		return "mapping: record rejected"
	}
	return "mapping: invalid input"
}
