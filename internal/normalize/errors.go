package normalize

import "errors"

// Errors intentionally carry no field names, values, addresses, endpoints,
// body text, or upstream error strings. They are stable telemetry reasons.
var (
	ErrMalformed       = errors.New("normalize: malformed pdata")
	ErrMissingRequired = errors.New("normalize: missing required field")
	ErrInvalidType     = errors.New("normalize: invalid field type")
	ErrInvalidValue    = errors.New("normalize: invalid field value")
	ErrUnsupportedBody = errors.New("normalize: unsupported body")
	ErrNoRecords       = errors.New("normalize: no records")
	ErrInvalidCallback = errors.New("normalize: invalid callback")
	ErrInvalidInput    = errors.New("normalize: invalid input")
)

// Reason returns a fixed, redacted reason for an error. It is intentionally
// independent of the dynamic error text supplied by a pdata/library caller.
func Reason(err error) string {
	switch {
	case errors.Is(err, ErrMalformed):
		return ErrMalformed.Error()
	case errors.Is(err, ErrMissingRequired):
		return ErrMissingRequired.Error()
	case errors.Is(err, ErrInvalidType):
		return ErrInvalidType.Error()
	case errors.Is(err, ErrInvalidValue):
		return ErrInvalidValue.Error()
	case errors.Is(err, ErrUnsupportedBody):
		return ErrUnsupportedBody.Error()
	case errors.Is(err, ErrNoRecords):
		return ErrNoRecords.Error()
	default:
		return ErrInvalidInput.Error()
	}
}
