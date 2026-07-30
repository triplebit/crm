// Package redact makes personal data a type rather than a string, so that it
// cannot reach a log by accident.
//
// The previous implementation documented that its logs redacted "cookies,
// Stripe payload details, session values, email tokens, bank identifiers, IMEI,
// and addresses". Nothing implemented any of that. Stripe's processor-supplied
// error text was preserved verbatim, the error renderer logged raw wrapped
// errors, and the worker persisted err.Error() into a durable last_error column
// that no retention rule ever touched.
//
// Redaction by discipline fails the first time someone adds a log line in a
// hurry. So a redact.Text prints as "[redacted]" through every path the standard
// library and log/slog use — fmt verbs, String, slog attributes — and yields its
// contents only to a caller who explicitly writes .Reveal(). The default is
// safe; disclosure is a visible act you can grep for.
package redact

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

// Placeholder is what a redacted value renders as.
const Placeholder = "[redacted]"

// Text is a string that must not be logged. Its zero value is an empty,
// still-redacted string.
type Text struct {
	value string
}

// New wraps a sensitive string.
func New(value string) Text { return Text{value: value} }

// Reveal returns the underlying value. Every call is a deliberate disclosure;
// review them the way you would review a decryption.
func (t Text) Reveal() string { return t.value }

// IsEmpty reports whether there is anything to reveal, without revealing it.
func (t Text) IsEmpty() bool { return t.value == "" }

// String satisfies fmt.Stringer, covering %s, %v and string concatenation
// through fmt.
func (t Text) String() string { return Placeholder }

// Format satisfies fmt.Formatter, which String alone does not: without it,
// %q would quote the underlying value and %#v would print the struct including
// its unexported field. This closes both.
func (t Text) Format(f fmt.State, verb rune) {
	switch verb {
	case 'v', 's', 'q', 'x', 'X':
		_, _ = f.Write([]byte(Placeholder))
	default:
		_, _ = f.Write([]byte(Placeholder))
	}
}

// LogValue satisfies slog.LogValuer, so structured logging redacts too.
func (t Text) LogValue() slog.Value { return slog.StringValue(Placeholder) }

// MarshalJSON ensures a redacted value serialises as the placeholder rather
// than leaking through a JSON-encoded log line or an API response.
func (t Text) MarshalJSON() ([]byte, error) { return []byte(`"` + Placeholder + `"`), nil }

// Compile-time proof that every interface the standard library reaches for is
// implemented. If one is dropped, this stops compiling rather than starting to
// leak.
var (
	_ fmt.Stringer   = Text{}
	_ fmt.Formatter  = Text{}
	_ slog.LogValuer = Text{}
	_ json.Marshaler = Text{}
)
