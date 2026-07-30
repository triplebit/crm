// Package safeerr carries error messages that are safe to show a person.
//
// Application services use it to distinguish a message written for the member
// or staff user ("Choose a gift or decline one, not both.") from an internal
// failure whose text must not reach a response body. The HTTP layer renders the
// former and logs the latter.
//
// This is a leaf package on purpose. The interface previously lived in the web
// layer while a service package implemented it, which pointed the dependency
// the wrong way: presentation defining a contract that business logic had to
// import.
package safeerr

import (
	"errors"
	"strings"
)

// Safe is an error carrying a message intended for a person. Implementations
// promise the message contains no internal detail.
type Safe interface {
	error
	SafeMessage() string
}

type safeError struct {
	message string
	status  int
}

func (e safeError) Error() string       { return e.message }
func (e safeError) SafeMessage() string { return e.message }

// New returns an error whose message may be shown to the user.
func New(message string) error {
	return safeError{message: message}
}

// WithStatus returns a safe error that also names the HTTP status the
// presentation layer should use. A safe refusal rendered as a 500 pollutes
// error-rate alerting and pages someone for what is actually a support case;
// carrying the status here keeps the service the author of the distinction
// without importing anything from the web layer.
func WithStatus(status int, message string) error {
	return safeError{message: message, status: status}
}

// StatusOf returns the status carried by err, or fallback when it carries
// none. Only meaningful at the presentation boundary.
func StatusOf(err error, fallback int) int {
	var carrier safeError
	if errors.As(err, &carrier) && carrier.status != 0 {
		return carrier.status
	}
	return fallback
}

// Message returns the user-facing message carried by err, or fallback when err
// carries none. Use it at the presentation boundary so an internal failure
// never has its text rendered into a response.
func Message(err error, fallback string) string {
	var safe Safe
	if errors.As(err, &safe) {
		if message := strings.TrimSpace(safe.SafeMessage()); message != "" {
			return message
		}
	}
	return fallback
}

// IsSafe reports whether err carries a user-facing message. Callers that log
// use it to pick a severity: a safe error is an expected rejection, not a fault.
func IsSafe(err error) bool {
	var safe Safe
	return errors.As(err, &safe)
}
