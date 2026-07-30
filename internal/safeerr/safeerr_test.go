package safeerr

import (
	"errors"
	"fmt"
	"testing"
)

func TestNewCarriesMessage(t *testing.T) {
	err := New("Choose a gift or decline one, not both.")
	if err.Error() != "Choose a gift or decline one, not both." {
		t.Errorf("Error() = %q", err.Error())
	}
	if !IsSafe(err) {
		t.Error("IsSafe(New(...)) = false, want true")
	}
	if got := Message(err, "fallback"); got != "Choose a gift or decline one, not both." {
		t.Errorf("Message() = %q", got)
	}
}

func TestMessageFallsBackForInternalErrors(t *testing.T) {
	internal := errors.New("pq: connection reset by peer")
	if got := Message(internal, "Please try again."); got != "Please try again." {
		t.Errorf("Message(internal) = %q, want the fallback", got)
	}
	if IsSafe(internal) {
		t.Error("IsSafe(internal error) = true, want false")
	}
	if got := Message(nil, "Please try again."); got != "Please try again." {
		t.Errorf("Message(nil) = %q, want the fallback", got)
	}
}

// TestMessageUnwrapsWrappedErrors matters because services wrap safe errors on
// the way out; the message must still be recoverable at the HTTP boundary.
func TestMessageUnwrapsWrappedErrors(t *testing.T) {
	wrapped := fmt.Errorf("start hotspot checkout: %w", New("Choose a valid catalog option."))
	if !IsSafe(wrapped) {
		t.Error("IsSafe(wrapped) = false, want true")
	}
	if got := Message(wrapped, "fallback"); got != "Choose a valid catalog option." {
		t.Errorf("Message(wrapped) = %q", got)
	}
}

// TestMessageIgnoresBlankSafeMessages preserves the behavior of the replaced
// webapp helper: a safe error carrying only whitespace yields the fallback
// rather than an empty page heading.
func TestMessageIgnoresBlankSafeMessages(t *testing.T) {
	for _, blank := range []string{"", "   ", "\t\n"} {
		if got := Message(New(blank), "fallback"); got != "fallback" {
			t.Errorf("Message(New(%q)) = %q, want the fallback", blank, got)
		}
	}
}

// TestSafeErrorSatisfiesErrorsIs confirms a safe error still behaves like an
// ordinary error for identity comparisons, so callers can keep using errors.Is
// against sentinels they wrap it with.
func TestSafeErrorSatisfiesErrorsIs(t *testing.T) {
	sentinel := errors.New("catalog unavailable")
	wrapped := fmt.Errorf("%w: %w", sentinel, New("Try again shortly."))
	if !errors.Is(wrapped, sentinel) {
		t.Error("errors.Is(wrapped, sentinel) = false, want true")
	}
	if got := Message(wrapped, "fallback"); got != "Try again shortly." {
		t.Errorf("Message(wrapped) = %q", got)
	}
}
