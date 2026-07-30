package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const secret = "member@example.org"

// Every path the standard library offers for turning a value into text must
// yield the placeholder. Redaction that only covers %v is redaction that leaks
// the first time someone reaches for %q or a JSON log encoder.
func TestSensitiveTextNeverRendersThroughAnyFormattingVerb(t *testing.T) {
	t.Parallel()

	value := New(secret)
	for _, format := range []string{"%v", "%s", "%q", "%x", "%X", "%#v", "%+v", "%d"} {
		got := fmt.Sprintf(format, value)
		if strings.Contains(got, secret) {
			t.Errorf("fmt.Sprintf(%q, value) = %q, which contains the secret", format, got)
		}
	}

	if got := value.String(); got != Placeholder {
		t.Errorf("String() = %q, want %q", got, Placeholder)
	}
	if got := fmt.Sprint(value); strings.Contains(got, secret) {
		t.Errorf("fmt.Sprint leaked: %q", got)
	}
	if got := fmt.Sprintf("%v", []Text{value}); strings.Contains(got, secret) {
		t.Errorf("a slice of redacted values leaked: %q", got)
	}
	if got := fmt.Sprintf("%v", struct{ Email Text }{value}); strings.Contains(got, secret) {
		t.Errorf("a struct containing a redacted value leaked: %q", got)
	}
}

func TestStructuredLoggingRedacts(t *testing.T) {
	t.Parallel()

	for name, newHandler := range map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			slog.New(newHandler(&buf)).Info("checkout failed", "email", New(secret))

			if strings.Contains(buf.String(), secret) {
				t.Errorf("%s handler leaked the secret: %s", name, buf.String())
			}
			if !strings.Contains(buf.String(), Placeholder) {
				t.Errorf("%s handler did not emit the placeholder: %s", name, buf.String())
			}
		})
	}
}

func TestJSONEncodingRedacts(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(struct {
		Email Text `json:"email"`
	}{New(secret)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Errorf("JSON encoding leaked the secret: %s", encoded)
	}
}

// Disclosure must be possible, but only deliberately: Reveal is what you grep
// for when auditing where personal data is used.
func TestRevealReturnsTheValue(t *testing.T) {
	t.Parallel()

	if got := New(secret).Reveal(); got != secret {
		t.Errorf("Reveal() = %q, want %q", got, secret)
	}
}

func TestZeroValueIsAnEmptyRedactedString(t *testing.T) {
	t.Parallel()

	var zero Text
	if !zero.IsEmpty() {
		t.Error("the zero Text does not report IsEmpty()")
	}
	if got := zero.Reveal(); got != "" {
		t.Errorf("zero Reveal() = %q, want empty", got)
	}
	if got := zero.String(); got != Placeholder {
		t.Errorf("zero String() = %q, want %q", got, Placeholder)
	}
}

func TestIsEmptyDoesNotRequireRevealing(t *testing.T) {
	t.Parallel()

	if New("x").IsEmpty() {
		t.Error("a non-empty value reported IsEmpty()")
	}
	if !New("").IsEmpty() {
		t.Error("an empty value did not report IsEmpty()")
	}
}
