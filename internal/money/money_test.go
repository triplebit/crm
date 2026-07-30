package money

import (
	"errors"
	"testing"
)

func TestParseDollarsIsExact(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in   string
		want Cents
	}{
		{"25", 2500},
		{"25.00", 2500},
		{"25.5", 2550},
		{"25.50", 2550},
		{"25.05", 2505},
		{"0.01", 1},
		{"0", 0},
		{"0.00", 0},
		{".50", 50},
		{"1.", 100},
		{"$25.00", 2500},
		{"  $1,234.56  ", 123456},
		{"1,000", 100000},
		{"007", 700},

		// The reason this package does not use floats. As a float64, 20.10 is
		// 20.099999999999998 and 0.29 is 0.28999999999999998; rounding either
		// back to cents is a decision nobody should make on a donation.
		{"20.10", 2010},
		{"0.29", 29},
		{"1.15", 115},
		{"8.20", 820},
	} {
		got, err := ParseDollars(tc.in)
		if err != nil {
			t.Errorf("ParseDollars(%q) error = %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseDollars(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseDollarsRejectsBadInput(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in   string
		want error
	}{
		{"", ErrEmpty},
		{"   ", ErrEmpty},
		{"-5", ErrNegative},
		{"-0.01", ErrNegative},
		{"+5", ErrNotANumber},
		{"abc", ErrNotANumber},
		{"1e3", ErrNotANumber},
		{"1.2.3", ErrPrecision},
		{".", ErrNotANumber},
		{"5.001", ErrPrecision},
		{"0.005", ErrPrecision},
		{"1 000", ErrNotANumber},
		{"NaN", ErrNotANumber},
		{"Infinity", ErrNotANumber},
		{"99999999999999999999", ErrTooLarge},
		{"20000000", ErrTooLarge},
	} {
		got, err := ParseDollars(tc.in)
		if err == nil {
			t.Errorf("ParseDollars(%q) = %d, want error %v", tc.in, got, tc.want)
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("ParseDollars(%q) error = %v, want %v", tc.in, err, tc.want)
		}
	}
}

// Rejection messages are shown to a person, so they must say what to do.
func TestParseErrorsReadAsInstructions(t *testing.T) {
	t.Parallel()

	for _, err := range []error{ErrEmpty, ErrNotANumber, ErrNegative, ErrPrecision, ErrTooLarge} {
		if msg := err.Error(); msg == "" || len(msg) < 10 {
			t.Errorf("error message %q is not usable in a form", msg)
		}
	}
}

func TestCentsRenderTwoDecimalPlaces(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in            Cents
		want, display string
	}{
		{0, "0.00", "$0.00"},
		{1, "0.01", "$0.01"},
		{50, "0.50", "$0.50"},
		{2500, "25.00", "$25.00"},
		{123456, "1234.56", "$1234.56"},
		{-2500, "-25.00", "$-25.00"},
	} {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("Cents(%d).String() = %q, want %q", tc.in, got, tc.want)
		}
		if got := tc.in.Display(); got != tc.display {
			t.Errorf("Cents(%d).Display() = %q, want %q", tc.in, got, tc.display)
		}
	}
}

// Anything that parses must render back to the same amount.
func TestParseAndRenderRoundTrip(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"0.00", "0.01", "1.00", "25.50", "99.99", "1234.56"} {
		cents, err := ParseDollars(in)
		if err != nil {
			t.Fatalf("ParseDollars(%q): %v", in, err)
		}
		if got := cents.String(); got != in {
			t.Errorf("round trip of %q produced %q", in, got)
		}
	}
}
