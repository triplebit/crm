// Package money converts between the dollar strings a person types and the
// integer cents everything else uses.
//
// No value in this package is ever a float. A donation of $20.10 is 2010 cents;
// as a float64 it is 20.099999999999998, and rounding that back is a decision
// nobody should be making on a charitable contribution. Parsing is done
// digit-by-digit for that reason.
//
// This is the one place a browser-supplied amount becomes a number. The browser
// submits a dollar string and nothing else — never cents, never a Stripe price,
// never an account reference — and the server decides what it means.
package money

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Cents is an exact amount in the smallest currency unit.
type Cents int64

// Errors describe what a person did wrong, so a handler can show them directly.
var (
	ErrEmpty      = errors.New("enter an amount")
	ErrNotANumber = errors.New("enter an amount using digits, for example 25 or 25.00")
	ErrNegative   = errors.New("enter an amount greater than zero")
	ErrPrecision  = errors.New("enter an amount with at most two decimal places")
	ErrTooLarge   = errors.New("that amount is too large")
)

// maxCents caps a single parsed amount at ten million dollars. Stripe rejects
// far smaller amounts anyway; this exists so that no arithmetic downstream can
// be pushed near an integer boundary by a hostile input.
const maxCents = Cents(1_000_000_000)

// ParseDollars converts a human-entered dollar amount into exact cents.
//
// Accepts an optional leading "$", surrounding whitespace, thousands separators,
// and zero to two decimal places. It rejects negatives outright rather than
// normalising them, because every amount this application parses is a payment.
func ParseDollars(input string) (Cents, error) {
	s := strings.TrimSpace(input)
	s = strings.TrimPrefix(s, "$")
	s = strings.ReplaceAll(s, ",", "")
	s = strings.TrimSpace(s)

	if s == "" {
		return 0, ErrEmpty
	}
	if strings.HasPrefix(s, "-") {
		return 0, ErrNegative
	}
	if strings.HasPrefix(s, "+") {
		return 0, ErrNotANumber
	}

	whole, frac, hasFrac := strings.Cut(s, ".")
	if whole == "" && !hasFrac {
		return 0, ErrNotANumber
	}
	// Allow ".50" and "1." but not "." alone.
	if whole == "" && frac == "" {
		return 0, ErrNotANumber
	}
	if whole == "" {
		whole = "0"
	}
	if hasFrac && len(frac) > 2 {
		return 0, ErrPrecision
	}
	if !allDigits(whole) || (hasFrac && frac != "" && !allDigits(frac)) {
		return 0, ErrNotANumber
	}

	dollars, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, ErrTooLarge
	}
	if dollars > int64(maxCents)/100 {
		return 0, ErrTooLarge
	}

	// Pad so "5" means 50 cents and "05" means 5 cents.
	switch len(frac) {
	case 0:
		frac = "00"
	case 1:
		frac += "0"
	}
	cents, err := strconv.ParseInt(frac, 10, 64)
	if err != nil {
		return 0, ErrNotANumber
	}

	total := Cents(dollars*100 + cents)
	if total > maxCents {
		return 0, ErrTooLarge
	}
	return total, nil
}

// String renders cents as a plain dollar amount with two decimal places and no
// currency symbol, for example "25.00".
func (c Cents) String() string {
	sign := ""
	v := int64(c)
	if v < 0 {
		sign = "-"
		v = -v
	}
	return fmt.Sprintf("%s%d.%02d", sign, v/100, v%100)
}

// Display renders cents for a person, for example "$25.00".
func (c Cents) Display() string { return "$" + c.String() }

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
