// Package core holds the portal's value vocabulary: the small, pure types that
// every other layer agrees on. It imports nothing outside the standard library.
//
// Types here are deliberately opaque structs rather than named string types.
// A named string type lets any string be converted into it
// (core.AccountRef("typo")); an opaque struct does not. Since addressing the
// wrong Stripe account is one of the few mistakes in this system that moves
// money to the wrong ledger, that distinction is worth the extra constructor.
package core

import "fmt"

// AccountRef identifies one of the two Stripe accounts in the organization.
//
// The portal deliberately keeps membership revenue and charitable donations in
// separate Stripe accounts, so every financial row and every Stripe API call is
// scoped by an AccountRef. It is the required argument immediately after
// ctx on every Stripe call, so "which account?" can never be implicit.
//
// The zero value is invalid and panics if used. That is intentional: a struct
// field someone forgot to populate must fail loudly in the first test rather
// than quietly address whichever account happens to be the default. There is
// no default account anywhere in this codebase.
type AccountRef struct {
	name string
}

// The two accounts. Organization Customer Sharing gives both the same Customer
// identifiers and eligible saved cards; everything else — subscriptions,
// invoices, Checkout Sessions, Portal configurations, Products, Prices — is
// account-specific.
var (
	// Memberships owns hotspot subscriptions and initial device/SIM charges.
	Memberships = AccountRef{name: "memberships"}

	// Donations owns one-time donations and Friends subscriptions.
	Donations = AccountRef{name: "donations"}
)

// String returns the wire and database representation of the account.
//
// It panics on the zero AccountRef. Callers that legitimately need to test for
// the zero value must use IsZero.
func (a AccountRef) String() string {
	if a.name == "" {
		panic("core: zero AccountRef used; every Stripe call and financial row must name its account explicitly")
	}
	return a.name
}

// IsZero reports whether a is the unusable zero value.
func (a AccountRef) IsZero() bool { return a.name == "" }

// ParseAccountRef converts a stored or configured value into an AccountRef.
// It is the only way to build one from a string, and it rejects everything that
// is not exactly one of the two known accounts.
func ParseAccountRef(s string) (AccountRef, error) {
	switch s {
	case Memberships.name:
		return Memberships, nil
	case Donations.name:
		return Donations, nil
	default:
		return AccountRef{}, fmt.Errorf("core: unknown Stripe account reference %q", s)
	}
}

// AccountRefs returns both accounts, in a stable order, for callers that must
// act on each one (readiness checks, per-account sweeps).
func AccountRefs() []AccountRef { return []AccountRef{Memberships, Donations} }
