package core

import "fmt"

// StripeEnvironment names which Stripe universe a record belongs to: the
// sandbox (test keys, test money) or production (live keys, real money).
//
// This is deliberately not Environment. The process posture is
// production-or-development; the Stripe universe is sandbox-or-production,
// and every Stripe-touching table constrains its environment column to those
// two words. Conflating them let an early draft write "development" into a
// column that PostgreSQL would have refused — caught by the type instead.
//
// The zero value panics on use, like every identifier in this package.
type StripeEnvironment struct {
	name string
}

var (
	// StripeSandbox is the test universe. Keys are sk_test_/rk_test_.
	StripeSandbox = StripeEnvironment{name: "sandbox"}

	// StripeProduction is the live universe. Keys are sk_live_/rk_live_,
	// and money moved there is real.
	StripeProduction = StripeEnvironment{name: "production"}
)

// String returns the wire and database representation.
func (e StripeEnvironment) String() string {
	if e.name == "" {
		panic("core: zero StripeEnvironment used; every Stripe record must name its universe explicitly")
	}
	return e.name
}

// IsZero reports whether e is the unusable zero value.
func (e StripeEnvironment) IsZero() bool { return e.name == "" }

// IsLive reports whether this is the universe where money is real.
func (e StripeEnvironment) IsLive() bool { return e == StripeProduction }

// ParseStripeEnvironment converts a stored value into a StripeEnvironment.
func ParseStripeEnvironment(s string) (StripeEnvironment, error) {
	switch s {
	case StripeSandbox.name:
		return StripeSandbox, nil
	case StripeProduction.name:
		return StripeProduction, nil
	default:
		return StripeEnvironment{}, fmt.Errorf("core: unknown Stripe environment %q", s)
	}
}

// StripeEnvironmentFor maps the process posture onto the Stripe universe: a
// production process uses live Stripe, everything else uses the sandbox.
// There is deliberately no way to point a production process at the sandbox
// or a development process at live money.
func StripeEnvironmentFor(env Environment) StripeEnvironment {
	if env.IsProduction() {
		return StripeProduction
	}
	return StripeSandbox
}
