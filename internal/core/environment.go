package core

import "fmt"

// Environment is the deployment posture. It scopes every Stripe identifier in
// the database, so a sandbox object can never be mistaken for a live one.
//
// The zero value is invalid and panics if used, for the same reason as
// AccountRef: a forgotten field must fail in a test, not pick a posture.
type Environment struct {
	name string
}

var (
	// Production is the live posture: real money, HTTPS required, HSTS on,
	// strict keys, no relaxations of any kind.
	Production = Environment{name: "production"}

	// Development is a local-only posture. It relaxes transport requirements
	// (http://localhost is allowed, so cookies are not Secure-only) and nothing
	// else. It grants no authentication shortcut: there is no demo mode in this
	// codebase, because the previous implementation's demo mode was a complete
	// authentication bypass that defaulted to ON.
	Development = Environment{name: "development"}
)

// String returns the wire and database representation of the environment.
func (e Environment) String() string {
	if e.name == "" {
		panic("core: zero Environment used; the deployment posture must be explicit")
	}
	return e.name
}

// IsZero reports whether e is the unusable zero value.
func (e Environment) IsZero() bool { return e.name == "" }

// IsProduction reports whether the strict posture applies. Every security gate
// keyed on the environment must be written so that Production is the strict
// branch, and so that an unrecognised value could never reach this method.
func (e Environment) IsProduction() bool { return e == Production }

// ParseEnvironment converts a configured value into an Environment.
//
// An empty value means Production. This is the single most important default in
// the codebase and it is deliberately located here, in the only constructor, so
// that no caller can re-derive it differently.
//
// The previous implementation defaulted the other way — absent PORTAL_ENV meant
// development, which in turn meant an authentication bypass, all-zero
// encryption keys, non-Secure cookies and no HSTS, with no error. An operator
// who forgot one environment variable got an insecure deployment silently. Here,
// forgetting it costs you a startup error about a missing key, never a
// downgraded posture.
func ParseEnvironment(s string) (Environment, error) {
	switch s {
	case "", Production.name:
		return Production, nil
	case Development.name:
		return Development, nil
	default:
		return Environment{}, fmt.Errorf(
			"core: unknown environment %q (want %q or %q; empty means %q)",
			s, Production.name, Development.name, Production.name)
	}
}
