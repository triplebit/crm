package core

import "testing"

func TestParseAccountRefRoundTripsKnownAccountsAndRejectsEverythingElse(t *testing.T) {
	for _, want := range AccountRefs() {
		got, err := ParseAccountRef(want.String())
		if err != nil {
			t.Fatalf("ParseAccountRef(%q) returned error: %v", want, err)
		}
		if got != want {
			t.Errorf("ParseAccountRef(%q) = %v, want %v", want, got, want)
		}
	}

	for _, bad := range []string{"", "Memberships", "memberships ", "donation", "acct_123"} {
		if _, err := ParseAccountRef(bad); err == nil {
			t.Errorf("ParseAccountRef(%q) succeeded; every value that is not exactly one of the two accounts must be rejected", bad)
		}
	}
}

func TestZeroAccountRefPanicsRatherThanAddressingADefaultAccount(t *testing.T) {
	var zero AccountRef
	if !zero.IsZero() {
		t.Fatal("zero AccountRef reports IsZero() == false")
	}
	defer func() {
		if recover() == nil {
			t.Error("zero AccountRef.String() did not panic; a forgotten account would silently address one of the two ledgers")
		}
	}()
	_ = zero.String()
}

// TestParseEnvironmentDefaultsToProduction guards the single most important
// default in the codebase. The previous implementation defaulted an absent
// PORTAL_ENV to development, which enabled an authentication bypass, all-zero
// encryption keys and non-Secure cookies without any error.
func TestParseEnvironmentDefaultsToProduction(t *testing.T) {
	got, err := ParseEnvironment("")
	if err != nil {
		t.Fatalf("ParseEnvironment(\"\") returned error: %v", err)
	}
	if got != Production {
		t.Fatalf("ParseEnvironment(\"\") = %v, want %v", got, Production)
	}
	if !got.IsProduction() {
		t.Error("the default environment does not report IsProduction()")
	}
}

func TestParseEnvironmentAcceptsOnlyTheTwoKnownPostures(t *testing.T) {
	dev, err := ParseEnvironment("development")
	if err != nil {
		t.Fatalf("ParseEnvironment(\"development\") returned error: %v", err)
	}
	if dev.IsProduction() {
		t.Error("development reports IsProduction()")
	}

	for _, bad := range []string{"Production", "prod", "staging", "test", " development"} {
		if _, err := ParseEnvironment(bad); err == nil {
			t.Errorf("ParseEnvironment(%q) succeeded; an unrecognised posture must be an error, never a silent downgrade", bad)
		}
	}
}

func TestZeroEnvironmentPanicsRatherThanPickingAPosture(t *testing.T) {
	var zero Environment
	if !zero.IsZero() {
		t.Fatal("zero Environment reports IsZero() == false")
	}
	if zero.IsProduction() {
		t.Error("zero Environment reports IsProduction(); a forgotten posture must never read as the strict one either")
	}
	defer func() {
		if recover() == nil {
			t.Error("zero Environment.String() did not panic")
		}
	}()
	_ = zero.String()
}
