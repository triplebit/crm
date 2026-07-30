package catalog

import (
	"strings"
	"testing"

	"triplebit.org/portal/internal/core"
)

const validManifest = `{
  "items": [
    {
      "slug": "hotspot-basic",
      "name": "Hotspot Basic",
      "kind": "hotspot_tier",
      "price": {"amount": "15.00", "currency": "USD", "recurring": true, "interval": "month"}
    },
    {
      "slug": "hotspot-device",
      "name": "Hotspot Device",
      "kind": "device",
      "requires_shipping": true,
      "requires_imei": true,
      "inventory_tracked": true,
      "price": {"amount": "80.00", "currency": "usd"}
    },
    {
      "slug": "one-time-donation",
      "name": "One-time donation",
      "kind": "donation",
      "price": {"amount": "0.00", "currency": "usd"}
    }
  ]
}`

func TestValidManifestParses(t *testing.T) {
	t.Parallel()
	m, err := Parse(strings.NewReader(validManifest))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(m.Items) != 3 {
		t.Fatalf("parsed %d items, want 3", len(m.Items))
	}

	tier := m.Items[0]
	if tier.Price.Amount != 1500 {
		t.Errorf("amount = %d cents, want 1500: dollars must parse exactly", tier.Price.Amount)
	}
	if tier.Price.Currency != "usd" {
		t.Errorf("currency = %q, want normalised %q", tier.Price.Currency, "usd")
	}
	if tier.Price.IntervalCount != 1 {
		t.Errorf("interval count = %d, want defaulted 1", tier.Price.IntervalCount)
	}
	if tier.Program != "hotspot" || tier.Account() != core.Memberships {
		t.Errorf("hotspot tier routed to %v, want the memberships account", tier.Account())
	}
	if donation := m.Items[2]; donation.Account() != core.Donations {
		t.Errorf("donation routed to %v, want the donations account", donation.Account())
	}
}

func TestManifestProblemsAreAllReportedAtOnce(t *testing.T) {
	t.Parallel()
	_, err := Parse(strings.NewReader(`{
	  "items": [
	    {"slug": "BAD SLUG", "name": "", "kind": "mystery",
	     "price": {"amount": "1.2.3", "currency": "dollars", "recurring": true, "interval": "fortnight"}}
	  ]
	}`))
	if err == nil {
		t.Fatal("a manifest with six problems parsed")
	}
	for _, want := range []string{"slug", "name", "kind", "amount", "currency", "interval"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention the %s problem:\n%v", want, err)
		}
	}
}

func TestManifestRejections(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"duplicate slug": `{"items": [
			{"slug": "a", "name": "A", "kind": "donation", "price": {"amount": "1.00", "currency": "usd"}},
			{"slug": "a", "name": "A again", "kind": "donation", "price": {"amount": "2.00", "currency": "usd"}}]}`,
		"one-time price with interval": `{"items": [
			{"slug": "a", "name": "A", "kind": "donation", "price": {"amount": "1.00", "currency": "usd", "interval": "month"}}]}`,
		"unknown field": `{"items": [
			{"slug": "a", "name": "A", "kind": "donation", "colour": "red", "price": {"amount": "1.00", "currency": "usd"}}]}`,
		"float amount": `{"items": [
			{"slug": "a", "name": "A", "kind": "donation", "price": {"amount": 1.00, "currency": "usd"}}]}`,
		"empty manifest": `{"items": []}`,
	}
	for name, body := range cases {
		if _, err := Parse(strings.NewReader(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
