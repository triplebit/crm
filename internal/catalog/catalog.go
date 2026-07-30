// Package catalog defines the price manifest: the operator-authored,
// repository-committed source of truth for what the portal sells and at what
// price.
//
// The browser never submits an amount, only a slug; the server resolves the
// price from the local catalog, which catalog-sync loads from this manifest.
// Stripe holds a projection of the manifest, never the other way round — if
// the two disagree, the manifest wins and sync reconciles Stripe toward it.
//
// The format is JSON via the standard library. Amounts are dollar strings
// parsed by internal/money into integer cents; no float is ever constructed.
package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/money"
)

// slugPattern and currencyPattern mirror the catalog_items and
// catalog_price_versions CHECK constraints exactly, so a manifest that parses
// is a manifest the database will accept.
var (
	slugPattern     = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	currencyPattern = regexp.MustCompile(`^[a-z]{3}$`)
)

// kinds maps each item kind to the program it belongs to. It mirrors the
// schema's enums; an unknown kind or a kind/program mismatch is a manifest
// error, caught before anything reaches the database or Stripe.
var kinds = map[string]string{
	"hotspot_tier": "hotspot",
	"friends_tier": "friends",
	"device":       "hotspot",
	"gift":         "hotspot",
	"shipping":     "hotspot",
	"donation":     "donation",
}

// programAccounts routes each program to the Stripe account that owns its
// money. Membership revenue and charitable donations are deliberately
// separate accounts; this map is the single place the routing is written.
var programAccounts = map[string]core.AccountRef{
	"hotspot":  core.Memberships,
	"friends":  core.Donations,
	"donation": core.Donations,
}

// Manifest is the parsed, validated catalog.
type Manifest struct {
	Items []Item
}

// Item is one sellable thing and its single current price.
type Item struct {
	Slug             string
	Name             string
	Kind             string
	Program          string
	RequiresShipping bool
	RequiresIMEI     bool

	Price PriceSpec
}

// PriceSpec is the price the manifest asserts for an item.
type PriceSpec struct {
	Amount   money.Cents
	Currency string

	Recurring     bool
	Interval      string
	IntervalCount int64
}

// Account returns the Stripe account that owns this item's money.
func (i Item) Account() core.AccountRef { return programAccounts[i.Program] }

// manifestJSON is the wire format. Amounts arrive as dollar strings.
type manifestJSON struct {
	Items []struct {
		Slug             string `json:"slug"`
		Name             string `json:"name"`
		Kind             string `json:"kind"`
		RequiresShipping bool   `json:"requires_shipping"`
		RequiresIMEI     bool   `json:"requires_imei"`
		Price            struct {
			Amount        string `json:"amount"`
			Currency      string `json:"currency"`
			Recurring     bool   `json:"recurring"`
			Interval      string `json:"interval"`
			IntervalCount int64  `json:"interval_count"`
		} `json:"price"`
	} `json:"items"`
}

// Parse reads and validates a manifest. Like the config loader it reports
// every problem at once: an operator editing prices should not discover
// mistakes one run at a time.
func Parse(r io.Reader) (Manifest, error) {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	var raw manifestJSON
	if err := decoder.Decode(&raw); err != nil {
		return Manifest{}, fmt.Errorf("catalog: manifest is not valid JSON: %w", err)
	}
	// One document, then EOF. A second JSON value after the manifest would
	// otherwise be silently ignored — which for a price file means half of
	// somebody's edit taking effect.
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return Manifest{}, errors.New("catalog: trailing content after the manifest; one JSON document only")
	}

	var problems []string
	fail := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	m := Manifest{Items: make([]Item, 0, len(raw.Items))}
	seen := make(map[string]bool, len(raw.Items))
	for _, entry := range raw.Items {
		where := entry.Slug
		if where == "" {
			where = "(item with no slug)"
		}

		if !slugPattern.MatchString(entry.Slug) {
			fail("%s: slug must be lowercase words separated by hyphens", where)
		}
		if seen[entry.Slug] {
			fail("%s: duplicate slug", where)
		}
		seen[entry.Slug] = true
		if strings.TrimSpace(entry.Name) == "" {
			fail("%s: a name is required", where)
		}
		program, known := kinds[entry.Kind]
		if !known {
			fail("%s: unknown kind %q", where, entry.Kind)
		}

		amount, err := money.ParseDollars(entry.Price.Amount)
		if err != nil {
			fail("%s: amount %q: %v", where, entry.Price.Amount, err)
		}
		currency := strings.ToLower(strings.TrimSpace(entry.Price.Currency))
		if !currencyPattern.MatchString(currency) {
			fail("%s: currency must be a three-letter code, got %q", where, entry.Price.Currency)
		}
		if entry.Price.Recurring {
			switch entry.Price.Interval {
			case "day", "week", "month", "year":
			default:
				fail("%s: recurring interval must be day, week, month or year, got %q", where, entry.Price.Interval)
			}
			if entry.Price.IntervalCount < 0 {
				fail("%s: interval count cannot be negative", where)
			}
		} else if entry.Price.Interval != "" || entry.Price.IntervalCount != 0 {
			fail("%s: a one-time price must not carry an interval", where)
		}

		count := entry.Price.IntervalCount
		if entry.Price.Recurring && count == 0 {
			count = 1
		}
		m.Items = append(m.Items, Item{
			Slug:             entry.Slug,
			Name:             strings.TrimSpace(entry.Name),
			Kind:             entry.Kind,
			Program:          program,
			RequiresShipping: entry.RequiresShipping,
			RequiresIMEI:     entry.RequiresIMEI,
			Price: PriceSpec{
				Amount:        amount,
				Currency:      currency,
				Recurring:     entry.Price.Recurring,
				Interval:      entry.Price.Interval,
				IntervalCount: count,
			},
		})
	}
	if len(m.Items) == 0 && len(problems) == 0 {
		problems = append(problems, "the manifest lists no items")
	}
	if len(problems) > 0 {
		return Manifest{}, fmt.Errorf("catalog: manifest is not valid:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return m, nil
}
