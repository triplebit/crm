// Command layercheck fails the build when the package dependency graph violates
// the portal's layering.
//
// It exists because the previous implementation accumulated three real layering
// inversions that nothing detected: internal/dashboard imported the HTTP layer
// and returned webapp.DashboardSnapshot from a pure SQL reader; internal/
// paymentflow, the core payment service, imported the HTTP layer and returned
// webapp.HostedAction; and internal/store, the persistence layer, imported an
// SMTP delivery package. Each compiled fine. Each was found by reading 40,000
// lines, which is not a control.
//
// Rules enforced:
//
//	R1  Every internal import must target a strictly lower layer.
//	R2  A package not listed in the layer map is an error. New packages are
//	    unchecked otherwise, which would make this tool fail open.
//	R3  No internal/repo/X may import internal/repo/Y. Cross-aggregate work is
//	    composed in a service, inside one transaction. repo/audit is the single
//	    exception: one append-only table, no reads.
//	R4  web/view may import only internal/web/viewdata, so templates cannot
//	    reach a service, a repository or the Stripe client.
//
// Usage: go run ./internal/tools/layercheck
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

const modulePath = "triplebit.org/portal"

// layers maps each internal package to its layer number. Imports must go
// strictly downward: a package may import a lower number, never an equal or
// higher one. Equal layers are refused too, so siblings stay independent and the
// graph cannot grow a cycle later. That strictness has already earned its keep —
// it forced repo/audit and web/viewdata to be given explicit positions below
// their peers rather than being waved through as "same layer, close enough".
//
// Numbers are spaced by ten so a package can be inserted between two existing
// layers without renumbering the file.
//
// Adding a package means adding it here. That is deliberate — see R2.
var layers = map[string]int{
	// L0 — leaves. Zero internal imports. Each is small, single-purpose and
	// independently testable.
	"internal/safeerr": 0, // human-facing vs internal error text
	"internal/cryptox": 0, // AES-256-GCM keyring + record/field-bound PII AAD
	"internal/httpx":   0, // middleware, security headers, XFF, rate limiting
	"internal/csrf":    0, // HMAC token, constant-time compare
	"internal/cookie":  0, // the only Set-Cookie writer; exposes no Path field
	"internal/tokens":  0, // opaque 32-byte token + SHA-256 digest
	"internal/money":   0, // exact cents parsing; no float ever
	"internal/redact":  0, // sensitive text as a type, not a string
	"migrations":       0, // embedded SQL + checksum ledger + Verify()

	// L10 — the shared value vocabulary and the price allowlist.
	"internal/core":    10,
	"internal/catalog": 10, // imports core only; never the Stripe client

	// L20 — outbound seams.
	"internal/stripepay": 20, // stripe-go wrapper; AccountRef-first API
	"internal/db":        20, // Conn, Pool, WithTx, constraint errors

	// L25 — the one repository that sits below the others: a single append-only
	// table with no reads, which every other repository may write to.
	"internal/repo/audit": 25,

	// L30 — one repository per aggregate. See R3: these are mutually independent.
	"internal/repo/accounts":  30,
	"internal/repo/catalogdb": 30,
	"internal/repo/orders":    30,
	"internal/repo/billing":   30,
	"internal/repo/customers": 30,
	"internal/repo/inbox":     30,
	"internal/repo/fulfil":    30,
	"internal/repo/jobq":      30,

	// L40 — services. Each owns its own input and output types, so no package
	// here ever needs to know the HTTP layer exists.
	"internal/auth":       40,
	"internal/checkout":   40,
	"internal/stripesync": 40,
	"internal/staff":      40,
	"internal/member":     40,
	"internal/privacy":    40,

	// L45–L60 — presentation, ordered so data flows one way: handlers build
	// viewdata, templates render it. Templates cannot reach back up.
	"internal/web/viewdata": 45, // plain structs, pre-formatted strings
	"web/view":              50, // templ components; see R4
	"internal/web":          60, // router, middleware, handlers

	// L70+ — composition roots and process configuration.
	"internal/config":           70,
	"internal/testdb":           70, // test helper
	"internal/tools/layercheck": 70,
	"cmd/portal":                80,
}

// repoAuditPkg is the one repository other repositories may import.
const repoAuditPkg = "internal/repo/audit"

type pkg struct {
	ImportPath   string
	Imports      []string
	TestImports  []string
	XTestImports []string
}

func main() {
	pkgs, err := listPackages()
	if err != nil {
		fmt.Fprintf(os.Stderr, "layercheck: %v\n", err)
		os.Exit(1)
	}

	problems := check(pkgs, layers)
	if len(problems) > 0 {
		sort.Strings(problems)
		fmt.Fprintf(os.Stderr, "layercheck: %d layering violation(s)\n\n", len(problems))
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "  - %s\n", p)
		}
		fmt.Fprintln(os.Stderr)
		os.Exit(1)
	}

	fmt.Printf("layercheck: %d packages, layering clean\n", len(pkgs))
}

// check returns one message per violation, or nil when the graph is clean. It is
// separated from main so the rules themselves are unit-testable: an enforcement
// tool that has never been observed to fail is not known to work.
func check(pkgs []pkg, layers map[string]int) []string {
	var problems []string
	for _, p := range pkgs {
		local := trimModule(p.ImportPath)
		if local == "" {
			continue
		}
		from, known := layers[local]
		if !known {
			problems = append(problems, fmt.Sprintf(
				"%s is not listed in layercheck's layer map. Add it, choosing the lowest layer that works: an unlisted package would be silently unchecked.",
				local))
			continue
		}

		// Test files may import upward (a repository test may use internal/testdb),
		// so only non-test imports are checked for layering.
		for _, imp := range p.Imports {
			to := trimModule(imp)
			if to == "" {
				continue
			}
			toLayer, ok := layers[to]
			if !ok {
				problems = append(problems, fmt.Sprintf(
					"%s imports %s, which is not in the layer map", local, to))
				continue
			}

			// R1: strictly downward.
			if toLayer >= from {
				problems = append(problems, fmt.Sprintf(
					"%s (L%d) imports %s (L%d): imports must go strictly downward",
					local, from, to, toLayer))
			}

			// R3: repositories are independent of each other.
			if isRepo(local) && isRepo(to) && to != repoAuditPkg {
				problems = append(problems, fmt.Sprintf(
					"%s imports %s: repositories must not import each other. Compose them in a service inside one db.WithTx.",
					local, to))
			}

			// R4: templates see formatted data and nothing else.
			if local == "web/view" && to != "internal/web/viewdata" {
				problems = append(problems, fmt.Sprintf(
					"web/view imports %s: templates may import only internal/web/viewdata", to))
			}
		}
	}

	return problems
}

func listPackages() ([]pkg, error) {
	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %w", err)
	}

	var pkgs []pkg
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for {
		var p pkg
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// trimModule converts a full import path into a repo-relative package path,
// returning "" for anything outside this module (stdlib and dependencies).
func trimModule(importPath string) string {
	if importPath == modulePath {
		return "."
	}
	if !strings.HasPrefix(importPath, modulePath+"/") {
		return ""
	}
	return strings.TrimPrefix(importPath, modulePath+"/")
}

func isRepo(local string) bool { return strings.HasPrefix(local, "internal/repo/") }
