package main

import (
	"strings"
	"testing"
)

// testLayers is a miniature layer map. Using a fixture rather than the real one
// keeps these tests meaningful when packages are added to the project.
var testLayers = map[string]int{
	"internal/leaf":         0,
	"internal/core":         10,
	"internal/db":           20,
	"internal/stripepay":    20,
	"internal/repo/audit":   25,
	"internal/repo/orders":  30,
	"internal/repo/billing": 30,
	"internal/checkout":     40,
	"internal/staff":        40, // a same-layer sibling of checkout
	"internal/web/viewdata": 45,
	"web/view":              50,
	"web/view/email":        50, // a template subpackage; R4 must cover it too
	"internal/web":          60,
}

func mod(p string) string { return modulePath + "/" + p }

func newPkg(path string, imports ...string) pkg {
	full := make([]string, 0, len(imports)+1)
	for _, i := range imports {
		full = append(full, mod(i))
	}
	// A standard-library import must always be ignored.
	full = append(full, "context")
	return pkg{ImportPath: mod(path), Imports: full}
}

// assertOneProblemContaining requires exactly one violation, mentioning want.
// Used where a single rule should fire, so a second message would mean the rules
// overlap in a way that muddies the diagnostic.
func assertOneProblemContaining(t *testing.T, problems []string, want string) {
	t.Helper()
	if len(problems) != 1 {
		t.Fatalf("got %d problems %q, want exactly 1", len(problems), problems)
	}
	if !strings.Contains(problems[0], want) {
		t.Errorf("problem %q does not mention %q", problems[0], want)
	}
}

// assertProblemContaining requires at least one violation mentioning want. Used
// where more than one rule legitimately fires on the same edge.
func assertProblemContaining(t *testing.T, problems []string, want string) {
	t.Helper()
	if len(problems) == 0 {
		t.Fatalf("no problems reported; expected one mentioning %q", want)
	}
	for _, p := range problems {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Errorf("problems %q do not include one mentioning %q", problems, want)
}

func TestCleanGraphHasNoProblems(t *testing.T) {
	pkgs := []pkg{
		newPkg("internal/leaf"),
		newPkg("internal/core", "internal/leaf"),
		newPkg("internal/repo/orders", "internal/db", "internal/core", "internal/repo/audit"),
		newPkg("internal/checkout", "internal/repo/orders", "internal/core"),
		newPkg("internal/web", "internal/checkout", "internal/web/viewdata"),
		newPkg("web/view", "internal/web/viewdata"),
	}
	if problems := check(pkgs, testLayers); len(problems) != 0 {
		t.Errorf("clean graph reported problems: %q", problems)
	}
}

// The inversion that actually happened twice in the previous implementation:
// a business package importing the HTTP layer for its own return types.
func TestUpwardImportIsRejected(t *testing.T) {
	pkgs := []pkg{newPkg("internal/checkout", "internal/web")}
	assertOneProblemContaining(t, check(pkgs, testLayers), "strictly downward")
}

// Two services at the same layer must stay independent, so a future
// checkout <-> staff entanglement is a build failure rather than a discovery.
func TestSameLayerImportIsRejected(t *testing.T) {
	pkgs := []pkg{newPkg("internal/checkout", "internal/staff")}
	assertOneProblemContaining(t, check(pkgs, testLayers), "strictly downward")
}

// A repo-to-repo edge trips both R1 (same layer) and R3. Both messages are
// correct; R3's is the one that tells you what to do instead.
func TestRepositoriesMayNotImportEachOther(t *testing.T) {
	pkgs := []pkg{newPkg("internal/repo/orders", "internal/repo/billing")}
	assertProblemContaining(t, check(pkgs, testLayers), "must not import each other")
}

func TestRepositoriesMayImportAudit(t *testing.T) {
	pkgs := []pkg{newPkg("internal/repo/orders", "internal/repo/audit")}
	if problems := check(pkgs, testLayers); len(problems) != 0 {
		t.Errorf("importing repo/audit was rejected: %q", problems)
	}
}

// internal/core is below web/view, so R1 permits this edge; only R4 catches it.
// That is the point of R4: templates must not reach past viewdata even downward.
func TestTemplatesMayImportOnlyViewdata(t *testing.T) {
	pkgs := []pkg{newPkg("web/view", "internal/core")}
	assertOneProblemContaining(t, check(pkgs, testLayers), "only internal/web/viewdata")
}

// R2: the tool must fail closed. A package absent from the map is unchecked,
// which would silently disable every other rule for it.
func TestUnlistedPackageIsAnError(t *testing.T) {
	pkgs := []pkg{newPkg("internal/brandnew", "internal/core")}
	assertOneProblemContaining(t, check(pkgs, testLayers), "not listed")
}

func TestUnlistedImportTargetIsAnError(t *testing.T) {
	pkgs := []pkg{newPkg("internal/checkout", "internal/mystery")}
	assertOneProblemContaining(t, check(pkgs, testLayers), "not in the layer map")
}

// The real map must cover the real packages; otherwise R2 fires in CI rather
// than here, where the message is clearer.
func TestRealLayerMapListsTheModuleRoot(t *testing.T) {
	if _, ok := layers["internal/core"]; !ok {
		t.Error("the real layer map is missing internal/core")
	}
	for name, layer := range layers {
		if layer < 0 {
			t.Errorf("package %q has negative layer %d", name, layer)
		}
	}
}

// R4 is a prefix rule: a template subpackage must not slip out from under it
// by not being the exact string "web/view".
func TestTemplateSubpackagesAreCoveredByR4(t *testing.T) {
	pkgs := []pkg{newPkg("web/view/email", "internal/core")}
	assertOneProblemContaining(t, check(pkgs, testLayers), "only internal/web/viewdata")
}

// R5: stripe-go is a third-party import, invisible to the layer numbers, so it
// gets its own rule. Only the wrapper may import it.
func TestStripeIsReachableOnlyThroughTheWrapper(t *testing.T) {
	direct := pkg{
		ImportPath: mod("internal/checkout"),
		Imports:    []string{"github.com/stripe/stripe-go/v86", "context"},
	}
	assertOneProblemContaining(t, check([]pkg{direct}, testLayers), "only through internal/stripepay")

	wrapper := pkg{
		ImportPath: mod("internal/stripepay"),
		Imports:    []string{"github.com/stripe/stripe-go/v86", "context"},
	}
	if problems := check([]pkg{wrapper}, testLayers); len(problems) != 0 {
		t.Errorf("the wrapper itself was refused stripe-go: %q", problems)
	}

	// Test files are not an exemption: a _test.go importing stripe-go can
	// hand-build params outside the wrapper's guarantees.
	viaTest := pkg{
		ImportPath:  mod("internal/checkout"),
		TestImports: []string{"github.com/stripe/stripe-go/v86"},
	}
	assertOneProblemContaining(t, check([]pkg{viaTest}, testLayers), "only through internal/stripepay")
	viaXTest := pkg{
		ImportPath:   mod("internal/checkout"),
		XTestImports: []string{"github.com/stripe/stripe-go/v86"},
	}
	assertOneProblemContaining(t, check([]pkg{viaXTest}, testLayers), "only through internal/stripepay")
}

// A scan that cannot see the binary package, or that sees implausibly few
// packages, is a partial scan — and a partial scan that passes is the tool
// failing open.
func TestPartialScanIsRefused(t *testing.T) {
	small := []pkg{newPkg("internal/core", "internal/leaf")}
	problems := assertComplete(small)
	assertProblemContaining(t, problems, "module root")
	assertProblemContaining(t, problems, "at least")

	// The anchor alone is not enough: a subtree scan that happens to contain
	// cmd/portal still fails the package floor.
	tiny := append(small, newPkg("cmd/portal"))
	assertProblemContaining(t, assertComplete(tiny), "at least")

	full := []pkg{newPkg("cmd/portal")}
	for i := 0; i < minPackages; i++ {
		full = append(full, newPkg(string(rune('a'+i))+"pkg"))
	}
	if problems := assertComplete(full); len(problems) != 0 {
		t.Errorf("a complete scan was refused: %q", problems)
	}
}
