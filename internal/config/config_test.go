package config

import (
	"encoding/base64"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func key(b byte) string {
	raw := make([]byte, keySize)
	for i := range raw {
		raw[i] = b
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// setEnv applies a complete, valid environment, then the overrides. A value of
// "" unsets the variable, which is how the "operator forgot this" cases are
// expressed.
func setEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	base := map[string]string{
		"PORTAL_ENV":                      "production",
		"PORTAL_BASE_URL":                 "https://members.example.org",
		"PORTAL_DATABASE_URL":             "postgres://portal@localhost/portal",
		"PORTAL_ENCRYPTION_KEY_ID":        "pii-v1",
		"PORTAL_ENCRYPTION_KEY":           key(1),
		"PORTAL_SESSION_KEY_ID":           "session-v1",
		"PORTAL_SESSION_KEY":              key(2),
		"PORTAL_OIDC_ISSUER":              "https://id.example.org",
		"PORTAL_OIDC_CLIENT_ID":           "portal",
		"PORTAL_OIDC_CLIENT_SECRET":       "secret",
		"PORTAL_OIDC_REDIRECT_URL":        "https://members.example.org/auth/callback",
		"PORTAL_LISTEN_ADDR":              "",
		"PORTAL_SESSION_IDLE_TTL":         "",
		"PORTAL_SESSION_ABSOLUTE_TTL":     "",
		"PORTAL_TRUST_PROXY":              "",
		"PORTAL_TRUSTED_PROXY_CIDRS":      "",
		"PORTAL_ENCRYPTION_PREVIOUS_KEYS": "",
		"PORTAL_SESSION_PREVIOUS_KEYS":    "",
		"PORTAL_BRAND_NAME":               "",
		"PORTAL_BRAND_TAGLINE":            "",
	}
	for name, value := range overrides {
		base[name] = value
	}
	for name, value := range base {
		if value == "" {
			t.Setenv(name, "")
		} else {
			t.Setenv(name, value)
		}
	}
}

func loadServe(t *testing.T, overrides map[string]string) (*Config, error) {
	t.Helper()
	setEnv(t, overrides)
	cfg, err := Load()
	if err != nil {
		return cfg, err
	}
	return cfg, cfg.RequireServe()
}

func TestCompleteConfigurationLoads(t *testing.T) {
	cfg, err := loadServe(t, nil)
	if err != nil {
		t.Fatalf("a complete configuration was rejected: %v", err)
	}
	if !cfg.Environment.IsProduction() {
		t.Error("environment is not production")
	}
	if cfg.ListenAddr != defaultListenAddr {
		t.Errorf("ListenAddr = %q, want the default %q", cfg.ListenAddr, defaultListenAddr)
	}
	if cfg.SessionIdleTTL != defaultIdleTTL || cfg.SessionAbsoluteTTL != defaultAbsoluteTTL {
		t.Errorf("session TTLs = %v/%v, want the defaults %v/%v",
			cfg.SessionIdleTTL, cfg.SessionAbsoluteTTL, defaultIdleTTL, defaultAbsoluteTTL)
	}
}

// The single most important behaviour in this package. The previous
// implementation defaulted an absent PORTAL_ENV to development, which enabled an
// authentication bypass, all-zero encryption keys, non-Secure cookies and no
// HSTS, without an error anywhere.
func TestAbsentEnvironmentMeansProduction(t *testing.T) {
	cfg, err := loadServe(t, map[string]string{"PORTAL_ENV": ""})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Environment.IsProduction() {
		t.Fatal("an absent PORTAL_ENV did not mean production")
	}
}

func TestUnknownEnvironmentIsRejected(t *testing.T) {
	setEnv(t, map[string]string{"PORTAL_ENV": "staging"})
	if _, err := Load(); err == nil {
		t.Fatal("an unrecognised PORTAL_ENV was accepted")
	}
}

// A missing key must stop the process, never become a usable zero key.
func TestMissingKeysAreRefusedRatherThanDefaulted(t *testing.T) {
	for _, name := range []string{
		"PORTAL_ENCRYPTION_KEY", "PORTAL_ENCRYPTION_KEY_ID",
		"PORTAL_SESSION_KEY", "PORTAL_SESSION_KEY_ID",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := loadServe(t, map[string]string{name: ""})
			if err == nil {
				t.Fatalf("serving was allowed with %s unset", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error %q does not name %s", err, name)
			}
			if cfg != nil && name == "PORTAL_ENCRYPTION_KEY" && len(cfg.PII.Active) != 0 {
				t.Error("a missing key produced key material anyway")
			}
		})
	}
}

func TestMalformedKeysAreRejected(t *testing.T) {
	for name, value := range map[string]string{
		"not base64":      "!!!!",
		"too short":       base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"too long":        base64.StdEncoding.EncodeToString(make([]byte, 64)),
		"all zero":        base64.StdEncoding.EncodeToString(make([]byte, keySize)),
		"empty after pad": "====",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadServe(t, map[string]string{"PORTAL_ENCRYPTION_KEY": value}); err == nil {
				t.Errorf("a %s key was accepted", name)
			}
		})
	}
}

// Operators paste keys from several tools, so all four base64 spellings of the
// same 32 bytes must work.
func TestKeysAcceptEveryCommonBase64Spelling(t *testing.T) {
	raw := make([]byte, keySize)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	for name, encoded := range map[string]string{
		"standard padded":   base64.StdEncoding.EncodeToString(raw),
		"standard raw":      base64.RawStdEncoding.EncodeToString(raw),
		"url-safe padded":   base64.URLEncoding.EncodeToString(raw),
		"url-safe unpadded": base64.RawURLEncoding.EncodeToString(raw),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := loadServe(t, map[string]string{"PORTAL_ENCRYPTION_KEY": encoded})
			if err != nil {
				t.Fatalf("%s encoding was rejected: %v", name, err)
			}
			if string(cfg.PII.Active) != string(raw) {
				t.Error("the decoded key does not match")
			}
		})
	}
}

// The two rings must be independent, or recovering one key reads the other's
// data too.
func TestTheTwoKeyRingsMustNotShareMaterial(t *testing.T) {
	shared := key(9)
	if _, err := loadServe(t, map[string]string{
		"PORTAL_ENCRYPTION_KEY": shared,
		"PORTAL_SESSION_KEY":    shared,
	}); err == nil {
		t.Error("the same key was accepted for personal data and for sessions")
	}

	if _, err := loadServe(t, map[string]string{
		"PORTAL_ENCRYPTION_KEY_ID": "same-id",
		"PORTAL_SESSION_KEY_ID":    "same-id",
	}); err == nil {
		t.Error("the same key id was accepted for both rings")
	}

	// Independence must hold across previous keys too, in both directions:
	// a rotation that moves one ring's key into the other ring's history is
	// the same compromise with a delay on it.
	if _, err := loadServe(t, map[string]string{
		"PORTAL_SESSION_PREVIOUS_KEYS": "session-v0=" + key(1), // the PII active key
	}); err == nil {
		t.Error("the PII active key was accepted as a previous session key")
	}
	if _, err := loadServe(t, map[string]string{
		"PORTAL_ENCRYPTION_PREVIOUS_KEYS": "pii-v0=" + key(2), // the session active key
	}); err == nil {
		t.Error("the session active key was accepted as a previous PII key")
	}
	if _, err := loadServe(t, map[string]string{
		"PORTAL_ENCRYPTION_PREVIOUS_KEYS": "pii-v0=" + key(9),
		"PORTAL_SESSION_PREVIOUS_KEYS":    "session-v0=" + key(9),
	}); err == nil {
		t.Error("the same key was accepted in both rings' previous lists")
	}
}

func TestProductionRequiresHTTPS(t *testing.T) {
	for name, overrides := range map[string]map[string]string{
		"base URL":     {"PORTAL_BASE_URL": "http://members.example.org"},
		"OIDC issuer":  {"PORTAL_OIDC_ISSUER": "http://id.example.org"},
		"redirect URL": {"PORTAL_OIDC_REDIRECT_URL": "http://members.example.org/auth/callback"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadServe(t, overrides); err == nil {
				t.Errorf("production accepted an http %s", name)
			}
		})
	}
}

func TestDevelopmentPermitsPlainHTTP(t *testing.T) {
	if _, err := loadServe(t, map[string]string{
		"PORTAL_ENV":               "development",
		"PORTAL_BASE_URL":          "http://localhost:8080",
		"PORTAL_OIDC_ISSUER":       "http://localhost:1411",
		"PORTAL_OIDC_REDIRECT_URL": "http://localhost:8080/auth/callback",
	}); err != nil {
		t.Errorf("development rejected plain http: %v", err)
	}
}

// Trusting forwarded headers without naming who may send them would let any
// peer claim any client address.
func TestTrustProxyWithoutCIDRsIsRefused(t *testing.T) {
	if _, err := loadServe(t, map[string]string{"PORTAL_TRUST_PROXY": "true"}); err == nil {
		t.Fatal("forwarded headers were trusted with no proxy CIDRs configured")
	}
	if _, err := loadServe(t, map[string]string{
		"PORTAL_TRUST_PROXY":         "true",
		"PORTAL_TRUSTED_PROXY_CIDRS": "10.20.0.0/16",
	}); err != nil {
		t.Errorf("a correctly configured proxy was rejected: %v", err)
	}
}

func TestPreviousKeysAreParsedAndBounded(t *testing.T) {
	cfg, err := loadServe(t, map[string]string{
		"PORTAL_ENCRYPTION_PREVIOUS_KEYS": "pii-v0=" + key(5) + ",pii-vx=" + key(6),
	})
	if err != nil {
		t.Fatalf("valid previous keys were rejected: %v", err)
	}
	if len(cfg.PII.Previous) != 2 {
		t.Errorf("parsed %d previous keys, want 2", len(cfg.PII.Previous))
	}

	if _, err := loadServe(t, map[string]string{
		"PORTAL_ENCRYPTION_PREVIOUS_KEYS": "pii-v0=" + key(5) + ",pii-v0=" + key(6),
	}); err == nil {
		t.Error("a repeated previous key id was accepted")
	}

	if _, err := loadServe(t, map[string]string{
		"PORTAL_ENCRYPTION_PREVIOUS_KEYS": "pii-v1=" + key(5),
	}); err == nil {
		t.Error("the active key id was accepted as a previous key")
	}
}

func TestSessionTTLsMustBeCoherent(t *testing.T) {
	if _, err := loadServe(t, map[string]string{
		"PORTAL_SESSION_IDLE_TTL":     "24h",
		"PORTAL_SESSION_ABSOLUTE_TTL": "12h",
	}); err == nil {
		t.Error("an idle timeout longer than the absolute timeout was accepted")
	}
}

func TestEveryProblemIsReportedAtOnce(t *testing.T) {
	_, err := loadServe(t, map[string]string{
		"PORTAL_DATABASE_URL":   "",
		"PORTAL_OIDC_CLIENT_ID": "",
		"PORTAL_OIDC_ISSUER":    "",
	})
	if err == nil {
		t.Fatal("three missing values were accepted")
	}
	for _, want := range []string{"PORTAL_DATABASE_URL", "PORTAL_OIDC_CLIENT_ID", "PORTAL_OIDC_ISSUER"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s; an operator would fix these one restart at a time:\n%v", want, err)
		}
	}
}

// The worker must not require, and therefore must never be given, the secrets
// that read browser sessions or decrypt personal data. Compose scopes the
// environment, but this keeps the code side honest: a worker that never asks
// for these cannot be compromised into using them.
func TestWorkerNeedsNoBrowserOrPersonalDataSecrets(t *testing.T) {
	setEnv(t, map[string]string{
		"PORTAL_ENCRYPTION_KEY":     "",
		"PORTAL_ENCRYPTION_KEY_ID":  "",
		"PORTAL_SESSION_KEY":        "",
		"PORTAL_SESSION_KEY_ID":     "",
		"PORTAL_OIDC_CLIENT_SECRET": "",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := cfg.RequireWorker(); err != nil {
		t.Fatalf("the worker demanded secrets it has no use for: %v", err)
	}
}

// Structural companion to the test above: RequireWorker must not so much as
// mention the key rings. Reading the fields would be the first step towards
// requiring them, and the deployment's secret scoping would then break at a
// distance from this file.
func TestRequireWorkerDoesNotReferenceKeyRings(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "config.go", nil, 0)
	if err != nil {
		t.Fatalf("parse config.go: %v", err)
	}

	var body *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if ok && fn.Name.Name == "RequireWorker" {
			body = fn
			return false
		}
		return true
	})
	if body == nil {
		t.Fatal("RequireWorker was not found in config.go")
	}

	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "PII", "Session":
			t.Errorf("RequireWorker references c.%s: the worker must never need the "+
				"personal-data or session keys, so that its container is never given them",
				sel.Sel.Name)
		}
		return true
	})
}
