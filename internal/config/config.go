// Package config loads the portal's runtime configuration from the
// environment.
//
// # The default posture is production
//
// This is the single most important decision in the package, and it is the
// reverse of the previous implementation's. There, PORTAL_ENV defaulted to
// development, PORTAL_DEMO_MODE defaulted to true, and a missing encryption key
// silently became thirty-two zero bytes. An operator who forgot one variable got
// an authentication bypass where every visitor was "Demo Member", predictable
// encryption keys, cookies without Secure, and no HSTS — with no error at any
// point. Every good gate in that codebase was conditioned on
// Environment == Production, so forgetting to say "production" disabled all of
// them at once.
//
// Here, an absent PORTAL_ENV means production, an absent key is a startup error,
// and there is no demo mode to enable. Getting configuration wrong makes the
// process refuse to start, which is the only failure mode that cannot be
// mistaken for working.
//
// # One load, per-command validation
//
// One flat struct and one Load, rather than the previous implementation's
// 272-line loader with four profiles that could drift apart. Each subcommand
// then calls the Require method for its role, so the worker is never asked for
// browser secrets and never receives them.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"triplebit.org/portal/internal/core"
)

// Config is the complete runtime configuration. Fields are populated by Load
// regardless of subcommand; the Require methods decide what must be present.
type Config struct {
	Environment core.Environment

	// BaseURL is the public origin. Its scheme decides cookie security, and
	// production requires https.
	BaseURL    *url.URL
	ListenAddr string

	DatabaseURL string

	// Two independent key rings. Production requires that they share neither a
	// key nor a key ID, so compromising one cannot read the other's data.
	PII     Keyring
	Session Keyring

	SessionIdleTTL     time.Duration
	SessionAbsoluteTTL time.Duration

	OIDC OIDC

	// TrustProxy enables X-Forwarded-For parsing, and is meaningless without at
	// least one CIDR — which is enforced, not assumed.
	TrustProxy        bool
	TrustedProxyCIDRs []string

	BrandName    string
	BrandTagline string
}

// Keyring is one AES-256-GCM key ring: an active key plus decrypt-only
// predecessors retained so ciphertext written before a rotation stays readable.
type Keyring struct {
	ActiveID string
	Active   []byte
	Previous map[string][]byte
}

// Material flattens the ring into id → key bytes, active included, which is
// the shape cryptox.NewKeyring consumes.
func (k Keyring) Material() map[string][]byte {
	keys := make(map[string][]byte, len(k.Previous)+1)
	for id, key := range k.Previous {
		keys[id] = key
	}
	if len(k.Active) > 0 {
		keys[k.ActiveID] = k.Active
	}
	return keys
}

// OIDC is the Pocket ID client configuration.
type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

const (
	defaultListenAddr   = ":8080"
	defaultIdleTTL      = 30 * time.Minute
	defaultAbsoluteTTL  = 12 * time.Hour
	defaultBrandName    = "Membership Portal"
	defaultBrandTagline = "Membership and giving"
	maxPreviousKeys     = 8
	keySize             = 32
)

// Load reads configuration from the environment. It reports every problem it
// finds rather than stopping at the first, because an operator fixing a
// deployment should not have to discover mistakes one restart at a time.
func Load() (*Config, error) {
	l := &loader{}
	cfg := &Config{}

	cfg.Environment = l.environment()
	cfg.BaseURL = l.baseURL(cfg.Environment)
	cfg.ListenAddr = l.stringOr("PORTAL_LISTEN_ADDR", defaultListenAddr)
	cfg.DatabaseURL = strings.TrimSpace(os.Getenv("PORTAL_DATABASE_URL"))

	cfg.PII = l.keyring("PORTAL_ENCRYPTION")
	cfg.Session = l.keyring("PORTAL_SESSION")

	cfg.SessionIdleTTL = l.duration("PORTAL_SESSION_IDLE_TTL", defaultIdleTTL)
	cfg.SessionAbsoluteTTL = l.duration("PORTAL_SESSION_ABSOLUTE_TTL", defaultAbsoluteTTL)

	cfg.OIDC = OIDC{
		Issuer:       strings.TrimSpace(os.Getenv("PORTAL_OIDC_ISSUER")),
		ClientID:     strings.TrimSpace(os.Getenv("PORTAL_OIDC_CLIENT_ID")),
		ClientSecret: os.Getenv("PORTAL_OIDC_CLIENT_SECRET"),
		RedirectURL:  strings.TrimSpace(os.Getenv("PORTAL_OIDC_REDIRECT_URL")),
	}

	cfg.TrustProxy = l.bool("PORTAL_TRUST_PROXY", false)
	cfg.TrustedProxyCIDRs = l.list("PORTAL_TRUSTED_PROXY_CIDRS")

	cfg.BrandName = l.stringOr("PORTAL_BRAND_NAME", defaultBrandName)
	cfg.BrandTagline = l.stringOr("PORTAL_BRAND_TAGLINE", defaultBrandTagline)

	l.checkUniversal(cfg)
	return cfg, l.err()
}

// RequireServe validates what the HTTP server needs. It is the only role given
// both key rings, because it is the only one that reads browser sessions and
// decrypts personal data for staff.
func (c *Config) RequireServe() error {
	l := &loader{}
	l.require(c.DatabaseURL != "", "PORTAL_DATABASE_URL is required")
	l.require(c.BaseURL != nil, "PORTAL_BASE_URL is required")
	l.requireKeyring("PORTAL_ENCRYPTION", c.PII)
	l.requireKeyring("PORTAL_SESSION", c.Session)
	l.require(c.OIDC.Issuer != "", "PORTAL_OIDC_ISSUER is required")
	l.require(c.OIDC.ClientID != "", "PORTAL_OIDC_CLIENT_ID is required")
	l.require(c.OIDC.ClientSecret != "", "PORTAL_OIDC_CLIENT_SECRET is required")
	l.require(c.OIDC.RedirectURL != "", "PORTAL_OIDC_REDIRECT_URL is required")

	if c.Environment.IsProduction() {
		l.require(strings.HasPrefix(c.OIDC.Issuer, "https://"),
			"PORTAL_OIDC_ISSUER must use https in production")
		l.require(strings.HasPrefix(c.OIDC.RedirectURL, "https://"),
			"PORTAL_OIDC_REDIRECT_URL must use https in production")
	}
	if c.TrustProxy {
		l.require(len(c.TrustedProxyCIDRs) > 0,
			"PORTAL_TRUST_PROXY is enabled but PORTAL_TRUSTED_PROXY_CIDRS is empty: "+
				"forwarded headers would be honoured from any peer")
	}
	return l.err()
}

// RequireWorker validates what the background processor needs.
//
// It deliberately does not reference the session or PII key rings. The worker
// has no browser sessions to read and no personal data to display, so it is
// never given those secrets and a compromise of it cannot decrypt them. There
// is a test asserting this method touches neither field, because the property
// is easy to erode by accident.
func (c *Config) RequireWorker() error {
	l := &loader{}
	l.require(c.DatabaseURL != "", "PORTAL_DATABASE_URL is required")
	return l.err()
}

// RequireMigrate validates what the migration runner needs.
func (c *Config) RequireMigrate() error {
	l := &loader{}
	l.require(c.DatabaseURL != "", "PORTAL_DATABASE_URL is required")
	return l.err()
}

// loader accumulates problems so one run reports them all.
type loader struct {
	problems []string
}

func (l *loader) require(ok bool, problem string) {
	if !ok {
		l.problems = append(l.problems, problem)
	}
}

func (l *loader) err() error {
	if len(l.problems) == 0 {
		return nil
	}
	return fmt.Errorf("configuration is not valid:\n  - %s", strings.Join(l.problems, "\n  - "))
}

func (l *loader) environment() core.Environment {
	env, err := core.ParseEnvironment(strings.TrimSpace(os.Getenv("PORTAL_ENV")))
	if err != nil {
		l.problems = append(l.problems, err.Error())
		// Fall back to the strict posture, so a typo cannot relax anything even
		// in the window before the error is returned.
		return core.Production
	}
	return env
}

func (l *loader) baseURL(env core.Environment) *url.URL {
	raw := strings.TrimSpace(os.Getenv("PORTAL_BASE_URL"))
	if raw == "" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		l.problems = append(l.problems, fmt.Sprintf("PORTAL_BASE_URL %q is not a valid absolute URL", raw))
		return nil
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if env.IsProduction() {
			l.problems = append(l.problems,
				"PORTAL_BASE_URL must use https in production: cookies would not be Secure")
		}
	default:
		l.problems = append(l.problems, fmt.Sprintf("PORTAL_BASE_URL scheme %q is not supported", parsed.Scheme))
		return nil
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	// The portal cannot be mounted under a subpath: every route is absolute
	// and cookies are Path=/. Worse, the same-origin check compares the
	// browser's Origin header — scheme://host only — against this URL, so a
	// path here would silently 403 every form submission. Refuse it at
	// startup instead of failing at the first sign-out.
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		l.problems = append(l.problems,
			fmt.Sprintf("PORTAL_BASE_URL %q must be an origin only — scheme and host, no path, query or credentials", raw))
		return nil
	}
	return parsed
}

// keyring reads <prefix>_KEY_ID, <prefix>_KEY and <prefix>_PREVIOUS_KEYS.
//
// A missing or malformed key produces a problem, never a usable zero key.
func (l *loader) keyring(prefix string) Keyring {
	ring := Keyring{
		ActiveID: strings.TrimSpace(os.Getenv(prefix + "_KEY_ID")),
		Previous: map[string][]byte{},
	}

	if raw := strings.TrimSpace(os.Getenv(prefix + "_KEY")); raw != "" {
		key, err := decodeKey(raw)
		if err != nil {
			l.problems = append(l.problems, fmt.Sprintf("%s_KEY %v", prefix, err))
		} else {
			ring.Active = key
		}
	}

	for _, entry := range l.list(prefix + "_PREVIOUS_KEYS") {
		id, raw, ok := strings.Cut(entry, "=")
		id = strings.TrimSpace(id)
		if !ok || id == "" {
			l.problems = append(l.problems,
				fmt.Sprintf("%s_PREVIOUS_KEYS entries must be formatted id=base64key", prefix))
			continue
		}
		key, err := decodeKey(strings.TrimSpace(raw))
		if err != nil {
			l.problems = append(l.problems, fmt.Sprintf("%s_PREVIOUS_KEYS entry %q %v", prefix, id, err))
			continue
		}
		if _, duplicate := ring.Previous[id]; duplicate {
			l.problems = append(l.problems, fmt.Sprintf("%s_PREVIOUS_KEYS repeats key id %q", prefix, id))
			continue
		}
		ring.Previous[id] = key
	}
	if len(ring.Previous) > maxPreviousKeys {
		l.problems = append(l.problems,
			fmt.Sprintf("%s_PREVIOUS_KEYS holds %d keys, at most %d are allowed",
				prefix, len(ring.Previous), maxPreviousKeys))
	}
	return ring
}

func (l *loader) requireKeyring(prefix string, ring Keyring) {
	l.require(ring.ActiveID != "", prefix+"_KEY_ID is required")
	l.require(len(ring.Active) > 0, prefix+"_KEY is required")
	_, clash := ring.Previous[ring.ActiveID]
	l.require(!(clash && ring.ActiveID != ""),
		prefix+"_PREVIOUS_KEYS must not contain the active key id")
}

// checkUniversal holds the cross-field rules that apply to every subcommand.
func (l *loader) checkUniversal(cfg *Config) {
	// The two rings must be genuinely independent: no key material may appear
	// in both, in any position. Comparing only the active keys would let a
	// rotation quietly move the PII key into the session ring's previous list
	// (or vice versa), after which recovering one ring decrypts the other's
	// data — precisely what having two rings is meant to prevent.
	for piiID, piiKey := range cfg.PII.Material() {
		for sessionID, sessionKey := range cfg.Session.Material() {
			if string(piiKey) == string(sessionKey) {
				l.problems = append(l.problems, fmt.Sprintf(
					"PORTAL_ENCRYPTION key %q and PORTAL_SESSION key %q are the same key material; the rings must be independent",
					piiID, sessionID))
			}
		}
	}
	if cfg.PII.ActiveID != "" && cfg.PII.ActiveID == cfg.Session.ActiveID {
		l.problems = append(l.problems,
			"PORTAL_ENCRYPTION_KEY_ID and PORTAL_SESSION_KEY_ID must be different")
	}
	if cfg.SessionIdleTTL > 0 && cfg.SessionAbsoluteTTL > 0 &&
		cfg.SessionIdleTTL > cfg.SessionAbsoluteTTL {
		l.problems = append(l.problems,
			"PORTAL_SESSION_IDLE_TTL must not exceed PORTAL_SESSION_ABSOLUTE_TTL")
	}
}

func (l *loader) stringOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func (l *loader) bool(name string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		l.problems = append(l.problems, fmt.Sprintf("%s %q is not a boolean", name, raw))
		return fallback
	}
	return value
}

func (l *loader) duration(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		l.problems = append(l.problems, fmt.Sprintf("%s %q is not a positive duration", name, raw))
		return fallback
	}
	return value
}

func (l *loader) list(name string) []string {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// decodeKey accepts standard or raw base64 and requires exactly 32 bytes.
//
// It returns an error for anything else. It never returns a zero key: the
// previous implementation's equivalent did, in development, which is how a
// deployment could run with an all-zero encryption key and no warning.
func decodeKey(raw string) ([]byte, error) {
	key, err := decodeBase64(raw)
	if err != nil {
		return nil, errors.New("is not valid base64")
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("must decode to exactly %d bytes, got %d", keySize, len(key))
	}
	if isAllZero(key) {
		return nil, errors.New("must not be all zero bytes")
	}
	return key, nil
}

func isAllZero(key []byte) bool {
	for _, b := range key {
		if b != 0 {
			return false
		}
	}
	return true
}
