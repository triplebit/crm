package stripepay_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/stripepay"
)

// These tests exist because the verifier is the trust boundary for everything
// M6 does: past it, a payload is treated as Stripe's word and money moves.
// Signatures are constructed here by hand rather than with a helper, so the
// test proves the real scheme is honoured, not that two of our own functions
// agree with each other.

const (
	membershipsSecret = "whsec_memberships_secret"
	donationsSecret   = "whsec_donations_secret"
	membershipsAcct   = "acct_wh_memberships"
	donationsAcct     = "acct_wh_donations"
)

func newVerifier(t *testing.T, env core.StripeEnvironment) *stripepay.WebhookVerifier {
	t.Helper()
	v, err := stripepay.NewWebhookVerifier(env, membershipsSecret, donationsSecret,
		membershipsAcct, donationsAcct)
	if err != nil {
		t.Fatalf("NewWebhookVerifier: %v", err)
	}
	return v
}

// sign produces the Stripe-Signature header for a body, the way Stripe does:
// HMAC-SHA256 over "<timestamp>.<body>" with the endpoint secret.
func sign(secret string, body []byte, at time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.%s", at.Unix(), body)
	return fmt.Sprintf("t=%d,v1=%s", at.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

func eventBody(id, eventType, account string, livemode bool, objectID string) []byte {
	return eventBodyVersion(id, eventType, account, livemode, objectID, stripepay.ExpectedAPIVersion)
}

// eventBodyVersion lets a test choose the api_version, because a mismatched one
// is a distinct failure an operator must be able to recognise.
func eventBodyVersion(id, eventType, account string, livemode bool, objectID, apiVersion string) []byte {
	return []byte(fmt.Sprintf(
		`{"id":%q,"object":"event","type":%q,"created":%d,"livemode":%t,"context":%q,`+
			`"api_version":%q,"data":{"object":{"id":%q,"object":"checkout.session"}}}`,
		id, eventType, time.Now().Unix(), livemode, account, apiVersion, objectID))
}

func TestVerifyAcceptsAWellSignedEvent(t *testing.T) {
	t.Parallel()
	v := newVerifier(t, core.StripeSandbox)
	body := eventBody("evt_ok1", "checkout.session.completed", membershipsAcct, false, "cs_test_ok1")

	event, err := v.Verify(core.Memberships, body, sign(membershipsSecret, body, time.Now()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if event.ID != "evt_ok1" || event.Type != "checkout.session.completed" {
		t.Errorf("event = %+v", event)
	}
	if event.ObjectID != "cs_test_ok1" {
		t.Errorf("object id = %q, want the session id", event.ObjectID)
	}
	if event.Account != core.Memberships {
		t.Errorf("account = %v", event.Account)
	}
	// The raw body must survive verbatim: it is what the inbox stores, and a
	// re-derived projection must be able to read exactly what Stripe signed.
	if string(event.Payload) != string(body) {
		t.Error("the payload was not preserved byte for byte")
	}
}

func TestVerifyRejectsBadSignatures(t *testing.T) {
	t.Parallel()
	v := newVerifier(t, core.StripeSandbox)
	body := eventBody("evt_bad1", "checkout.session.completed", membershipsAcct, false, "cs_test_bad1")
	now := time.Now()

	cases := map[string]struct {
		body   []byte
		header string
	}{
		"tampered body": {
			// Signed correctly, then altered — the case a signature exists to catch.
			body:   append(body[:len(body)-1], []byte(`,"injected":true}`)...),
			header: sign(membershipsSecret, body, now),
		},
		"wrong secret": {body: body, header: sign(donationsSecret, body, now)},
		"stale timestamp": {
			// Outside Stripe's tolerance: replay defence.
			body:   body,
			header: sign(membershipsSecret, body, now.Add(-24*time.Hour)),
		},
		"no header":      {body: body, header: ""},
		"garbage header": {body: body, header: "t=1,v1=nonsense"},
	}
	for name, tc := range cases {
		if _, err := v.Verify(core.Memberships, tc.body, tc.header); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !errors.Is(err, stripepay.ErrBadSignature) {
			t.Errorf("%s: error %v is not ErrBadSignature", name, err)
		}
	}
}

// The two-endpoint design's whole purpose: a correctly signed event delivered
// to the wrong account's endpoint must be refused, not projected into the
// wrong ledger.
func TestVerifyRefusesAnEventFromTheOtherAccount(t *testing.T) {
	t.Parallel()
	v := newVerifier(t, core.StripeSandbox)

	// Signed with the memberships secret, but the event says it belongs to the
	// donations account.
	body := eventBody("evt_cross1", "checkout.session.completed", donationsAcct, false, "cs_test_cross1")
	_, err := v.Verify(core.Memberships, body, sign(membershipsSecret, body, time.Now()))
	if err == nil {
		t.Fatal("an event belonging to the other account was accepted")
	}
	if !strings.Contains(err.Error(), "endpoint") {
		t.Errorf("error %v does not explain the account mismatch", err)
	}

	// An unknown account is refused too: it is neither of ours.
	unknown := eventBody("evt_cross2", "checkout.session.completed", "acct_someoneelse", false, "cs_test_cross2")
	if _, err := v.Verify(core.Memberships, unknown, sign(membershipsSecret, unknown, time.Now())); err == nil {
		t.Error("an event naming an unknown account was accepted")
	}

	// An event with no context at all is accepted: Stripe omits it outside
	// organization routing, and the signing secret already proves the account.
	noContext := eventBody("evt_cross3", "checkout.session.completed", "", false, "cs_test_cross3")
	if _, err := v.Verify(core.Memberships, noContext, sign(membershipsSecret, noContext, time.Now())); err != nil {
		t.Errorf("an event without a context was refused: %v", err)
	}
}

// Livemode must match the universe the process runs in, or real and test money
// would mix in one database.
func TestVerifyRefusesTheWrongUniverse(t *testing.T) {
	t.Parallel()

	sandbox := newVerifier(t, core.StripeSandbox)
	live := eventBody("evt_live1", "checkout.session.completed", membershipsAcct, true, "cs_live1")
	if _, err := sandbox.Verify(core.Memberships, live, sign(membershipsSecret, live, time.Now())); err == nil {
		t.Error("a live event was accepted by a sandbox process")
	}

	production := newVerifier(t, core.StripeProduction)
	test := eventBody("evt_test1", "checkout.session.completed", membershipsAcct, false, "cs_test1")
	if _, err := production.Verify(core.Memberships, test, sign(membershipsSecret, test, time.Now())); err == nil {
		t.Error("a test event was accepted by a live process")
	}
}

func TestNewWebhookVerifierRefusesUnusableConfiguration(t *testing.T) {
	t.Parallel()
	cases := map[string][]string{
		"no memberships secret": {"", donationsSecret, membershipsAcct, donationsAcct},
		"no donations secret":   {membershipsSecret, "", membershipsAcct, donationsAcct},
		// Two accounts sharing a secret would make the cross-account check
		// above unenforceable: either endpoint would verify either event.
		"shared secret":  {membershipsSecret, membershipsSecret, membershipsAcct, donationsAcct},
		"no account ids": {membershipsSecret, donationsSecret, "", ""},
	}
	for name, args := range cases {
		if _, err := stripepay.NewWebhookVerifier(core.StripeSandbox, args[0], args[1], args[2], args[3]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := stripepay.NewWebhookVerifier(core.StripeEnvironment{}, membershipsSecret, donationsSecret,
		membershipsAcct, donationsAcct); err == nil {
		t.Error("a zero environment was accepted")
	}
}

// An authentic event on the wrong API version must not read as a forgery. A
// misconfigured endpoint fails every event identically, and an operator sent
// looking for an attacker will not find the Dashboard setting that fixes it.
func TestVerifyDistinguishesAnAPIVersionMismatchFromAForgery(t *testing.T) {
	t.Parallel()
	v := newVerifier(t, core.StripeSandbox)
	body := eventBodyVersion("evt_ver1", "checkout.session.completed", membershipsAcct,
		false, "cs_test_ver1", "2019-01-01")

	_, err := v.Verify(core.Memberships, body, sign(membershipsSecret, body, time.Now()))
	if err == nil {
		t.Fatal("an event on an unexpected API version was accepted")
	}
	if !errors.Is(err, stripepay.ErrAPIVersionMismatch) {
		t.Errorf("error %v is not ErrAPIVersionMismatch", err)
	}
	if errors.Is(err, stripepay.ErrBadSignature) {
		t.Error("a version mismatch was reported as a bad signature; that sends operators hunting an attacker")
	}
	if !strings.Contains(err.Error(), stripepay.ExpectedAPIVersion) {
		t.Error("the error does not name the version the endpoint should use")
	}
}
