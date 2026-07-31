package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/httpx"
	"triplebit.org/portal/internal/stripepay"
	"triplebit.org/portal/internal/testdb"
)

const (
	testMembershipsSecret = "whsec_web_memberships"
	testDonationsSecret   = "whsec_web_donations"
	testMembershipsAcct   = "acct_web_memberships"
	testDonationsAcct     = "acct_web_donations"
)

// deliver posts a body the way Stripe does: no Origin, no Referer, no cookie,
// and a signature over the exact bytes.
//
// It goes through the same middleware chain New builds, not straight to the mux,
// because the property that matters most here lives in the middleware: Stripe
// sends no Origin header, so a same-origin check with no exemption refuses every
// delivery before a handler ever runs. Testing the handler alone would pass
// while production silently settled nothing.
func deliver(t *testing.T, s *Server, account core.AccountRef, secret string, body []byte, at time.Time) *httptest.ResponseRecorder {
	t.Helper()
	var root http.Handler = s.mux
	root = httpx.LimitBody(root, maxFormBytes)
	root = httpx.RequireSameOrigin("http://portal.test", s.webhookPaths(), root)

	r := httptest.NewRequest(http.MethodPost, "http://portal.test"+webhookPath(account),
		strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		fmt.Fprintf(mac, "%d.%s", at.Unix(), body)
		r.Header.Set("Stripe-Signature",
			fmt.Sprintf("t=%d,v1=%s", at.Unix(), hex.EncodeToString(mac.Sum(nil))))
	}
	w := httptest.NewRecorder()
	root.ServeHTTP(w, r)
	return w
}

// eventID mints an id in Stripe's own shape. The schema enforces
// '^evt_[A-Za-z0-9]+$', so a friendlier id with underscores in it would test
// that CHECK constraint rather than this endpoint.
func eventID() string {
	return "evt_" + strings.ReplaceAll(uuid.NewString(), "-", "")
}

func webEventBody(id, account, objectID string) []byte {
	return []byte(fmt.Sprintf(
		`{"id":%q,"object":"event","type":"checkout.session.completed","created":%d,`+
			`"livemode":true,"context":%q,"api_version":%q,`+
			`"data":{"object":{"id":%q,"object":"checkout.session"}}}`,
		id, time.Now().Unix(), account, stripepay.ExpectedAPIVersion, objectID))
}

func countEvents(t *testing.T, stripeID string) int {
	t.Helper()
	var n int
	err := testdb.Pool(t).Conn().QueryRow(context.Background(),
		`SELECT count(*) FROM webhook_events WHERE stripe_event_id = $1`, stripeID).Scan(&n)
	if err != nil {
		t.Fatalf("count events: %v", err)
	}
	return n
}

// The regression test for the mistake this endpoint invited: Stripe posts with
// neither an Origin nor a Referer header, so the same-origin middleware that
// protects every other mutating route would have refused every delivery with a
// 403 — and the symptom would have appeared nowhere near the cause. Members
// would pay and nothing would ever settle.
func TestStripeWebhookIsReachableWithoutAnOriginHeader(t *testing.T) {
	s, _ := newTestServer(t)
	id := eventID()
	t.Cleanup(func() { deleteEvent(t, id) })

	w := deliver(t, s, core.Memberships, testMembershipsSecret,
		webEventBody(id, testMembershipsAcct, "cs_test_web1"), time.Now())

	if w.Code != http.StatusOK {
		t.Fatalf("status %d (%s), want 200: Stripe's delivery did not reach the handler", w.Code, strings.TrimSpace(w.Body.String()))
	}
	if countEvents(t, id) != 1 {
		t.Error("the event was acknowledged but not stored")
	}
}

// A retry must be a no-op that still reports success. Stripe retries the same
// event id, so "already have it" is the normal path, and answering anything
// other than 200 would make it keep trying forever.
func TestStripeWebhookStoresARetriedDeliveryOnlyOnce(t *testing.T) {
	s, _ := newTestServer(t)
	id := eventID()
	t.Cleanup(func() { deleteEvent(t, id) })
	body := webEventBody(id, testMembershipsAcct, "cs_test_web2")

	for attempt := 1; attempt <= 3; attempt++ {
		w := deliver(t, s, core.Memberships, testMembershipsSecret, body, time.Now())
		if w.Code != http.StatusOK {
			t.Fatalf("attempt %d: status %d, want 200", attempt, w.Code)
		}
	}
	if n := countEvents(t, id); n != 1 {
		t.Errorf("%d rows for one event id; a retry must not create a second", n)
	}
}

// An unverifiable delivery is refused with 400 — a permanent answer, because
// nothing about a retry would change it — and nothing is stored. Storing first
// and verifying later would let anyone fill the inbox with events the worker
// would then act on.
func TestStripeWebhookRefusesWhatItCannotVerify(t *testing.T) {
	s, _ := newTestServer(t)

	cases := map[string]struct {
		account core.AccountRef
		secret  string
		bodyFor func(id string) []byte
	}{
		"no signature": {core.Memberships, "", func(id string) []byte {
			return webEventBody(id, testMembershipsAcct, "cs_x")
		}},
		"wrong secret": {core.Memberships, testDonationsSecret, func(id string) []byte {
			return webEventBody(id, testMembershipsAcct, "cs_x")
		}},
		// Correctly signed for this endpoint, but the event says it belongs to
		// the other account: the cross-account guard, at the HTTP boundary.
		"other account's event": {core.Memberships, testMembershipsSecret, func(id string) []byte {
			return webEventBody(id, testDonationsAcct, "cs_x")
		}},
		// Authentic but on an API version this binary does not model.
		"api version mismatch": {core.Memberships, testMembershipsSecret, func(id string) []byte {
			return []byte(fmt.Sprintf(
				`{"id":%q,"object":"event","type":"checkout.session.completed","created":%d,`+
					`"livemode":true,"context":%q,"api_version":"2019-01-01",`+
					`"data":{"object":{"id":"cs_x","object":"checkout.session"}}}`,
				id, time.Now().Unix(), testMembershipsAcct))
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			id := eventID()
			t.Cleanup(func() { deleteEvent(t, id) })

			w := deliver(t, s, tc.account, tc.secret, tc.bodyFor(id), time.Now())
			if w.Code != http.StatusBadRequest {
				t.Errorf("status %d, want 400", w.Code)
			}
			if countEvents(t, id) != 0 {
				t.Error("an unverified event was stored")
			}
		})
	}
}

// The same-origin exemption must cover the webhook paths and nothing else: a
// forged POST to an ordinary route still has to be refused, or the fix for the
// webhook would have opened every other endpoint.
func TestSameOriginExemptionCoversWebhooksOnly(t *testing.T) {
	s, _ := newTestServer(t)
	paths := s.webhookPaths()
	if len(paths) != 2 {
		t.Fatalf("webhookPaths() = %v, want one per Stripe account", paths)
	}

	root := httpx.RequireSameOrigin("http://portal.test", paths,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
	for _, path := range []string{"/logout", "/enroll", "/give"} {
		r := httptest.NewRequest(http.MethodPost, "http://portal.test"+path, nil)
		r.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		root.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("cross-origin POST %s: status %d, want 403", path, w.Code)
		}
	}
}

func deleteEvent(t *testing.T, stripeID string) {
	t.Helper()
	_, _ = testdb.Pool(t).Conn().Exec(context.Background(),
		`DELETE FROM webhook_events WHERE stripe_event_id = $1`, stripeID)
}

// Two DIFFERENT events must both be stored.
//
// This is the regression test for the worst defect in the milestone. The handler
// omitted the row's own id, so every delivery inserted the all-zeros UUID: the
// first event claimed it and every later distinct event collided on the primary
// key — which ON CONFLICT (environment, account_ref, stripe_event_id) does not
// cover — producing a 500 that Stripe retried for three days before giving up.
// The portal could hold exactly one webhook event for its entire life, and
// nothing after the first ever settled.
//
// Every existing test missed it, and the shape of the gap is the lesson: one
// test stored a single event, one stored the SAME event three times (which is the
// intended ON CONFLICT path, and passes), and the projector tests build
// inbox.Event values themselves so they never exercise what the handler fills in.
// Nothing stored two distinct events through the HTTP boundary.
func TestTwoDifferentEventsAreBothStored(t *testing.T) {
	s, _ := newTestServer(t)

	first, second := eventID(), eventID()
	t.Cleanup(func() { deleteEvent(t, first); deleteEvent(t, second) })

	for _, id := range []string{first, second} {
		w := deliver(t, s, core.Memberships, testMembershipsSecret,
			webEventBody(id, testMembershipsAcct, "cs_"+id), time.Now())
		if w.Code != http.StatusOK {
			t.Fatalf("event %s: status %d (%s), want 200", id, w.Code,
				strings.TrimSpace(w.Body.String()))
		}
	}

	for _, id := range []string{first, second} {
		if n := countEvents(t, id); n != 1 {
			t.Errorf("event %s stored %d times, want 1", id, n)
		}
	}

	// And their row ids must differ, which is the actual invariant: two events
	// sharing one primary key is what broke.
	var distinctRowIDs int
	if err := testdb.Pool(t).Conn().QueryRow(context.Background(), `
		SELECT count(DISTINCT id) FROM webhook_events WHERE stripe_event_id = ANY($1)
	`, []string{first, second}).Scan(&distinctRowIDs); err != nil {
		t.Fatalf("count row ids: %v", err)
	}
	if distinctRowIDs != 2 {
		t.Errorf("%d distinct row ids for 2 events; the handler is reusing one", distinctRowIDs)
	}
}
