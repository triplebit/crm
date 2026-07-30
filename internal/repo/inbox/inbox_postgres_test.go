package inbox_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/inbox"
	"triplebit.org/portal/internal/testdb"
)

// Events are keyed per test run so the shared database stays usable, and
// swept afterwards — webhook_events is not append-only, so it can be.
func newEvent(t *testing.T, pool *db.Pool, eventType string) inbox.Event {
	t.Helper()
	id := uuid.New()
	stripeID := "evt_" + strings.ReplaceAll(id.String(), "-", "")
	t.Cleanup(func() {
		if _, err := pool.Conn().Exec(context.Background(),
			`DELETE FROM webhook_events WHERE stripe_event_id = $1`, stripeID); err != nil {
			t.Errorf("cleanup event %s: %v", stripeID, err)
		}
	})
	return inbox.Event{
		ID:          id,
		Environment: core.StripeSandbox,
		Account:     core.Memberships,
		StripeID:    stripeID,
		Type:        eventType,
		ObjectID:    "pi_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
		Payload:     []byte(`{"id":"` + stripeID + `"}`),
	}
}

// Stripe retries deliveries. A retry must be recorded once, not projected
// twice — the unique index is what makes that true, and Receive reports which
// case happened so the handler can answer 200 either way.
func TestReceiveIsIdempotentPerStripeEvent(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	repo := inbox.New()
	now := time.Now().UTC()

	event := newEvent(t, pool, "payment_intent.succeeded")
	stored, err := repo.Receive(ctx, pool.Conn(), event, now, now)
	if err != nil {
		t.Fatalf("first Receive: %v", err)
	}
	if !stored {
		t.Error("the first delivery was reported as a duplicate")
	}

	// The same Stripe event id, a different row id, as a redelivery would be.
	redelivery := event
	redelivery.ID = uuid.New()
	stored, err = repo.Receive(ctx, pool.Conn(), redelivery, now, now)
	if err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if stored {
		t.Error("a redelivered event was stored a second time")
	}

	var rows int
	if err := pool.Conn().QueryRow(ctx,
		`SELECT count(*) FROM webhook_events WHERE stripe_event_id = $1`, event.StripeID).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("%d rows for one Stripe event, want 1", rows)
	}
}

// Two workers polling at once must take different rows. Without SKIP LOCKED
// they convoy on the oldest row and one of them does nothing; worse, a naive
// claim could hand the same event to both.
func TestConcurrentWorkersClaimDifferentEvents(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	repo := inbox.New()
	now := time.Now().UTC()

	const workers = 4
	ids := make(map[uuid.UUID]bool, workers)
	for i := 0; i < workers; i++ {
		e := newEvent(t, pool, "payment_intent.succeeded")
		if _, err := repo.Receive(ctx, pool.Conn(), e, now, now); err != nil {
			t.Fatalf("receive: %v", err)
		}
		ids[e.ID] = true
	}

	claimed := make([]uuid.UUID, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e, _, err := repo.Claim(ctx, pool.Conn(), core.StripeSandbox, time.Minute, now)
			claimed[i], errs[i] = e.ID, err
		}(i)
	}
	wg.Wait()

	seen := make(map[uuid.UUID]int)
	for i, err := range errs {
		if err != nil {
			// Not-found is legitimate: another package's test may have taken
			// the row. Anything else is a real failure.
			if errors.Is(err, db.ErrNotFound) {
				continue
			}
			t.Fatalf("worker %d: %v", i, err)
		}
		seen[claimed[i]]++
	}
	for id, count := range seen {
		if count > 1 {
			t.Errorf("event %s was claimed %d times; a claim must be exclusive", id, count)
		}
	}
	// At least our own events should have been claimable.
	if len(seen) == 0 {
		t.Error("no worker claimed anything")
	}
}

// The crash the schema previously had no answer for: a worker takes a lease
// and dies. The row must become claimable again, and the dead worker's late
// completion must be refused.
func TestExpiredLeaseIsReapedAndTheDeadWorkerCannotFinish(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	repo := inbox.New()
	now := time.Now().UTC()

	event := newEvent(t, pool, "invoice.paid")
	if _, err := repo.Receive(ctx, pool.Conn(), event, now, now); err != nil {
		t.Fatalf("receive: %v", err)
	}

	claimed, token, err := repo.Claim(ctx, pool.Conn(), core.StripeSandbox, time.Second, now)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}

	// The lease expires; the reaper returns it.
	if _, err := repo.ReapExpiredLeases(ctx, pool.Conn(), now.Add(time.Minute)); err != nil {
		t.Fatalf("reap: %v", err)
	}
	var state string
	var leaseToken *uuid.UUID
	if err := pool.Conn().QueryRow(ctx,
		`SELECT processing_state, lease_token FROM webhook_events WHERE id = $1`,
		claimed.ID).Scan(&state, &leaseToken); err != nil {
		t.Fatalf("read state: %v", err)
	}
	if state != "failed" || leaseToken != nil {
		t.Errorf("after reaping: state=%s token=%v; want failed with no lease", state, leaseToken)
	}

	// The dead worker wakes up and tries to record success. Its lease is gone,
	// so the write must be refused — otherwise it could overwrite the state of
	// a row another worker has since taken.
	err = repo.Complete(ctx, pool.Conn(), claimed.ID, token, now)
	if !errors.Is(err, db.ErrConflict) {
		t.Errorf("a reaped worker completed its event: %v", err)
	}
}

// An event that keeps failing must stop being retried and become visible to a
// human instead. A dead-letter queue nobody reads is not a control.
func TestExhaustedAttemptsStopRetryingAndSurface(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	repo := inbox.New()
	now := time.Now().UTC()

	event := newEvent(t, pool, "charge.refunded")
	if _, err := repo.Receive(ctx, pool.Conn(), event, now, now); err != nil {
		t.Fatalf("receive: %v", err)
	}
	// Give it a small budget so the test does not need twelve rounds.
	if _, err := pool.Conn().Exec(ctx,
		`UPDATE webhook_events SET max_attempts = 2 WHERE id = $1`, event.ID); err != nil {
		t.Fatalf("shrink budget: %v", err)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		claimed, token, err := repo.Claim(ctx, pool.Conn(), core.StripeSandbox, time.Minute, now)
		if err != nil {
			t.Fatalf("claim %d: %v", attempt, err)
		}
		if claimed.ID != event.ID {
			// Another package's test row; put it back and retry.
			_ = repo.Fail(ctx, pool.Conn(), claimed.ID, token, "not ours")
			attempt--
			continue
		}
		if err := repo.Fail(ctx, pool.Conn(), claimed.ID, token, fmt.Sprintf("attempt %d failed", attempt)); err != nil {
			t.Fatalf("fail %d: %v", attempt, err)
		}
	}

	// Budget exhausted: it must not be handed out again.
	for i := 0; i < 5; i++ {
		claimed, token, err := repo.Claim(ctx, pool.Conn(), core.StripeSandbox, time.Minute, now)
		if errors.Is(err, db.ErrNotFound) {
			break
		}
		if err != nil {
			t.Fatalf("claim after exhaustion: %v", err)
		}
		if claimed.ID == event.ID {
			t.Fatal("an event past its attempt budget was claimed again")
		}
		_ = repo.Fail(ctx, pool.Conn(), claimed.ID, token, "not ours")
	}

	// And it must be listed for a human.
	letters, err := repo.DeadLetters(ctx, pool.Conn(), core.StripeSandbox, 100)
	if err != nil {
		t.Fatalf("dead letters: %v", err)
	}
	found := false
	for _, l := range letters {
		if l.StripeID == event.StripeID {
			found = true
			if l.Attempts != 2 || !strings.Contains(l.LastError, "attempt 2") {
				t.Errorf("dead letter reports attempts=%d error=%q", l.Attempts, l.LastError)
			}
		}
	}
	if !found {
		t.Error("an exhausted event is not listed as a dead letter; nobody would ever see it")
	}
}
