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

	// The clock advances past the backoff between attempts, so this test measures
	// the attempt BUDGET and nothing else. Retry spacing is a separate property
	// with its own test; conflating them would make this one fail for two
	// different reasons and explain neither.
	for attempt := 1; attempt <= 2; attempt++ {
		claimed, token, err := repo.Claim(ctx, pool.Conn(), core.StripeSandbox, time.Minute, now)
		if err != nil {
			t.Fatalf("claim %d: %v", attempt, err)
		}
		if claimed.ID != event.ID {
			// Another package's test row; put it back and retry.
			_ = repo.Fail(ctx, pool.Conn(), claimed.ID, token, "not ours", claimed.Attempts, now)
			attempt--
			continue
		}
		if err := repo.Fail(ctx, pool.Conn(), claimed.ID, token,
			fmt.Sprintf("attempt %d failed", attempt), claimed.Attempts, now); err != nil {
			t.Fatalf("fail %d: %v", attempt, err)
		}
		now = now.Add(2 * time.Hour) // past the backoff cap
	}

	// Budget exhausted: it must not be handed out again, however long we wait.
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
		_ = repo.Fail(ctx, pool.Conn(), claimed.ID, token, "not ours", claimed.Attempts, now)
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

// A failed event must not be claimable again until its delay has elapsed, and it
// must be claimable once it has. This is the property the M6 gate claimed —
// "a failed job visibly retries with backoff" — and did not have.
//
// Everything here is driven by an injected clock rather than by sleeping, so the
// test measures the schedule instead of the test runner's patience.
func TestAFailedEventWaitsForItsBackoffBeforeBeingClaimedAgain(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	repo := inbox.New()
	now := time.Now().UTC()

	event := newEvent(t, pool, "invoice.payment_failed")
	if _, err := repo.Receive(ctx, pool.Conn(), event, now, now); err != nil {
		t.Fatalf("receive: %v", err)
	}

	// claimOurs takes rows until it gets this test's, returning other packages'
	// rows to the queue untouched — the test database is shared.
	claimOurs := func(at time.Time) (inbox.Event, uuid.UUID, error) {
		for range 20 {
			claimed, token, err := repo.Claim(ctx, pool.Conn(), core.StripeSandbox, time.Minute, at)
			if err != nil {
				return inbox.Event{}, uuid.Nil, err
			}
			if claimed.ID == event.ID {
				return claimed, token, nil
			}
			_ = repo.Fail(ctx, pool.Conn(), claimed.ID, token, "not ours", claimed.Attempts, at)
		}
		t.Fatal("could not reach this test's event among the shared rows")
		return inbox.Event{}, uuid.Nil, nil
	}

	// A new event is due immediately: receipt must not itself be delayed.
	claimed, token, err := claimOurs(now)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := repo.Fail(ctx, pool.Conn(), claimed.ID, token, "stripe was down",
		claimed.Attempts, now); err != nil {
		t.Fatalf("fail: %v", err)
	}

	// Immediately afterwards there is nothing due. Before the due time existed,
	// this is exactly where the next attempt was handed out — twelve times in a
	// few milliseconds, then dead-lettered.
	if _, _, err := repo.Claim(ctx, pool.Conn(), core.StripeSandbox, time.Minute, now); err == nil {
		t.Error("a just-failed event was claimable immediately; the outage would burn its whole budget")
	} else if !errors.Is(err, db.ErrNotFound) {
		t.Errorf("claim error = %v, want db.ErrNotFound", err)
	}

	// Still nothing due a moment later: the minimum wait is seconds, not
	// milliseconds.
	if _, _, err := repo.Claim(ctx, pool.Conn(), core.StripeSandbox, time.Minute,
		now.Add(time.Second)); err != nil && !errors.Is(err, db.ErrNotFound) {
		t.Errorf("claim error = %v, want db.ErrNotFound", err)
	}

	// Past the maximum first delay (base plus jitter), it comes back.
	retryAt := now.Add(2 * time.Minute)
	again, token2, err := claimOurs(retryAt)
	if err != nil {
		t.Fatalf("claim after the backoff: %v", err)
	}
	if again.Attempts != 2 {
		t.Errorf("attempts = %d on the second claim, want 2", again.Attempts)
	}

	// And a second failure waits longer than the first did, which is what makes
	// the schedule a backoff rather than a fixed delay.
	if err := repo.Fail(ctx, pool.Conn(), again.ID, token2, "stripe still down",
		again.Attempts, retryAt); err != nil {
		t.Fatalf("second fail: %v", err)
	}
	var firstDue, secondDue time.Time
	if err := pool.Conn().QueryRow(ctx,
		`SELECT next_attempt_at FROM webhook_events WHERE id = $1`, event.ID).Scan(&secondDue); err != nil {
		t.Fatalf("read due time: %v", err)
	}
	firstDue = now.Add(inbox.BackoffFor(1))
	if secondDue.Sub(retryAt) <= firstDue.Sub(now) {
		t.Errorf("second delay %s is not longer than the first %s",
			secondDue.Sub(retryAt), firstDue.Sub(now))
	}
}
