package inbox_test

import (
	"testing"
	"time"

	"triplebit.org/portal/internal/repo/inbox"
)

// The shape of the retry schedule, tested without a database because it is
// arithmetic and deserves to be pinned exactly.
//
// It exists because the roadmap's M6 gate promised "a failed job visibly retries
// with backoff" and there was no backoff at all: Fail returned a row to 'failed',
// Claim took it back on the next poll, and a one-second outage burned all twelve
// attempts in milliseconds — dead-lettering a legitimate payment. The attempt
// budget is meant to measure persistence, not speed.
func TestBackoffGrowsThenLevelsOff(t *testing.T) {
	t.Parallel()

	// Jitter means each call differs, so assert on bounds rather than equality.
	// Bounds are what actually matter: never instant, never unbounded.
	const (
		base   = 30 * time.Second
		cap    = time.Hour
		jitter = 0.2
	)

	within := func(t *testing.T, attempt int, want time.Duration) time.Duration {
		t.Helper()
		got := inbox.BackoffFor(attempt)
		low := time.Duration(float64(want) * (1 - jitter))
		high := time.Duration(float64(want) * (1 + jitter))
		if got < low || got > high {
			t.Errorf("BackoffFor(%d) = %s, want within ±%.0f%% of %s",
				attempt, got, jitter*100, want)
		}
		return got
	}

	// Doubling from the base, up to the cap.
	want := base
	for attempt := 1; attempt <= 8; attempt++ {
		within(t, attempt, want)
		if want < cap {
			want *= 2
			if want > cap {
				want = cap
			}
		}
	}

	// Past the cap it levels off rather than growing without bound: a schedule
	// that kept doubling would push the twelfth attempt days out, long after
	// Stripe has stopped retrying and anyone would have noticed.
	for _, attempt := range []int{9, 12, 50, 1000} {
		within(t, attempt, cap)
	}

	// A nonsense attempt number must still produce a real delay. Zero would mean
	// an immediate retry, which is the bug this whole schedule exists to prevent.
	for _, attempt := range []int{0, -1} {
		if got := inbox.BackoffFor(attempt); got <= 0 {
			t.Errorf("BackoffFor(%d) = %s, want a positive delay", attempt, got)
		}
	}
}

// Jitter has to actually vary, or a fleet of workers that failed together comes
// back in lockstep and reproduces the outage they were waiting out.
func TestBackoffIsJittered(t *testing.T) {
	t.Parallel()

	seen := make(map[time.Duration]bool)
	for range 50 {
		seen[inbox.BackoffFor(3)] = true
	}
	if len(seen) < 10 {
		t.Errorf("50 calls produced only %d distinct delays; the jitter is not spreading anything", len(seen))
	}
}
