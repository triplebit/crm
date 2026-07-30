package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterRejectsBurstAndRefills(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	limiter, err := NewRateLimiter(RateLimitOptions{
		Requests: 2,
		Window:   time.Minute,
		MaxKeys:  4,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if allowed, _ := limiter.Allow("member"); !allowed {
			t.Fatal("request within burst capacity was rejected")
		}
	}
	if allowed, retry := limiter.Allow("member"); allowed || retry <= 0 {
		t.Fatalf("burst was not rejected with retry delay: %v, %s", allowed, retry)
	}

	now = now.Add(30 * time.Second)
	if allowed, _ := limiter.Allow("member"); !allowed {
		t.Fatal("one token did not refill after half the window")
	}
}

func TestRateLimiterBoundsDistinctKeys(t *testing.T) {
	limiter, err := NewRateLimiter(RateLimitOptions{
		Requests: 1,
		Window:   time.Minute,
		MaxKeys:  2,
	})
	if err != nil {
		t.Fatal(err)
	}
	limiter.Allow("one")
	limiter.Allow("two")
	limiter.Allow("three")

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if len(limiter.buckets) != 2 {
		t.Fatalf("bucket count = %d, want 2", len(limiter.buckets))
	}
	if _, retained := limiter.buckets["one"]; retained {
		t.Fatal("least-recently-used key was not evicted")
	}
}

func TestRateLimitHTTPResponse(t *testing.T) {
	limiter, err := NewRateLimiter(RateLimitOptions{
		Requests: 1,
		Window:   time.Minute,
		MaxKeys:  2,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := RateLimit(
		limiter,
		func(*http.Request) string { return "same-client" },
		http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusNoContent)
		}),
	)

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/", nil))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first status = %d", first.Code)
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil))
	if second.Code != http.StatusTooManyRequests ||
		second.Header().Get("Retry-After") == "" {
		t.Fatalf(
			"limited response = %d, retry-after %q",
			second.Code,
			second.Header().Get("Retry-After"),
		)
	}
}
