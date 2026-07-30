package httpx

import (
	"container/list"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimitOptions configures an in-process token bucket. MaxKeys is required
// so hostile, high-cardinality keys cannot grow server memory without bound.
type RateLimitOptions struct {
	Requests int
	Window   time.Duration
	MaxKeys  int
	Now      func() time.Time
}

// RateLimiter is a concurrency-safe, bounded LRU collection of token buckets.
// It is appropriate for protecting a single portal process; upstream
// reverse-proxy limits can provide an additional deployment-wide boundary.
type RateLimiter struct {
	mu       sync.Mutex
	requests float64
	window   time.Duration
	maxKeys  int
	now      func() time.Time
	buckets  map[string]*rateBucket
	lru      *list.List
}

type rateBucket struct {
	key       string
	tokens    float64
	updatedAt time.Time
	element   *list.Element
}

type RateLimitKey func(*http.Request) string

func NewRateLimiter(options RateLimitOptions) (*RateLimiter, error) {
	if options.Requests < 1 {
		return nil, errors.New("rate-limit request count must be positive")
	}
	if options.Window <= 0 {
		return nil, errors.New("rate-limit window must be positive")
	}
	if options.MaxKeys < 1 {
		return nil, errors.New("rate-limit key bound must be positive")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &RateLimiter{
		requests: float64(options.Requests),
		window:   options.Window,
		maxKeys:  options.MaxKeys,
		now:      options.Now,
		buckets:  make(map[string]*rateBucket, options.MaxKeys),
		lru:      list.New(),
	}, nil
}

// Allow consumes one token for key and returns the time until another token is
// available when the request is rejected.
func (l *RateLimiter) Allow(key string) (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = "unknown"
	}
	now := l.now().UTC()

	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			oldest := l.lru.Back()
			if oldest != nil {
				evicted := oldest.Value.(*rateBucket)
				delete(l.buckets, evicted.key)
				l.lru.Remove(oldest)
			}
		}
		bucket = &rateBucket{
			key:       key,
			tokens:    l.requests,
			updatedAt: now,
		}
		bucket.element = l.lru.PushFront(bucket)
		l.buckets[key] = bucket
	} else {
		l.lru.MoveToFront(bucket.element)
	}

	elapsed := now.Sub(bucket.updatedAt)
	if elapsed > 0 {
		refill := elapsed.Seconds() * l.requests / l.window.Seconds()
		bucket.tokens = min(l.requests, bucket.tokens+refill)
		bucket.updatedAt = now
	}
	if bucket.tokens >= 1 {
		bucket.tokens--
		return true, 0
	}

	secondsPerToken := l.window.Seconds() / l.requests
	waitSeconds := (1 - bucket.tokens) * secondsPerToken
	retryAfter := time.Duration(math.Ceil(waitSeconds*1000)) * time.Millisecond
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	return false, retryAfter
}

// RateLimit wraps an HTTP handler. An empty key is grouped into one bounded
// "unknown" bucket rather than bypassing the control.
func RateLimit(
	limiter *RateLimiter,
	key RateLimitKey,
	next http.Handler,
) http.Handler {
	if limiter == nil {
		return next
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		value := ""
		if key != nil {
			value = key(request)
		}
		allowed, retryAfter := limiter.Allow(value)
		if !allowed {
			WriteRateLimitExceeded(writer, retryAfter)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// RateLimitIfPresent applies the limit only when the key function returns a
// non-empty value. It is used for a stable authenticated subject layered on
// top of an always-present per-IP limit.
func RateLimitIfPresent(
	limiter *RateLimiter,
	key RateLimitKey,
	next http.Handler,
) http.Handler {
	if limiter == nil {
		return next
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if key == nil {
			next.ServeHTTP(writer, request)
			return
		}
		value := strings.TrimSpace(key(request))
		if value == "" {
			next.ServeHTTP(writer, request)
			return
		}
		allowed, retryAfter := limiter.Allow(value)
		if !allowed {
			WriteRateLimitExceeded(writer, retryAfter)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func WriteRateLimitExceeded(writer http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(math.Ceil(retryAfter.Seconds()))
	writer.Header().Set("Retry-After", strconv.Itoa(max(1, seconds)))
	writer.Header().Set("Cache-Control", "no-store")
	http.Error(
		writer,
		"Too many requests. Please try again shortly.",
		http.StatusTooManyRequests,
	)
}
