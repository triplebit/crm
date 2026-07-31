package web

import (
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/repo/inbox"
	"triplebit.org/portal/internal/stripepay"
)

// webhookPath is the endpoint Stripe posts to, one per account. The account is
// in the path rather than read from the body because it selects which signing
// secret must verify the request: the body is not trusted until after that.
func webhookPath(account core.AccountRef) string {
	return "/stripe/webhook/" + account.String()
}

// stripeWebhook receives one event and does as little as possible with it.
//
// The handler's only job is to make the event durable and acknowledge it. It
// deliberately does not project: Stripe expects a response within seconds and
// retries anything slower, so doing the work inline would turn a slow database
// into duplicate deliveries, and an outage in projection into lost events. The
// worker projects from the inbox at its own pace, which is also what makes
// replay safe — the event is on disk before anything acts on it.
//
// Status codes are the retry protocol, so each one is chosen for what it makes
// Stripe do:
//
//   - 400, unverifiable: Stripe should not retry, because nothing will change.
//     A forged or misconfigured delivery is not a transient failure.
//   - 500, stored badly: Stripe should retry, because the database was the
//     problem and the next attempt may find it healthy.
//   - 200, stored (or already present): stop delivering. A duplicate is a
//     success — the inbox is keyed on the event id, and Stripe retries the same
//     id, so "already have it" is the normal happy path for a retry.
func (s *Server) stripeWebhook(account core.AccountRef) handler {
	return func(c *reqctx) error {
		// The body is read once and kept verbatim: the signature covers these
		// exact bytes, and the inbox stores them so a projection can be
		// re-derived later from what Stripe actually said.
		body, err := io.ReadAll(c.r.Body)
		if err != nil {
			// Includes the body cap being hit. Refusing with 400 would tell
			// Stripe to give up on an event that is probably genuine, so this
			// is a 500: retry, and let the failure be visible.
			s.logger.ErrorContext(c.r.Context(), "reading a webhook body failed",
				slog.String("account", account.String()), slog.String("error", err.Error()))
			http.Error(c.w, "could not read the request body", http.StatusInternalServerError)
			return nil
		}

		event, err := s.webhooks.Verify(account, body, c.r.Header.Get("Stripe-Signature"))
		if err != nil {
			// Logged at WARN, not ERROR: an unverifiable delivery is expected
			// background noise on a public endpoint, and paging someone for it
			// would train them to ignore the alert. A version mismatch is the
			// exception — that one is a misconfiguration only an operator can
			// fix, and it fails every event identically until they do.
			level := slog.LevelWarn
			if errors.Is(err, stripepay.ErrAPIVersionMismatch) {
				level = slog.LevelError
			}
			s.logger.Log(c.r.Context(), level, "rejected a webhook delivery",
				slog.String("account", account.String()), slog.String("error", err.Error()))
			http.Error(c.w, "signature verification failed", http.StatusBadRequest)
			return nil
		}

		stored, err := s.inbox.Receive(c.r.Context(), s.pool.Conn(), inbox.Event{
			// The row's own identity. Omitting it sent the all-zeros UUID, which
			// the first delivery claimed and every later distinct delivery then
			// collided with on the primary key — a 500 that Stripe retried for
			// three days before giving up. The portal could hold exactly one
			// webhook event, ever, and nothing after it ever settled.
			ID:          uuid.New(),
			StripeID:    event.ID,
			Type:        event.Type,
			Environment: s.stripeEnv,
			Account:     event.Account,
			ObjectID:    event.ObjectID,
			Payload:     event.Payload,
		}, s.now().UTC(), event.CreatedAt)
		if err != nil {
			// Nothing is acknowledged that was not stored: a 200 here would
			// tell Stripe to stop retrying an event the portal has lost, and
			// the member's money would sit paid against an unsettled order
			// with no trace of why.
			s.logger.ErrorContext(c.r.Context(), "storing a webhook event failed",
				slog.String("event", event.ID), slog.String("error", err.Error()))
			http.Error(c.w, "could not store the event", http.StatusInternalServerError)
			return nil
		}
		if !stored {
			s.logger.InfoContext(c.r.Context(), "webhook event already received",
				slog.String("event", event.ID), slog.String("type", event.Type))
		}

		c.w.WriteHeader(http.StatusOK)
		return nil
	}
}
