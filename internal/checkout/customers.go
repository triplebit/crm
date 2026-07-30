// Package checkout is the money-out service: it turns a signed-in member's
// choice into a Stripe Checkout Session, with every step crash-safe.
//
// This file is EnsureCustomer. One person has one Stripe Customer per
// environment, shared across the organization's two accounts (the same cus_
// identifier appears in both — verified against the real sandbox, with
// propagation measured in seconds). Creation is made crash-safe and
// concurrency-safe by the intent row: persisted before the remote call, one
// per person per environment by unique index, carrying the idempotency key —
// so any number of racing requests converge on one Customer, and a crash at
// any point resumes rather than duplicates.
package checkout

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/customers"
	"triplebit.org/portal/internal/stripepay"
)

// propagationWait bounds how long EnsureCustomer waits for a shared Customer
// to appear in the sibling account. Measured: ~1.1 seconds; tolerated: this.
// A person hitting the bound sees one failed checkout attempt and retries.
const (
	propagationWait = 15 * time.Second
	propagationPoll = 500 * time.Millisecond
)

// Service is the checkout orchestrator.
type Service struct {
	customers *customers.Repo
	pool      *db.Pool
	pay       *stripepay.Client
	env       core.StripeEnvironment
	now       func() time.Time
	sleep     func(context.Context, time.Duration) error
}

// Options configures the service. Everything is required except Now.
type Options struct {
	Customers   *customers.Repo
	Pool        *db.Pool
	Pay         *stripepay.Client
	Environment core.StripeEnvironment
	Now         func() time.Time

	// Sleep is the propagation-poll wait; tests replace it. Nil means real
	// context-aware sleeping.
	Sleep func(context.Context, time.Duration) error
}

// New builds the service, refusing an incomplete configuration.
func New(opts Options) (*Service, error) {
	switch {
	case opts.Customers == nil:
		return nil, errors.New("checkout: a customers repository is required")
	case opts.Pool == nil:
		return nil, errors.New("checkout: a database pool is required")
	case opts.Pay == nil:
		return nil, errors.New("checkout: a Stripe client is required")
	case opts.Environment.IsZero():
		return nil, errors.New("checkout: a Stripe environment is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	sleep := opts.Sleep
	if sleep == nil {
		sleep = func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	return &Service{
		customers: opts.Customers,
		pool:      opts.Pool,
		pay:       opts.Pay,
		env:       opts.Environment,
		now:       now,
		sleep:     sleep,
	}, nil
}

// Person is who the Customer belongs to, with the identity claims Stripe
// gets to see (they appear on receipts).
type Person struct {
	UserID uuid.UUID
	Email  string
	Name   string
}

// EnsureCustomer returns the person's Stripe Customer id, valid in the given
// account, creating and/or waiting for propagation as needed. Idempotent and
// safe under concurrency and crash-retry.
func (s *Service) EnsureCustomer(ctx context.Context, account core.AccountRef, person Person) (string, error) {
	// Fast path: this exact context has been observed before.
	customerID, err := s.customers.CustomerIDFor(ctx, s.pool.Conn(), person.UserID, s.env, account)
	switch {
	case err == nil:
		return customerID, nil
	case !errors.Is(err, db.ErrNotFound):
		return "", err
	}

	// The intent is created (or found) first, before any remote call. Its
	// origin account and idempotency key are fixed at insert, so concurrent
	// callers — even ones targeting the other account — converge on one
	// remote create.
	intent, err := s.customers.EnsureIntent(ctx, s.pool.Conn(), person.UserID, s.env, account, person.Email, person.Name)
	if err != nil {
		return "", err
	}

	switch {
	case intent.CustomerID != nil:
		customerID = *intent.CustomerID

	case !intent.Fresh:
		// An unresolved intent from an earlier attempt is the crash-window
		// signature: the Customer may exist remotely with nothing recorded
		// locally, and Stripe prunes idempotency records after ~24 hours, so
		// re-creating on the old key is only safe inside that window.
		// Reconcile by metadata search first; a Customer too young for
		// eventually-consistent search to see is young enough that the
		// idempotency record still deduplicates the create below.
		found, ok, err := s.pay.FindCustomerByLocalAccount(ctx, intent.OriginAccount, person.UserID.String())
		if err != nil {
			return "", err
		}
		if ok {
			if err := s.customers.RecordIntentResult(ctx, s.pool.Conn(), intent.ID, found.ID, s.now().UTC()); err != nil {
				return "", err
			}
			customerID = found.ID
			break
		}
		fallthrough

	default:
		created, err := s.pay.CreateCustomer(ctx, intent.OriginAccount, intent.Idempotency, stripepay.CustomerSpec{
			Email:          intent.Email,
			Name:           intent.Name,
			LocalAccountID: person.UserID.String(),
		})
		if err != nil {
			return "", err
		}
		if err := s.customers.RecordIntentResult(ctx, s.pool.Conn(), intent.ID, created.ID, s.now().UTC()); err != nil {
			return "", err
		}
		customerID = created.ID
	}

	// The origin projection is repaired on every path — including resuming a
	// recorded intent, where an earlier crash may have died exactly between
	// recording the intent and writing this row. Without this, that person
	// would consult the intent on every request forever.
	if err := s.customers.RecordCustomer(ctx, s.pool.Conn(), person.UserID, s.env, intent.OriginAccount, customerID, s.now().UTC()); err != nil {
		return "", err
	}

	// If the caller's account is not the origin, the Customer arrives there
	// by organization sharing — same identifier, bounded lag. resource_missing
	// is "not yet", anything else is an error.
	if account != intent.OriginAccount {
		if err := s.awaitPropagation(ctx, account, customerID); err != nil {
			return "", err
		}
		if err := s.customers.RecordCustomer(ctx, s.pool.Conn(), person.UserID, s.env, account, customerID, s.now().UTC()); err != nil {
			return "", err
		}
	}
	return customerID, nil
}

func (s *Service) awaitPropagation(ctx context.Context, account core.AccountRef, customerID string) error {
	deadline := s.now().Add(propagationWait)
	for {
		_, err := s.pay.GetCustomer(ctx, account, customerID)
		switch {
		case err == nil:
			return nil
		case !stripepay.IsNotFound(err):
			return err
		case s.now().After(deadline):
			return fmt.Errorf("checkout: customer %s has not propagated to %s within %s: %w",
				customerID, account.String(), propagationWait, err)
		}
		if err := s.sleep(ctx, propagationPoll); err != nil {
			return err
		}
	}
}
