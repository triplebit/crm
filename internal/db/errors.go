package db

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Sentinels every repository returns, so callers can branch on outcome without
// importing pgx or knowing any SQLSTATE.
var (
	// ErrNotFound means the row does not exist, or does not exist in a state
	// the query would accept.
	ErrNotFound = errors.New("db: not found")

	// ErrConflict means a uniqueness or exclusion constraint refused the write.
	// Which constraint is available via ConstraintError.
	ErrConflict = errors.New("db: conflict")

	// ErrInvalid means a CHECK constraint, a foreign key, or a NOT NULL refused
	// the write: the database rejected the value itself, not a race.
	ErrInvalid = errors.New("db: invalid")
)

// ConstraintError names the specific database constraint that refused a write.
//
// The schema deliberately carries the business rules — one live membership per
// person per program, at most one in-flight membership order, reserved never
// exceeding on_hand — so "which constraint fired" is frequently the most useful
// thing the caller can know. Callers switch on Constraint; errors.Is(err,
// ErrConflict) still works for those that only need the category.
//
// This replaces the previous implementation's deliberate wrapping of three
// different sentinels into a single error so that errors.Is matched all three.
// That was described as backward compatibility; its effect was to destroy the
// caller's ability to tell three distinct outcomes apart, in the order
// concurrency path.
type ConstraintError struct {
	// Constraint is the database identifier, for example
	// "orders_one_pending_membership_program_per_user_idx".
	Constraint string

	// Detail is PostgreSQL's DETAIL line. It can quote column values, so it is
	// safe for logs only after redaction and must never reach a response body.
	Detail string

	// Kind is the sentinel this constraint maps to.
	Kind error

	cause error
}

func (e *ConstraintError) Error() string {
	if e.Constraint == "" {
		return fmt.Sprintf("%v: %v", e.Kind, e.cause)
	}
	return fmt.Sprintf("%v: constraint %s", e.Kind, e.Constraint)
}

// Is lets errors.Is(err, db.ErrConflict) and friends match, so a caller that
// only cares about the category never has to know this type exists.
func (e *ConstraintError) Is(target error) bool { return target == e.Kind }

// Unwrap exposes the underlying pgx error for callers that need the detail.
func (e *ConstraintError) Unwrap() error { return e.cause }

// Normalize converts a pgx error into one of this package's sentinels, so that
// no SQLSTATE literal has to appear anywhere above this package.
//
// Anything unrecognised is returned unchanged: guessing at an unknown error's
// meaning is worse than passing it up.
func Normalize(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}

	switch pgErr.Code {
	case "23505": // unique_violation
		return &ConstraintError{Constraint: pgErr.ConstraintName, Detail: pgErr.Detail, Kind: ErrConflict, cause: err}
	case "23P01": // exclusion_violation
		return &ConstraintError{Constraint: pgErr.ConstraintName, Detail: pgErr.Detail, Kind: ErrConflict, cause: err}
	case "23514": // check_violation
		return &ConstraintError{Constraint: pgErr.ConstraintName, Detail: pgErr.Detail, Kind: ErrInvalid, cause: err}
	case "23503": // foreign_key_violation
		return &ConstraintError{Constraint: pgErr.ConstraintName, Detail: pgErr.Detail, Kind: ErrInvalid, cause: err}
	case "23502": // not_null_violation
		return &ConstraintError{Constraint: pgErr.ColumnName, Detail: pgErr.Detail, Kind: ErrInvalid, cause: err}
	default:
		return err
	}
}

// ConstraintOf returns the constraint name when err came from a named
// constraint, and "" otherwise. It saves every caller an errors.As dance.
func ConstraintOf(err error) string {
	var ce *ConstraintError
	if errors.As(err, &ce) {
		return ce.Constraint
	}
	return ""
}

func wrap(what string, err error) error { return fmt.Errorf("%s: %w", what, err) }
