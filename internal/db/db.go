// Package db is the portal's only database seam.
//
// It exists to answer one question once: how does a repository method run
// against either a pool or a caller's open transaction? The previous
// implementation answered it six times, declaring six near-identical
// pgx-shaped interfaces (store.DBTX, store.DB, staffops.DB, dashboard.DB,
// jobs.DB, session.Database), every one of them satisfied by the same
// *pgxpool.Pool. Here there is exactly one: Conn.
//
// The convention that makes one interface sufficient: repository constructors
// take a *Pool, but repository *methods* take a Conn as the argument
// immediately after ctx. A method can then be called standalone or joined to a
// caller's transaction without a second code path. That is what removes the
// nineteen hand-written BeginTx/Rollback/Commit blocks the previous
// implementation carried, along with the retry loop it never got around to
// writing.
package db

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Conn is the subset of pgx satisfied by both *pgxpool.Pool and pgx.Tx.
//
// It deliberately offers no Begin: nesting transactions is the caller's
// decision, made by choosing WithTx, not something a repository can do
// implicitly halfway down a call stack.
type Conn interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Compile-time proof that the two things anyone will pass actually satisfy Conn.
var (
	_ Conn = (*pgxpool.Pool)(nil)
	_ Conn = (pgx.Tx)(nil)
)

// Pool owns the connection pool and is the only way to start a transaction.
type Pool struct {
	pool *pgxpool.Pool
}

// NewPool wraps an established pgx pool.
func NewPool(pool *pgxpool.Pool) *Pool { return &Pool{pool: pool} }

// Open parses dsn, connects, and verifies the connection with a ping, so a bad
// DSN or an unreachable database fails at startup rather than on first use.
func Open(ctx context.Context, dsn string) (*Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, wrap("parse database URL", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, wrap("connect to database", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, wrap("ping database", err)
	}
	return &Pool{pool: pool}, nil
}

// Conn returns the pool as a Conn, for reads that need no transaction.
func (p *Pool) Conn() Conn { return p.pool }

// Pgx exposes the underlying pool for the few callers that genuinely need it:
// the migration runner, which must run multi-statement SQL over the simple
// protocol, and readiness checks.
func (p *Pool) Pgx() *pgxpool.Pool { return p.pool }

// Close releases the pool.
func (p *Pool) Close() {
	if p != nil && p.pool != nil {
		p.pool.Close()
	}
}
