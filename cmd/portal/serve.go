package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"triplebit.org/portal/internal/auth"
	"triplebit.org/portal/internal/checkout"
	"triplebit.org/portal/internal/config"
	"triplebit.org/portal/internal/cookie"
	"triplebit.org/portal/internal/core"
	"triplebit.org/portal/internal/cryptox"
	"triplebit.org/portal/internal/db"
	"triplebit.org/portal/internal/repo/accounts"
	"triplebit.org/portal/internal/repo/catalogdb"
	"triplebit.org/portal/internal/repo/customers"
	"triplebit.org/portal/internal/repo/orders"
	"triplebit.org/portal/internal/stripepay"
	"triplebit.org/portal/internal/web"
	"triplebit.org/portal/migrations"
)

// runServe assembles and runs the HTTP server. Assembly is strictly fail-fast:
// configuration, database, schema state and OIDC discovery are all proven
// before the listener opens, so a process that accepts a connection is one
// that can actually serve it.
func runServe(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("expected no arguments, got %d", len(args))
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.RequireServe(); err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	// The server never migrates; that is the migrate command's privilege. It
	// does refuse to start on a schema that does not match its binary, which
	// turns "deployed the web image before the migration ran" from a stream
	// of 500s into one clear startup error.
	if err := migrations.Verify(ctx, pool.Pgx()); err != nil {
		return fmt.Errorf("schema is not current: %w", err)
	}

	sessionKeys, err := cryptox.NewKeyring(cfg.Session.ActiveID, cfg.Session.Material())
	if err != nil {
		return fmt.Errorf("session keyring: %w", err)
	}
	piiKeys, err := cryptox.NewKeyring(cfg.PII.ActiveID, cfg.PII.Material())
	if err != nil {
		return fmt.Errorf("PII keyring: %w", err)
	}

	repo := accounts.New()
	sessions, err := auth.NewSessions(auth.SessionOptions{
		Repo: repo, Pool: pool, Keys: sessionKeys,
		IdleTTL: cfg.SessionIdleTTL, AbsoluteTTL: cfg.SessionAbsoluteTTL,
	})
	if err != nil {
		return err
	}
	oidc, err := auth.NewOIDC(ctx, auth.OIDCOptions{
		Issuer:       cfg.OIDC.Issuer,
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		RedirectURL:  cfg.OIDC.RedirectURL,
		Repo:         repo,
		Pool:         pool,
	})
	if err != nil {
		return err
	}
	jar, err := cookie.NewJar(cfg.BaseURL, cfg.Environment)
	if err != nil {
		return err
	}

	stripeEnv := core.StripeEnvironmentFor(cfg.Environment)
	pay, err := stripepay.New(stripepay.Options{
		APIKey:               cfg.Stripe.SecretKey,
		Environment:          stripeEnv,
		MembershipsAccountID: cfg.Stripe.MembershipsAccountID,
		DonationsAccountID:   cfg.Stripe.DonationsAccountID,
	})
	if err != nil {
		return err
	}
	checkoutSvc, err := checkout.New(checkout.Options{
		Customers:   customers.New(),
		Orders:      orders.New(),
		Catalog:     catalogdb.New(),
		Pool:        pool,
		Pay:         pay,
		Keys:        piiKeys,
		Environment: stripeEnv,
		BaseURL:     cfg.BaseURL.String(),
	})
	if err != nil {
		return err
	}

	var proxyCIDRs []string
	if cfg.TrustProxy {
		proxyCIDRs = cfg.TrustedProxyCIDRs
	}
	handler, err := web.New(web.Options{
		Sessions:          sessions,
		OIDC:              oidc,
		Checkout:          checkoutSvc,
		Jar:               jar,
		Logger:            logger,
		BaseURL:           cfg.BaseURL,
		BrandName:         cfg.BrandName,
		BrandTagline:      cfg.BrandTagline,
		Production:        cfg.Environment.IsProduction(),
		TrustedProxyCIDRs: proxyCIDRs,
	})
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	errs := make(chan error, 1)
	go func() {
		logger.Info("portal listening", "addr", cfg.ListenAddr, "env", fmt.Sprint(cfg.Environment))
		errs <- server.ListenAndServe()
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	}
}

// runHealthcheck probes a running server from inside its own container, where
// no shell and no curl exist. Exit 0 is healthy; anything else is not.
func runHealthcheck(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("expected no arguments, got %d", len(args))
	}
	addr := os.Getenv("PORTAL_LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}
