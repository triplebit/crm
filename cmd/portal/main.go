// Command portal is the single Triplebit Portal binary.
//
// One binary with subcommands, rather than the previous implementation's three
// binaries and two parallel configuration loaders that could drift apart. Each
// subcommand validates only the configuration it needs, so the worker never
// requires — and its container is never given — the PII or session encryption
// keys.
//
//	portal serve            HTTP server
//	portal worker           background queue and timer processor
//	portal migrate          apply embedded SQL migrations
//	portal catalog-sync     load the price manifest into the local catalog
//	portal catalog-availability  stop or resume offering one item
//	portal bootstrap-staff  grant the first local administrator
//	portal rotate-pii       re-encrypt PII envelopes under the active key
//	portal doctor           fail-closed pre-launch readiness gate
//	portal healthcheck      probe a running server (used by the container)
//	portal version          print build information
package main

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "version":
		err = runVersion(args)
	case "help", "-h", "--help":
		usage(os.Stdout)
	case "migrate":
		err = runMigrate(context.Background(), args)
	case "serve":
		err = runServe(context.Background(), args)
	case "healthcheck":
		err = runHealthcheck(context.Background(), args)
	case "catalog-sync":
		err = runCatalogSync(context.Background(), args)
	case "worker":
		err = runWorker(context.Background(), args)
	case "catalog-availability":
		err = runCatalogAvailability(context.Background(), args)
	case "bootstrap-staff", "rotate-pii", "doctor":
		// Implemented in later milestones. Listed explicitly so an unimplemented
		// subcommand reports that clearly, and a misspelling still exits 2.
		err = fmt.Errorf("subcommand %q is not implemented yet", cmd)
	default:
		fmt.Fprintf(os.Stderr, "portal: unknown subcommand %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "portal %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

// injectedRevision is set with -ldflags "-X main.injectedRevision=<sha>" by
// the Docker build, where no .git directory exists (it is dockerignored to
// keep the build cache stable) and debug.ReadBuildInfo therefore has no VCS
// stamp. Without this, the deployed image — the one place identity matters
// during an incident — is the one build that reports "unknown".
var injectedRevision string

func runVersion(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("expected no arguments, got %d", len(args))
	}

	revision, modified := "unknown", ""
	if injectedRevision != "" {
		revision = injectedRevision
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if injectedRevision == "" {
					revision = s.Value
				}
			case "vcs.modified":
				if s.Value == "true" {
					modified = " (modified)"
				}
			}
		}
		fmt.Printf("portal %s%s built with %s\n", revision, modified, info.GoVersion)
		return nil
	}

	fmt.Printf("portal %s%s\n", revision, modified)
	return nil
}

func usage(w *os.File) {
	fmt.Fprint(w, `portal — Triplebit Portal

Usage:
  portal <subcommand> [flags]

Subcommands:
  serve            run the HTTP server
  worker           run the background queue and timer processor
  migrate          apply embedded SQL migrations
  catalog-sync     load the price manifest into the local catalog
  catalog-availability <slug> in-stock|out-of-stock
                   stop or resume offering one item (no Stripe call)
  bootstrap-staff  grant the first local administrator (pending, M7)
  rotate-pii       re-encrypt PII envelopes under the active key (pending, M8)
  doctor           fail-closed pre-launch readiness gate (pending, M8)
  healthcheck      probe a running server
  version          print build information
`)
}
