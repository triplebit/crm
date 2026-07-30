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
//	portal bootstrap-staff  grant the first local administrator
//	portal rotate-pii       re-encrypt PII envelopes under the active key
//	portal doctor           fail-closed pre-launch readiness gate
//	portal healthcheck      probe a running server (used by the container)
//	portal version          print build information
package main

import (
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
	case "serve", "worker", "migrate", "catalog-sync", "bootstrap-staff",
		"rotate-pii", "doctor", "healthcheck":
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

func runVersion(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("expected no arguments, got %d", len(args))
	}

	revision, modified := "unknown", ""
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
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
  bootstrap-staff  grant the first local administrator
  rotate-pii       re-encrypt PII envelopes under the active key
  doctor           fail-closed pre-launch readiness gate
  healthcheck      probe a running server
  version          print build information
`)
}
