package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sd-strax/aatu/config"
	"github.com/sd-strax/aatu/supervisor"
)

// version is the OSS binary's version string. A build flag will stamp the
// git SHA once a release process exists; today it's a static label.
const version = "aatu OSS (dev)"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "start":
		if err := runStart(); err != nil {
			log.Fatalf("aatu start: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: aatu <command>")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  version    print the aatu version")
	fmt.Fprintln(os.Stderr, "  start      bring up the bundled-deps stack (Postgres for now; Temporal + Keycloak + backend land in subsequent A.2 sub-tasks)")
}

// runStart brings up the bundled-deps supervisor and blocks until the
// process receives SIGINT or SIGTERM. Stop is best-effort with a 30s
// deadline.
//
// Today's scope (A.2.1): Postgres only. Temporal, Keycloak, and the
// in-process backend land in A.2.2, A.2.3, and A.2.4 respectively.
func runStart() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	sup := supervisor.New()
	sup.Register(
		supervisor.NewPostgres(supervisor.PostgresConfig{
			DataDir:   filepath.Join(cfg.Data.Dir, "pg"),
			Port:      cfg.Postgres.Port,
			Databases: []string{"aatu_main", "aatu_temporal", "aatu_knowledge"},
		}),
		supervisor.FatalOnExit,
	)

	if err := sup.Start(ctx); err != nil {
		return fmt.Errorf("supervisor start: %w", err)
	}
	log.Println("aatu: bundled stack ready. Press Ctrl-C to stop.")

	<-ctx.Done()
	log.Println("aatu: shutdown signal received")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopCancel()
	if err := sup.Stop(stopCtx); err != nil {
		return fmt.Errorf("supervisor stop: %w", err)
	}
	log.Println("aatu: stopped")
	return nil
}
