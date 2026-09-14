//go:build ignore

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/integration/tshark/internal/oracle"
)

func main() {
	image := flag.String("image", "", "exact IMAGE_DIGEST reference")
	pull := flag.String("pull", "", "must be never")
	live := flag.String("live-capture", "", "fresh OCB capture directory (omit for immutable goldens)")
	flag.Parse()
	if *pull != "never" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: run_oracle.sh --pull=never --image <IMAGE_DIGEST>")
		os.Exit(2)
	}
	repo, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, 5*time.Minute)
	defer cancel()
	cfg := oracle.Config{Repo: repo, Image: *image, Artifacts: os.Getenv("NETFLOW_TSHARK_ARTIFACTS")}
	if *live != "" {
		err = oracle.RunLive(ctx, cfg, *live)
	} else {
		err = oracle.Run(ctx, cfg)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	if *live != "" {
		fmt.Println("PASS: pinned TShark decoded 21 original live OCB frames; payloads, projected fields, templates, sequence, outer lengths/checksums")
		return
	}
	fmt.Println("PASS: pinned TShark independently decoded seven immutable v5/v9/IPFIX goldens; payload identity, field values/order/widths/offsets, synthetic outer lengths/checksums")
}
