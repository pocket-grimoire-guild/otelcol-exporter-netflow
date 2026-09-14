package transport

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
)

func TestTelemetry(t *testing.T) {
	for _, tc := range []struct {
		name, host string
		step       testtransport.ResolverStep
		want       LookupOutcome
	}{
		{"literal", "192.0.2.1", testtransport.ResolverStep{}, LookupNotAttempted},
		{"success", "collector.example", testtransport.ResolverStep{Answers: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}, LookupSucceeded},
		{"failure", "collector.example", testtransport.ResolverStep{Err: errors.New("private lookup")}, LookupFailed},
		{"empty", "collector.example", testtransport.ResolverStep{}, LookupFailed},
		{"canceled", "collector.example", testtransport.ResolverStep{Wait: make(chan struct{})}, LookupFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := testtransport.NewResolver(tc.step)
			resolver, err := NewResolverWithLookup("udp", tc.host, time.Second, lookup)
			if err != nil {
				t.Fatal(err)
			}
			maintenance := NewMaintenance()
			token, err := maintenance.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if token.LookupOutcome() != LookupNotAttempted {
				t.Fatal("outcome before lookup")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.name == "canceled" {
				cancel()
			}
			_, _ = resolver.ResolveFor(ctx, token)
			if token.LookupOutcome() != tc.want {
				t.Fatalf("got %d want %d", token.LookupOutcome(), tc.want)
			}
			// A rejected second use cannot replace the first resolution's result.
			_, _ = resolver.ResolveFor(context.Background(), token)
			if token.LookupOutcome() != tc.want {
				t.Fatal("duplicate lookup overwrote outcome")
			}
			if _, err = maintenance.End(token); err != nil {
				t.Fatal(err)
			}
			if token.LookupOutcome() != tc.want {
				t.Fatal("End lost completed outcome")
			}
			next, err := maintenance.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if next.LookupOutcome() != LookupNotAttempted || token.LookupOutcome() != tc.want {
				t.Fatal("generation outcomes leaked")
			}
			_, _ = maintenance.End(next)
		})
	}
	t.Run("in_flight", func(t *testing.T) {
		started := make(chan struct{})
		lookup := testtransport.NewResolver(testtransport.ResolverStep{Started: started, Wait: make(chan struct{})})
		resolver, err := NewResolverWithLookup("udp", "collector.example", time.Second, lookup)
		if err != nil {
			t.Fatal(err)
		}
		maintenance := NewMaintenance()
		token, _ := maintenance.Begin()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() { _, _ = resolver.ResolveFor(ctx, token); close(done) }()
		<-started
		if token.LookupOutcome() != LookupNotAttempted {
			t.Fatal("in-flight lookup has terminal result")
		}
		cancel()
		<-done
		if token.LookupOutcome() != LookupFailed {
			t.Fatal("cancellation absent")
		}
		_, _ = maintenance.End(token)
	})
}
