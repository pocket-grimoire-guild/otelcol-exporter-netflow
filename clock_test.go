package netflowexporter

import (
	"context"
	"errors"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/destination"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testclock"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testpdata"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/testtransport"
	"go.opentelemetry.io/collector/component/componenttest"
	"math"
	"testing"
)

func TestClock(t *testing.T) {
	for _, tc := range []struct {
		wall, origin, want uint64
		configured         bool
	}{
		{1_234_567, 0, 1_000_000, false}, {1_234_567, 100, 1_000_100, true}, {99, 100, 99, true},
		{math.MaxUint64, 0, math.MaxUint64, false}, {(uint64(math.MaxUint32) + 1) * 1_000_000_000, 0, (uint64(math.MaxUint32) + 1) * 1_000_000_000, false},
		{(uint64(math.MaxUint32)+1)*1_000_000 + 1, 0, (uint64(math.MaxUint32)+1)*1_000_000 + 1, true},
	} {
		c := millisecondClock{clock: testclock.New(tc.wall, 123), origin: tc.origin, checkUptime: tc.configured}
		wall, mono := c.Now()
		if wall != tc.want || mono != 123 {
			t.Fatalf("%+v = %d/%d", tc, wall, mono)
		}
	}
	c := validConfig("netflow_v5")
	c.UptimeOrigin = ptr(uint64(0))
	e, conn := fakeExporter(t, c, testtransport.WriteStep{N: 72})
	if err := e.Start(context.Background(), componenttest.NewNopHost()); err != nil {
		t.Fatal(err)
	}
	if err := e.ConsumeLogs(context.Background(), testpdata.CanonicalLogs()); err == nil {
		t.Fatal("uptime overflow accepted")
	}
	for _, event := range conn.Events() {
		if event.Kind == testtransport.EventWrite {
			t.Fatal("exhausted epoch wrote")
		}
	}
	if _, err := e.runtime.Pack(context.Background(), testpdata.CanonicalLogs(), nil); errors.Is(err, destination.ErrPackTransient) {
		t.Fatal("exhaustion became retryable write")
	}
}
