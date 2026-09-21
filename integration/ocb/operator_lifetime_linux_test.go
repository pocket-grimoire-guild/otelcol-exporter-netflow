package ocb_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const operatorUptimeWindow = (1 << 32) * time.Millisecond

type operatorLifetime struct {
	remaining float64
	exhausted int64
}

// Inspect parsed data points, never HELP/TYPE substrings. The shared parser
// checks the exact gauge types, attributes, finite values and flow canaries.
func operatorLifetimes(t *testing.T, s operatorScrape) map[string]operatorLifetime {
	t.Helper()
	pairs := map[string]operatorLifetime{}
	seen := map[string]bool{}
	for _, sample := range s.samples {
		if sample.name != "otelcol_netflow_exporter_uptime_remaining" && sample.name != "otelcol_netflow_exporter_uptime_exhausted" {
			continue
		}
		id := sample.labels["exporter"]
		if id != "netflow/v5" && id != "netflow/v9" {
			t.Fatalf("unexpected lifetime sample for %q (IPFIX must have neither point)", id)
		}
		key := sample.name + "/" + id
		if seen[key] {
			t.Fatalf("duplicate lifetime series %s", key)
		}
		seen[key] = true
		pair := pairs[id]
		if sample.name == "otelcol_netflow_exporter_uptime_remaining" {
			pair.remaining = *sample.floatValue
		} else {
			pair.exhausted = sample.value
		}
		pairs[id] = pair
	}
	for _, id := range []string{"netflow/v5", "netflow/v9"} {
		for _, name := range []string{"uptime_remaining", "uptime_exhausted"} {
			if !seen["otelcol_netflow_exporter_"+name+"/"+id] {
				t.Fatalf("missing %s data sample for %s", name, id)
			}
		}
	}
	return pairs
}

func assertOperatorLifetimeProjection(t *testing.T, s operatorScrape, origins map[string]time.Time, v5Exhausted int64) map[string]operatorLifetime {
	t.Helper()
	pairs := operatorLifetimes(t, s)
	if s.requestedAt.IsZero() || s.receivedAt.Before(s.requestedAt) {
		t.Fatal("lifetime projection requires an actual timed HTTP observation")
	}
	for _, protocol := range []string{"v5", "v9"} {
		pair := pairs["netflow/"+protocol]
		wantExhausted := int64(0)
		if protocol == "v5" {
			wantExhausted = v5Exhausted
		}
		if pair.exhausted != wantExhausted {
			t.Fatalf("%s exhausted=%d, want %d", protocol, pair.exhausted, wantExhausted)
		}
		// The callback must fall inside the HTTP interval. Allow 5 ms for the
		// millisecond projection/clock sampling; do not target an exact edge.
		expiry := origins[protocol].Add(operatorUptimeWindow)
		low := max(0, expiry.Sub(s.receivedAt).Seconds()-0.005)
		high := max(0, expiry.Sub(s.requestedAt).Seconds()+0.005)
		if pair.remaining < low || pair.remaining > high {
			t.Fatalf("%s remaining=%f outside live origin projection [%f,%f]", protocol, pair.remaining, low, high)
		}
	}
	return pairs
}

// Use the existing checked fixture bytes and packet validators for both the
// ordinary example and these observations. Only configured template IDs move.
func operatorBootstrapTemplate(t *testing.T, protocol string, family int) []byte {
	t.Helper()
	name := []string{"canonical-ipv4-v1.bin", "canonical-ipv6-v1.bin"}[family]
	golden := bytes.Clone(operatorGolden(t, protocol, name))
	header, data := offsets(protocol)
	if protocol == "v9" {
		binary.BigEndian.PutUint16(golden[24:26], uint16(300+family))
		data = 108
	} else {
		binary.BigEndian.PutUint16(golden[20:22], uint16(300+family))
	}
	return golden[header:data]
}

type operatorLifetimeCollector struct {
	process        *collectorProcess
	outputs        map[string]*net.UDPConn
	ports          map[string]int
	origins        map[string]time.Time
	scraper        operatorScraper
	dir            string
	metricsAddress string
	v9Sequence     uint32 // synchronous test-owned output observation only
}

func startOperatorLifetimeCollector(t *testing.T, origins map[string]time.Time) *operatorLifetimeCollector {
	t.Helper()
	bin := os.Getenv("NETFLOW_OCB_BINARY")
	if bin == "" {
		t.Skip("build distribution/ocb and set NETFLOW_OCB_BINARY to exercise lifetime observations")
	}
	if os.Getenv("NETFLOW_OCB_NETNS") != "" {
		t.Skip("the checked-in operator example targets ordinary loopback")
	}
	bin, err := filepath.Abs(bin)
	must(t, err)
	assertBuild(t, bin)
	c := &operatorLifetimeCollector{outputs: map[string]*net.UDPConn{}, ports: map[string]int{}, origins: origins, dir: t.TempDir()}
	if base := os.Getenv("NETFLOW_OCB_ARTIFACTS"); base != "" {
		c.dir, err = os.MkdirTemp(base, "ocb-lifetime-")
		must(t, err)
		t.Logf("retained lifetime artifacts: %s", c.dir)
	}
	inputs := map[string]*net.UDPConn{}
	for _, protocol := range []string{"v5", "v9", "ipfix"} {
		inputs[protocol], c.outputs[protocol] = listen(t), listen(t)
		c.ports[protocol] = inputs[protocol].LocalAddr().(*net.UDPAddr).Port
		t.Setenv("NETFLOW_"+strings.ToUpper(protocol)+"_PORT", fmt.Sprint(c.ports[protocol]))
		t.Setenv("NETFLOW_"+strings.ToUpper(protocol)+"_ENDPOINT", c.outputs[protocol].LocalAddr().String())
	}
	for _, protocol := range []string{"v5", "v9"} {
		t.Setenv("NETFLOW_"+strings.ToUpper(protocol)+"_ORIGIN", fmt.Sprint(origins[protocol].UnixNano()))
	}
	must(t, os.WriteFile(filepath.Join(c.dir, "origins.txt"), []byte(fmt.Sprintf("v5_origin_unix_ns=%d\nv9_origin_unix_ns=%d\n", origins["v5"].UnixNano(), origins["v9"].UnixNano())), 0600))
	metrics := reserveMetricsPort(t)
	c.metricsAddress = metrics.Addr().String()
	c.scraper = newOperatorScraper(t, c.metricsAddress)
	configPath := filepath.Join(c.dir, "config.yaml")
	// Exact checked-in bytes: the real env provider supplies only existing
	// ports/endpoints/origins. Reader, pipelines and refresh policy stay intact.
	must(t, os.WriteFile(configPath, readFile(t, "../../distribution/ocb/config.yaml"), 0600))
	runCommand(t, bin, true, "validate", "--config", configPath)
	for _, input := range inputs {
		must(t, input.Close())
	}
	must(t, metrics.Close())
	// Registered before startCollector so its cleanup reaps before log capture.
	t.Cleanup(func() {
		if c.process != nil {
			must(t, os.WriteFile(filepath.Join(c.dir, "collector.log"), []byte(c.process.log.String()), 0600))
		}
	})
	c.process = startCollector(t, bin, configPath)
	waitReady(t, c.process)
	for _, protocol := range []string{"v9", "ipfix"} {
		for i := range 4 {
			out := c.outputs[protocol]
			must(t, out.SetReadDeadline(time.Now().Add(5*time.Second)))
			var packet [65535]byte
			n, _, err := out.ReadFromUDP(packet[:])
			must(t, err)
			c.assertTemplate(t, protocol, packet[:n], i%2)
		}
	}
	return c
}

func (c *operatorLifetimeCollector) assertTemplate(t *testing.T, protocol string, packet []byte, family int) {
	t.Helper()
	want := operatorBootstrapTemplate(t, protocol, family)
	if protocol == "v9" {
		assertTimedV9Packet(t, packet, want, c.v9Sequence, 1, uint32(c.process.started.Unix()), c.origins["v9"])
		c.v9Sequence++
	} else {
		assertPacket(t, protocol, packet, want, 0, 1, 42, uint32(c.process.started.Unix()), c.origins["v9"])
	}
}

// A due template remains valid traffic. Check its full bytes/header/sequence
// while rejecting data, and never extend the 150 ms window when one arrives.
func (c *operatorLifetimeCollector) assertNoData(t *testing.T) {
	t.Helper()
	assertOperatorQuiet(t, c.outputs["v5"])
	for _, protocol := range []string{"v9", "ipfix"} {
		out := c.outputs[protocol]
		must(t, out.SetReadDeadline(time.Now().Add(150*time.Millisecond)))
		for received := 0; ; received++ {
			var packet [65535]byte
			n, _, err := out.ReadFromUDP(packet[:])
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				break
			}
			must(t, err)
			if received >= 8 {
				t.Fatalf("%s exceeded bounded quiet-window template count", protocol)
			}
			header, _ := offsets(protocol)
			if n < header+6 {
				t.Fatalf("truncated %s quiet-window packet: %d", protocol, n)
			}
			family := int(binary.BigEndian.Uint16(packet[header+4:header+6])) - 300
			if family < 0 || family > 1 {
				t.Fatalf("unexpected %s quiet-window template/data packet", protocol)
			}
			c.assertTemplate(t, protocol, packet[:n], family)
			t.Logf("verified due %s template during no-data observation", protocol)
		}
	}
}

func (c *operatorLifetimeCollector) stop(t *testing.T) {
	t.Helper()
	stopCollector(t, c.process)
	assertMetricsPortReleased(t, c.metricsAddress)
	for _, protocol := range []string{"v5", "v9", "ipfix"} {
		assertOperatorQuiet(t, c.outputs[protocol])
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: receiverIP(), Port: c.ports[protocol]})
		must(t, err)
		must(t, conn.Close())
	}
	t.Log("Collector reaped; metrics listener and all three receiver ports released")
}

func TestCollectorOperatorLifetimeQuiet(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	origins := map[string]time.Time{
		"v5": now.Add(-operatorUptimeWindow + time.Hour),
		"v9": now.Add(-operatorUptimeWindow + 2*time.Hour),
	}
	c := startOperatorLifetimeCollector(t, origins)
	c.assertNoData(t)
	initial := c.scraper.poll(t, "quiet-startup", c.dir, func(operatorScrape) bool { return true })
	first := assertOperatorLifetimeProjection(t, initial, origins, 0)
	for id, pair := range first {
		if pair.remaining < 60 || pair.remaining > 86400 {
			t.Fatalf("%s startup margin=%f seconds, want [60,86400]", id, pair.remaining)
		}
	}
	previous := first
	later := c.scraper.poll(t, "quiet-later", c.dir, func(s operatorScrape) bool {
		pairs := assertOperatorLifetimeProjection(t, s, origins, 0)
		changed := true
		for id, pair := range pairs {
			if pair.remaining > previous[id].remaining {
				t.Fatalf("%s quiet countdown increased: %f -> %f", id, previous[id].remaining, pair.remaining)
			}
			changed = changed && pair.remaining < first[id].remaining
		}
		previous = pairs
		return changed // equal adjacent millisecond samples are allowed
	})
	c.assertNoData(t)
	for _, id := range []string{"netflow/v5", "netflow/v9", "netflow/ipfix"} {
		if before, after := initial.accounting(t, id, false), later.accounting(t, id, false); before != (operatorAccounting{}) || after != before {
			t.Fatalf("quiet observations changed record/failure/helper accounting for %s: %+v -> %+v", id, before, after)
		}
	}
	t.Logf("quiet real scrapes: v5 remaining %f -> %f; v9 %f -> %f; exhausted=0, IPFIX absent, no input/data", first["netflow/v5"].remaining, previous["netflow/v5"].remaining, first["netflow/v9"].remaining, previous["netflow/v9"].remaining)
	c.stop(t)
}

// This completion projection requires the failed request's own materialized
// series. The successful-request helper intentionally still requires sent and
// confirmed; neither may be forced to exist for an entirely unsent request.
func (s operatorScrape) exhaustedAccounting(t *testing.T, exporter string) operatorAccounting {
	t.Helper()
	a := s.accounting(t, exporter, false)
	required := map[string]bool{
		"otelcol_netflow_exporter_records/unsent/":    false,
		"otelcol_netflow_exporter_failures//internal": false,
		"otelcol_exporter_send_failed_log_records//":  false,
		"otelcol_exporter_in_flight_requests//":       false,
	}
	for _, sample := range s.samples {
		if sample.labels["exporter"] == exporter {
			key := sample.name + "/" + sample.labels["outcome"] + "/" + sample.labels["reason"]
			if _, ok := required[key]; ok {
				required[key] = true
			}
		}
	}
	for _, present := range required {
		if !present {
			a.inFlight = -1
		}
	}
	return a
}

func expiredOperatorV5Fixture(t *testing.T, origin time.Time, dir string) []byte {
	t.Helper()
	golden := operatorGolden(t, "v5", "canonical-ipv4-v1.bin")
	input := bytes.Clone(golden)
	exported := origin.Add(3 * time.Second)
	binary.BigEndian.PutUint32(input[8:12], uint32(exported.Unix()))
	binary.BigEndian.PutUint32(input[12:16], uint32(exported.Nanosecond()))
	// Independently decode the input header and the fixed record offsets. This
	// proves the request is valid historical input, not a time/map rejection.
	uptime := binary.BigEndian.Uint32(input[4:8])
	seconds := binary.BigEndian.Uint32(input[8:12])
	nanos := binary.BigEndian.Uint32(input[12:16])
	first := binary.BigEndian.Uint32(input[48:52])
	last := binary.BigEndian.Uint32(input[52:56])
	headerTime := time.Unix(int64(seconds), int64(nanos))
	sourceStart := headerTime.Add(-time.Duration(uptime-first) * time.Millisecond)
	sourceEnd := headerTime.Add(-time.Duration(uptime-last) * time.Millisecond)
	if len(input) != 72 || binary.BigEndian.Uint16(input[:2]) != 5 || binary.BigEndian.Uint16(input[2:4]) != 1 ||
		uptime != 3000 || first != 1000 || last != 1001 || !bytes.Equal(input[:8], golden[:8]) || !bytes.Equal(input[16:], golden[16:]) ||
		!headerTime.Equal(exported) || nanos >= 1_000_000_000 || origin.UnixNano()%int64(time.Millisecond) != 0 ||
		sourceStart.UnixNano()%int64(time.Millisecond) != 0 || sourceEnd.UnixNano()%int64(time.Millisecond) != 0 ||
		!sourceStart.Equal(origin.Add(time.Second)) || !sourceEnd.Equal(origin.Add(1001*time.Millisecond)) ||
		sourceStart.Before(origin) || sourceEnd.Before(sourceStart) || sourceEnd.After(headerTime) ||
		sourceEnd.Sub(origin) >= operatorUptimeWindow || time.Since(origin.Add(operatorUptimeWindow)) < 60*time.Second {
		t.Fatalf("invalid expired-v5 derivative: origin=%s header=%s uptime=%d FIRST/LAST=%d/%d source=%s..%s", origin, headerTime, uptime, first, last, sourceStart, sourceEnd)
	}
	must(t, os.WriteFile(filepath.Join(dir, "expired-v5.bin"), input, 0600))
	must(t, os.WriteFile(filepath.Join(dir, "expired-v5.txt"), []byte(fmt.Sprintf("origin_unix_ns=%d\nheader_seconds=%d\nheader_nanoseconds=%d\nuptime_ms=%d\nfirst_ms=%d\nlast_ms=%d\nsource_start_unix_ns=%d\nsource_end_unix_ns=%d\n", origin.UnixNano(), seconds, nanos, uptime, first, last, sourceStart.UnixNano(), sourceEnd.UnixNano())), 0600))
	return input
}

func TestCollectorOperatorLifetimeExhausted(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	origins := map[string]time.Time{
		"v5": now.Add(-operatorUptimeWindow - 60*time.Second),
		"v9": now.Add(-4 * time.Second),
	}
	c := startOperatorLifetimeCollector(t, origins)
	c.assertNoData(t)
	initial := c.scraper.poll(t, "expired-before-input", c.dir, func(operatorScrape) bool { return true })
	assertOperatorLifetimeProjection(t, initial, origins, 0)
	for _, id := range []string{"netflow/v5", "netflow/v9", "netflow/ipfix"} {
		if got := initial.accounting(t, id, false); got != (operatorAccounting{}) {
			t.Fatalf("unexpected pre-input accounting for %s: %+v", id, got)
		}
	}
	input := expiredOperatorV5Fixture(t, origins["v5"], c.dir)
	sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: receiverIP(), Port: c.ports["v5"]})
	must(t, err)
	t.Cleanup(func() { sender.Close() })
	for request := int64(1); request <= 2; request++ {
		must(t, sender.SetWriteDeadline(time.Now().Add(time.Second)))
		n, err := sender.Write(input)
		must(t, err)
		if n != len(input) {
			t.Fatalf("expired v5 short write: %d/%d", n, len(input))
		}
		want := operatorAccounting{unsent: request, failed: request, localFailures: request, internalFailures: request}
		after := c.scraper.poll(t, fmt.Sprintf("expired-request-%d", request), c.dir, func(s operatorScrape) bool {
			// Observable callbacks run before synchronous counter aggregation.
			// A request can finish between them, so wait for a post-latch
			// collection as well as completed request accounting.
			return s.exhaustedAccounting(t, "netflow/v5") == want &&
				operatorLifetimes(t, s)["netflow/v5"].exhausted == 1
		})
		assertOperatorLifetimeProjection(t, after, origins, 1)
		c.assertNoData(t)
		quiet := c.scraper.poll(t, fmt.Sprintf("expired-quiet-%d", request), c.dir, func(operatorScrape) bool { return true })
		assertOperatorLifetimeProjection(t, quiet, origins, 1)
		if got := quiet.exhaustedAccounting(t, "netflow/v5"); got != want {
			t.Fatalf("quiet scrape changed exhausted request accounting: %+v, want %+v", got, want)
		}
		for _, id := range []string{"netflow/v9", "netflow/ipfix"} {
			if got := quiet.accounting(t, id, false); got != initial.accounting(t, id, false) {
				t.Fatalf("v5 failure contaminated %s: %+v", id, got)
			}
		}
		t.Logf("expired v5 request %d: remaining=0 exhausted=1; unsent/internal/helper_failed=%d; in-flight=0, no invalid/rejection/confirmed/sent delta or data", request, request)
	}
	c.stop(t)
}

func TestCollectorOperatorLifetimeFailureParsing(t *testing.T) {
	const data = `# TYPE otelcol_netflow_exporter_failures counter
otelcol_netflow_exporter_failures{exporter="netflow/v5",reason="internal"} 9007199254740993
otelcol_netflow_exporter_failures{exporter="netflow/v5",reason="refresh"} 1
`
	a := parseOperatorScrape(t, []byte(data)).accounting(t, "netflow/v5", false)
	if a.internalFailures != 9007199254740993 || a.localFailures != 9007199254740994 || a.failed != 0 {
		t.Fatalf("local/helper failure accounting lost exactness or reason separation: %+v", a)
	}
	for _, reason := range []string{"uptime", "endpoint", "unknown", "tcp", "192.0.2.1"} {
		if _, err := decodeOperatorScrape([]byte(strings.Replace(data, `reason="internal"`, `reason="`+reason+`"`, 1))); err == nil {
			t.Fatalf("accepted unknown or sensitive failure reason %q", reason)
		}
	}
	// An entirely absent failure/in-flight family must not look completed.
	if got := parseOperatorScrape(t, nil).exhaustedAccounting(t, "netflow/v5"); got.inFlight != -1 {
		t.Fatalf("missing failed-request series appeared complete: %+v", got)
	}
}
