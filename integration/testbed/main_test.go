//go:build linux

package main

import (
	"context"
	"encoding/csv"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	netflowexporter "github.com/pocket-grimoire-guild/otelcol-exporter-netflow"
	"go.opentelemetry.io/collector/confmap"
	"gopkg.in/yaml.v3"
)

func TestConfigForParsesPublicShape(t *testing.T) {
	for name, wantUptime := range map[string]bool{"v5": true, "v9": true, "ipfix": false} {
		t.Run(name, func(t *testing.T) {
			raw := configFor(protocols[name], 4317, 9999, 6060)
			var doc map[string]any
			if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
				t.Fatalf("parse config: %v\n%s", err, raw)
			}
			exporters, ok := doc["exporters"].(map[string]any)
			if !ok {
				t.Fatalf("exporters has type %T", doc["exporters"])
			}
			netflow, ok := exporters["netflow"].(map[string]any)
			if !ok {
				t.Fatalf("netflow exporter has type %T", exporters["netflow"])
			}
			cfg := netflowexporter.NewFactory().CreateDefaultConfig().(*netflowexporter.Config)
			if err := confmap.NewFromStringMap(netflow).Unmarshal(cfg); err != nil {
				t.Fatalf("decode generated exporter config: %v", err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("validate generated exporter config: %v", err)
			}
			for _, key := range []string{"endpoint", "protocol", "schema", "identity", "mapping"} {
				if _, ok := netflow[key]; !ok {
					t.Fatalf("netflow config missing %q: %#v", key, netflow)
				}
			}
			_, hasTemplates := netflow["templates"]
			if name == "v5" && hasTemplates {
				t.Fatal("v5 unexpectedly has templates")
			}
			if name != "v5" && !hasTemplates {
				t.Fatal("template protocol omitted templates")
			}
			_, hasUptime := netflow["uptime_origin"]
			if hasUptime != wantUptime {
				t.Fatalf("uptime_origin present=%v, want=%v", hasUptime, wantUptime)
			}
			if strings.Contains(raw, "\n  templates:") || strings.Contains(raw, "\n  mapping:") {
				t.Fatalf("exporter children are misindented:\n%s", raw)
			}
		})
	}
}

func TestScenarioOptionsRejectUnknownAndNonFixedValues(t *testing.T) {
	for _, tc := range []struct {
		name        string
		records     int
		pacing      time.Duration
		concurrency int
	}{
		{name: "baseline", records: records, pacing: pacing, concurrency: 1},
		{name: "sustained", records: sustainedRecords, pacing: pacing, concurrency: 1},
		{name: "overload", records: overloadRecords, concurrency: overloadWorkers},
		{name: "recovery", records: recoveryRecords, pacing: recoveryPacing, concurrency: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options, err := scenarioOptions(tc.name)
			if err != nil {
				t.Fatalf("scenario rejected: %v", err)
			}
			if options.name != tc.name || options.records != tc.records || options.pacing != tc.pacing || options.concurrency != tc.concurrency {
				t.Fatalf("scenario options=%+v, want name=%q records=%d pacing=%s workers=%d", options, tc.name, tc.records, tc.pacing, tc.concurrency)
			}
			if err := options.validate(); err != nil {
				t.Fatalf("fixed scenario options rejected: %v", err)
			}
		})
	}
	for _, name := range []string{"", "SUSTAINED"} {
		if _, err := scenarioOptions(name); err == nil {
			t.Fatalf("unsupported scenario %q was accepted", name)
		}
	}
	for _, options := range []runOptions{
		{name: "baseline", records: records + 1, pacing: pacing, concurrency: 1},
		{name: "sustained", records: sustainedRecords, pacing: pacing / 2, concurrency: 1},
		{name: "overload", records: overloadRecords + 1, concurrency: overloadWorkers},
		{name: "overload", records: overloadRecords, concurrency: overloadWorkers + 1},
		{name: "recovery", records: recoveryRecords + 1, pacing: recoveryPacing, concurrency: 1},
		{name: "recovery", records: recoveryRecords, pacing: recoveryPacing / 2, concurrency: 1},
	} {
		if err := options.validate(); err == nil {
			t.Fatalf("mutable options were accepted: %+v", options)
		}
	}
}

func TestOverloadAccountingSeparatesFailedOffersAndReorder(t *testing.T) {
	start := time.Unix(1788220803, 0)
	sends := []sendMeasurement{
		{identity: 1, start: start, end: start.Add(10 * time.Millisecond)},
		{identity: 2, start: start.Add(time.Millisecond), end: start.Add(2 * time.Millisecond), failed: true},
		{identity: 3, start: start.Add(2 * time.Millisecond), end: start.Add(3 * time.Millisecond)},
	}
	decoded := []decodedRecord{{identity: 3, frameTime: start.Add(4 * time.Millisecond)}, {identity: 1, frameTime: start.Add(5 * time.Millisecond)}}
	summary, err := overloadAccounting(sends, decoded, 3)
	if err != nil {
		t.Fatalf("overload accounting rejected known partial receipt: %v", err)
	}
	if summary.attempts != 3 || summary.successes != 2 || summary.failures != 1 || summary.received != 2 || summary.missing != 1 || summary.missingSuccess != 0 || summary.receivedFailed != 0 || !summary.reordered {
		t.Fatalf("overload summary=%+v, want separate failure, missing and reorder accounting", summary)
	}
	if summary.offeredWindow != 10*time.Millisecond {
		t.Fatalf("offered window=%s, want 10ms from latest completion", summary.offeredWindow)
	}
	if got := boundedErrorText(errors.New(strings.Repeat("x", overloadErrorCap+20) + "\nline")); len(got) > overloadErrorCap || strings.ContainsAny(got, "\r\n") {
		t.Fatalf("bounded error=%q, want single line <=%d bytes", got, overloadErrorCap)
	}
	if _, err := overloadAccounting(sends, []decodedRecord{{identity: 4}}, 3); err == nil {
		t.Fatal("unknown overload identity was accepted")
	}
	if _, err := overloadAccounting(sends, []decodedRecord{{identity: 1}, {identity: 1}}, 3); err == nil {
		t.Fatal("duplicate overload identity was accepted")
	}
}

func TestWriteOverloadMeasurementsRecordsAllReceiptStates(t *testing.T) {
	start := time.Unix(1788220803, 0)
	packets := []packet{{b: []byte{1}, t: start.Add(10 * time.Millisecond)}, {b: []byte{2}, t: start.Add(20 * time.Millisecond)}}
	sends := []sendMeasurement{
		{identity: 1, start: start, end: start.Add(time.Millisecond)},
		{identity: 2, start: start.Add(time.Millisecond), end: start.Add(2 * time.Millisecond)},
		{identity: 3, start: start.Add(2 * time.Millisecond), end: start.Add(3 * time.Millisecond), failed: true},
		{identity: 4, start: start.Add(3 * time.Millisecond), end: start.Add(4 * time.Millisecond), failed: true, errorText: "failed-missing"},
	}
	decoded := decodeResult{identities: []decodedRecord{
		{identity: 1, frame: 1, frameTime: packets[0].t, frameTimeText: "1788220803.010000000"},
		{identity: 3, frame: 2, frameTime: packets[1].t, frameTimeText: "1788220803.020000000"},
	}}
	path := filepath.Join(t.TempDir(), "overload.csv")
	summary, err := writeOverloadMeasurements(path, sends, packets, decoded, 4)
	if err != nil {
		t.Fatalf("write overload measurements: %v", err)
	}
	if summary.attempts != 4 || summary.successes != 2 || summary.failures != 2 || summary.received != 2 || summary.missing != 2 || summary.missingSuccess != 1 || summary.receivedFailed != 1 {
		t.Fatalf("summary=%+v, want all four receipt states accounted", summary)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil {
		t.Fatalf("parse overload CSV: %v\n%s", err, data)
	}
	if len(rows) != 5 || len(rows[0]) != 11 {
		t.Fatalf("CSV rows/header=%d/%d, want 5/11", len(rows), len(rows[0]))
	}
	want := map[string][2]string{
		"1": {"success", "received"},
		"2": {"success", "missing"},
		"3": {"failure", "received_after_error"},
		"4": {"failure", "not_observed"},
	}
	for _, row := range rows[1:] {
		states, ok := want[row[0]]
		if !ok || row[4] != states[0] || row[6] != states[1] {
			t.Fatalf("CSV state row=%v, want identity/status/receipt=%v", row, want[row[0]])
		}
	}
	if rows[3][5] != "" {
		t.Fatalf("failed empty-error row retained unexpected error text %q", rows[3][5])
	}
}

func TestWriteOverloadMeasurementsRejectsInvalidReceiptEvidence(t *testing.T) {
	start := time.Unix(1788220803, 0)
	newInputs := func(frame int, packetTime, frameTime, sendStart time.Time) ([]sendMeasurement, []packet, decodeResult) {
		return []sendMeasurement{{identity: 1, start: sendStart, end: sendStart.Add(time.Millisecond)}}, []packet{{b: []byte{1}, t: packetTime}}, decodeResult{identities: []decodedRecord{{identity: 1, frame: frame, frameTime: frameTime, frameTimeText: "1788220803.000000000"}}}
	}
	timestampSends, timestampPackets, timestampDecoded := newInputs(1, start, start.Add(3*time.Microsecond), start.Add(-time.Millisecond))
	negativeSends, negativePackets, negativeDecoded := newInputs(1, start, start, start.Add(time.Millisecond))
	frameSends, framePackets, frameDecoded := newInputs(2, start, start, start.Add(-time.Millisecond))
	tests := []struct {
		name    string
		want    string
		sends   []sendMeasurement
		packets []packet
		decoded decodeResult
	}{
		{name: "timestamp mismatch", want: "frame time differs", sends: timestampSends, packets: timestampPackets, decoded: timestampDecoded},
		{name: "negative receipt", want: "receipt precedes send start", sends: negativeSends, packets: negativePackets, decoded: negativeDecoded},
		{name: "out of range frame", want: "outside 1 captured packets", sends: frameSends, packets: framePackets, decoded: frameDecoded},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := writeOverloadMeasurements(filepath.Join(t.TempDir(), "invalid.csv"), tc.sends, tc.packets, tc.decoded, 1)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("invalid evidence accepted or wrong error: %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCanonicalProviderCapsAtLimit(t *testing.T) {
	p := &canonicalProvider{limit: 2}
	var generated atomic.Uint64
	p.SetLoadGeneratorCounters(&generated)
	for i := 0; i < 2; i++ {
		logs, done := p.GenerateLogs()
		if done || logs.LogRecordCount() != 1 {
			t.Fatalf("call %d: done=%v records=%d", i, done, logs.LogRecordCount())
		}
	}
	logs, done := p.GenerateLogs()
	if !done || logs.LogRecordCount() != 0 {
		t.Fatalf("after limit: done=%v records=%d", done, logs.LogRecordCount())
	}
	if generated.Load() != 2 {
		t.Fatalf("Testbed generated counter=%d, want 2", generated.Load())
	}
}

func TestCanonicalProviderUniqueIdentities(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int64
	}{
		{name: "baseline", limit: records},
		{name: "sustained", limit: sustainedRecords},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &canonicalProvider{limit: tc.limit, unique: true}
			for want := 1; want <= int(tc.limit); want++ {
				logs, done := p.GenerateLogs()
				if done || logs.LogRecordCount() != 1 {
					t.Fatalf("record %d: done=%v records=%d", want, done, logs.LogRecordCount())
				}
				value, ok := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes().Get("source.port")
				if !ok || value.Type().String() != "Int" || value.Int() != int64(want) {
					t.Fatalf("record %d source.port=(%v,%v), want %d", want, value, ok, want)
				}
			}
			if _, done := p.GenerateLogs(); !done {
				t.Fatal("unique provider did not stop at fixed record cap")
			}
		})
	}
}

func TestVerifyIdentityOrderRejectsLossDuplicatesAndReorder(t *testing.T) {
	makeRecords := func(values ...int) []decodedRecord {
		got := make([]decodedRecord, 0, len(values))
		for _, value := range values {
			got = append(got, decodedRecord{identity: value})
		}
		return got
	}
	for _, tc := range []struct {
		name string
		got  []decodedRecord
	}{
		{name: "missing", got: makeRecords(1, 2)},
		{name: "missing-compensated-by-unexpected", got: makeRecords(1, 2, 4)},
		{name: "duplicate", got: makeRecords(1, 2, 2)},
		{name: "reordered", got: makeRecords(2, 1, 3)},
		{name: "unexpected-zero", got: makeRecords(0, 1, 2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyIdentityOrder(tc.got, 3); err == nil {
				t.Fatalf("accepted invalid identities: %#v", tc.got)
			}
		})
	}
	if err := verifyIdentityOrder(makeRecords(1, 2, 3), 3); err != nil {
		t.Fatalf("valid identity order rejected: %v", err)
	}
}

func TestParseProcSnapshotsRejectMalformedCounters(t *testing.T) {
	valid := "123 (collector (probe)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15\n"
	user, system, err := parseProcStat(valid)
	if err != nil {
		t.Fatalf("valid /proc stat rejected: %v", err)
	}
	if user != 11 || system != 12 {
		t.Fatalf("/proc CPU counters=(%d,%d), want (11,12)", user, system)
	}
	for _, malformed := range []string{"", "123 collector S", "123 (collector) S 1 2"} {
		if _, _, err := parseProcStat(malformed); err == nil {
			t.Fatalf("malformed /proc stat accepted: %q", malformed)
		}
	}
	if rss, err := parseProcRSS("Name:\tcollector\nVmRSS:\t2048 kB\n"); err != nil || rss != 2048 {
		t.Fatalf("valid VmRSS parsed as (%d,%v)", rss, err)
	}
	for _, malformed := range []string{"", "VmRSS: unknown kB", "VmSize: 2048 kB"} {
		if _, err := parseProcRSS(malformed); err == nil {
			t.Fatalf("malformed VmRSS accepted: %q", malformed)
		}
	}
}

func TestParseProcClockTicks(t *testing.T) {
	if got, err := parseProcClockTicks("100\n"); err != nil || got != 100 {
		t.Fatalf("CLK_TCK parsed as (%d,%v), want 100", got, err)
	}
	for _, malformed := range []string{"", "0", "-1", "100 ticks"} {
		if _, err := parseProcClockTicks(malformed); err == nil {
			t.Fatalf("malformed CLK_TCK accepted: %q", malformed)
		}
	}
}

func TestTimingHelpersRejectInvalidEpochAndSummarize(t *testing.T) {
	if _, err := parseEpoch(""); err == nil {
		t.Fatal("empty TShark epoch accepted")
	}
	if got, err := parseEpoch("1788220803.25"); err != nil || got.UnixNano() != 1788220803250000000 {
		t.Fatalf("epoch parsed as (%s,%v)", got, err)
	}
	stats := summarizeDurations([]time.Duration{5 * time.Millisecond, time.Millisecond, 3 * time.Millisecond, 2 * time.Millisecond})
	if stats.count != 4 || stats.min != time.Millisecond || stats.p50 != 3*time.Millisecond || stats.p95 != 5*time.Millisecond || stats.max != 5*time.Millisecond {
		t.Fatalf("unexpected duration summary: %+v", stats)
	}
	if got := ratePerSecond(100, 2*time.Second); got != 50 {
		t.Fatalf("rate=%v, want 50", got)
	}
	if got := ratePerSecond(100, 0); got != 0 {
		t.Fatalf("zero-window rate=%v, want 0", got)
	}
}

func TestDecodeRejectsNoOpCapture(t *testing.T) {
	if _, err := exec.LookPath(tsharkExecutable()); err != nil {
		t.Fatal("TShark is required for the independent decode test")
	}
	dir := t.TempDir()
	pcap := filepath.Join(dir, "empty.pcap")
	if err := writePCAP(pcap, []packet{{b: []byte{0, 0, 0, 0}}}, 40000, 2055); err != nil {
		t.Fatal(err)
	}
	if result, err := decode(context.Background(), pcap, 2055, 5); err == nil {
		t.Fatalf("no-op capture accepted: %+v", result)
	}
}

func TestDecodeRejectsWrongVersionNonCanonicalAndUnaccountedFrames(t *testing.T) {
	if _, err := exec.LookPath(tsharkExecutable()); err != nil {
		t.Fatal("TShark is required for strict independent decode tests")
	}
	v9IPv4 := filepath.Join("..", "testdata", "pcap", "v9-canonical-ipv4-v1.pcap")
	if _, err := decode(context.Background(), v9IPv4, 2055, 5); err == nil {
		t.Fatal("wrong-version frame was accepted")
	}
	v9IPv6 := filepath.Join("..", "testdata", "pcap", "v9-canonical-ipv6-v1.pcap")
	if _, err := decode(context.Background(), v9IPv6, 2055, 9); err == nil {
		t.Fatal("noncanonical source address was accepted")
	}
	if _, err := decodeExpected(context.Background(), v9IPv4, 2055, 9, 2); err == nil {
		t.Fatal("unaccounted capture frame was accepted")
	}
}

func TestCleanupIsIdempotent(t *testing.T) {
	cap, err := newCapture()
	if err != nil {
		t.Fatal(err)
	}
	first, firstErr := cap.closeCapture()
	second, secondErr := cap.closeCapture()
	if firstErr != secondErr || len(first) != len(second) {
		t.Fatalf("close results differ: first=%v/%d second=%v/%d", firstErr, len(first), secondErr, len(second))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dir := t.TempDir()
	child, err := startChild(ctx, "/bin/true", filepath.Join(dir, "unused"), filepath.Join(dir, "collector.log"))
	if err != nil {
		t.Fatal(err)
	}
	<-child.waitDone
	done := make(chan error, 1)
	go func() {
		_ = child.stopProcess()
		done <- child.stopProcess()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idempotent child cleanup deadlocked")
	}
}

func TestCleanupReportsExitAndForcedKill(t *testing.T) {
	dir := t.TempDir()
	writeScript := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ctx := context.Background()
	exitChild, err := startChild(ctx, writeScript("exit-seven", "exit 7"), filepath.Join(dir, "unused"), filepath.Join(dir, "exit.log"))
	if err != nil {
		t.Fatal(err)
	}
	<-exitChild.waitDone
	if err := exitChild.stopProcess(); err == nil {
		t.Fatal("nonzero child exit was accepted")
	}
	if err := exitChild.stopProcess(); err == nil {
		t.Fatal("nonzero child exit was lost on repeated cleanup")
	}

	termChild, err := startChild(ctx, writeScript("term-seven", "trap 'exit 7' TERM\nwhile sleep 1; do :; done"), filepath.Join(dir, "unused-term"), filepath.Join(dir, "term.log"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := termChild.stopProcess(); err == nil {
		t.Fatal("nonzero child exit after SIGTERM was accepted")
	}

	ignoreChild, err := startChild(ctx, writeScript("ignore-term", "trap '' TERM\nwhile :; do sleep 1; done"), filepath.Join(dir, "unused2"), filepath.Join(dir, "ignore.log"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := ignoreChild.stopProcess(); err == nil {
		t.Fatal("forced process-group kill was not reported")
	}
	if err := ignoreChild.stopProcess(); err == nil {
		t.Fatal("forced cleanup error was lost on repeat")
	}
}

func TestMeasurementsRejectZeroReceiptWindow(t *testing.T) {
	start := time.Unix(1788220803, 0)
	sends := make([]sendMeasurement, records)
	decoded := decodeResult{}
	receipt := start.Add(time.Millisecond)
	for i := range sends {
		sends[i] = sendMeasurement{identity: i + 1, start: start, end: receipt}
		decoded.identities = append(decoded.identities, decodedRecord{identity: i + 1, frame: 1, frameTime: receipt})
	}
	_, _, _, _, err := writeMeasurements(filepath.Join(t.TempDir(), "measurements.csv"), sends, []packet{{t: receipt}}, decoded, records)
	if err == nil || !strings.Contains(err.Error(), "windows must be positive") {
		t.Fatalf("zero receipt span accepted or wrong failure: %v", err)
	}
}

func TestMeasurementsSupportSustainedRecordCount(t *testing.T) {
	start := time.Unix(1788220803, 0)
	sends := make([]sendMeasurement, sustainedRecords)
	packets := make([]packet, sustainedRecords)
	decoded := decodeResult{identities: make([]decodedRecord, 0, sustainedRecords)}
	for i := 0; i < sustainedRecords; i++ {
		sendStart := start.Add(time.Duration(i) * 2 * time.Millisecond)
		sendEnd := sendStart.Add(time.Microsecond)
		receipt := start.Add(time.Duration(i+1) * 2 * time.Millisecond)
		sends[i] = sendMeasurement{identity: i + 1, start: sendStart, end: sendEnd}
		packets[i] = packet{t: receipt}
		decoded.identities = append(decoded.identities, decodedRecord{identity: i + 1, frame: i + 1, frameTime: receipt, frameTimeText: "1788220803.000000000"})
	}
	path := filepath.Join(t.TempDir(), "measurements.csv")
	callStats, latencyStats, offeredWindow, receiptWindow, err := writeMeasurements(path, sends, packets, decoded, sustainedRecords)
	if err != nil {
		t.Fatalf("sustained measurements rejected: %v", err)
	}
	if callStats.count != sustainedRecords || latencyStats.count != sustainedRecords || offeredWindow <= 0 || receiptWindow <= 0 {
		t.Fatalf("sustained measurements summary=%+v/%+v offered=%s receipt=%s", callStats, latencyStats, offeredWindow, receiptWindow)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(string(data), "\n"); lines != sustainedRecords+1 {
		t.Fatalf("measurement lines=%d, want %d", lines, sustainedRecords+1)
	}
	shortPath := filepath.Join(t.TempDir(), "short-measurements.csv")
	if _, _, _, _, err := writeMeasurements(shortPath, sends[:records], packets[:records], decodeResult{identities: decoded.identities[:records]}, sustainedRecords); err == nil || !strings.Contains(err.Error(), "send measurement count") {
		t.Fatalf("short sustained measurement set accepted or wrong failure: %v", err)
	}
}

func TestDecodeRejectsUnknownSetBesideTemplate(t *testing.T) {
	// Deliberately controlled oracle output tests parser rejection, not wire interoperability.
	dir := t.TempDir()
	oracle := filepath.Join(dir, "oracle")
	if err := os.WriteFile(oracle, []byte("#!/bin/sh\nprintf '1|9|0,999|300|||1788220803.000000000\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TSHARK_BIN", oracle)
	if _, err := decodeExpected(context.Background(), "unused", 2055, 9, 1); err == nil || !strings.Contains(err.Error(), "unexpected flowset") {
		t.Fatalf("unknown set alongside template accepted or wrong failure: %v", err)
	}
}
