//go:build linux

package main

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	netflowexporter "github.com/pocket-grimoire-guild/otelcol-exporter-netflow"
	"go.opentelemetry.io/collector/confmap"
	"gopkg.in/yaml.v3"
)

func TestRecoveryConfigEnablesPinnedTelemetryAndRefresh(t *testing.T) {
	for name := range protocols {
		t.Run(name, func(t *testing.T) {
			config, err := recoveryConfigFor(protocols[name], 4317, 9999, 6060, 7070)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(config, "level: detailed") || !strings.Contains(config, "port: 7070") {
				t.Fatalf("recovery config lacks Prometheus pull reader:\n%s", config)
			}
			switch name {
			case "v5":
				if strings.Contains(config, "template_refresh_packets") || strings.Contains(config, "template_refresh_data_packets") {
					t.Fatal("v5 unexpectedly has a template refresh count")
				}
			case "v9":
				if !strings.Contains(config, "template_refresh_packets: 20") {
					t.Fatal("v9 omitted packet-count refresh")
				}
			case "ipfix":
				if !strings.Contains(config, "template_refresh_data_packets: 20") {
					t.Fatal("IPFIX omitted data-message refresh")
				}
			}
		})
	}
}

func TestRecoveryConfigUnmarshalsAndValidatesRefreshThreshold(t *testing.T) {
	for name, p := range protocols {
		t.Run(name, func(t *testing.T) {
			raw, err := recoveryConfigFor(p, 4317, 9999, 6060, 7070)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := yaml.Unmarshal([]byte(raw), &document); err != nil {
				t.Fatalf("parse generated recovery config: %v", err)
			}
			exporters, ok := document["exporters"].(map[string]any)
			if !ok {
				t.Fatalf("exporters type=%T", document["exporters"])
			}
			netflow, ok := exporters["netflow"].(map[string]any)
			if !ok {
				t.Fatalf("netflow exporter type=%T", exporters["netflow"])
			}
			cfg := netflowexporter.NewFactory().CreateDefaultConfig().(*netflowexporter.Config)
			if err := confmap.NewFromStringMap(netflow).Unmarshal(cfg); err != nil {
				t.Fatalf("unmarshal recovery exporter config: %v", err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("validate recovery exporter config: %v", err)
			}
			switch name {
			case "v9":
				if cfg.NetFlowV9.TemplateRefreshPackets == nil || *cfg.NetFlowV9.TemplateRefreshPackets != recoveryTemplateRefreshCount {
					t.Fatalf("v9 refresh threshold=%v, want %d", cfg.NetFlowV9.TemplateRefreshPackets, recoveryTemplateRefreshCount)
				}
			case "ipfix":
				if cfg.IPFIX.TemplateRefreshDataPackets == nil || *cfg.IPFIX.TemplateRefreshDataPackets != recoveryTemplateRefreshCount {
					t.Fatalf("IPFIX refresh threshold=%v, want %d", cfg.IPFIX.TemplateRefreshDataPackets, recoveryTemplateRefreshCount)
				}
			case "v5":
				if cfg.NetFlowV9.TemplateRefreshPackets != nil || cfg.IPFIX.TemplateRefreshDataPackets != nil {
					t.Fatal("v5 unexpectedly decoded a template refresh threshold")
				}
			}
		})
	}
}

func TestParseRecoveryMetricsAcceptsActiveSeriesAndZeroAbsence(t *testing.T) {
	text := strings.Join([]string{
		`# TYPE otelcol_netflow_exporter_records counter`,
		`otelcol_netflow_exporter_admission{exporter="netflow",reason="accepted"} 12`,
		`otelcol_netflow_exporter_endpoint_epochs{exporter="netflow"} 1`,
		`otelcol_netflow_exporter_records{exporter="netflow",outcome="confirmed"} 9`,
		`otelcol_netflow_exporter_data_messages{exporter="netflow",outcome="confirmed"} 5`,
		`otelcol_netflow_exporter_templates{exporter="netflow",message_kind="bootstrap",outcome="confirmed"} 4`,
	}, "\n")
	got, err := parseRecoveryMetrics(text)
	if err != nil {
		t.Fatalf("parse active telemetry: %v", err)
	}
	if got.admissionAccepted != 12 || got.records["confirmed"] != 9 || got.dataMessages["confirmed"] != 5 {
		t.Fatalf("telemetry=%+v, want active series", got)
	}
	if got.records["ambiguous"] != 0 || got.records["unsent"] != 0 || got.templates["refresh"] != 0 {
		t.Fatalf("missing conditional series were not treated as zero: %+v", got)
	}
}

func TestParseRecoveryMetricsRejectsMalformedOrWrongLabels(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{name: "unquoted", text: `otelcol_netflow_exporter_records{exporter=netflow,outcome="confirmed"} 1`},
		{name: "duplicate", text: strings.Join([]string{
			`otelcol_netflow_exporter_admission{exporter="netflow",reason="accepted"} 1`,
			`otelcol_netflow_exporter_admission{exporter="netflow",reason="accepted"} 1`,
		}, "\n")},
		{name: "wrong exporter", text: strings.Join([]string{
			`otelcol_netflow_exporter_admission{exporter="other",reason="accepted"} 1`,
			`otelcol_netflow_exporter_records{exporter="netflow",outcome="confirmed"} 1`,
			`otelcol_netflow_exporter_data_messages{exporter="netflow",outcome="confirmed"} 1`,
		}, "\n")},
		{name: "negative", text: strings.Join([]string{
			`otelcol_netflow_exporter_admission{exporter="netflow",reason="accepted"} -1`,
			`otelcol_netflow_exporter_records{exporter="netflow",outcome="confirmed"} 1`,
			`otelcol_netflow_exporter_data_messages{exporter="netflow",outcome="confirmed"} 1`,
		}, "\n")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseRecoveryMetrics(tc.text); err == nil {
				t.Fatal("malformed telemetry was accepted")
			}
		})
	}
}

func TestVerifyIdentityRangeRejectsMissingDuplicateOrOutOfRange(t *testing.T) {
	valid := []decodedRecord{{identity: 7}, {identity: 8}, {identity: 9}}
	if err := verifyIdentityRange(valid, 7, 9); err != nil {
		t.Fatalf("valid identity range rejected: %v", err)
	}
	for _, records := range [][]decodedRecord{
		{{identity: 7}, {identity: 9}},
		{{identity: 7}, {identity: 7}, {identity: 9}},
		{{identity: 6}, {identity: 8}, {identity: 9}},
	} {
		if err := verifyIdentityRange(records, 7, 9); err == nil {
			t.Fatalf("invalid identity range accepted: %+v", records)
		}
	}
}

func resumedFieldLine(p protocol, frame int, flowsets, templates, sources, ports, epoch string) string {
	return fmt.Sprintf("%d|%d|%s|%s|%s|%s|%s", frame, p.version, flowsets, templates, sources, ports, epoch)
}

func validResumedFieldText(p protocol) string {
	templateSet := "0"
	if p.version == 10 {
		templateSet = "2"
	}
	return strings.Join([]string{
		resumedFieldLine(p, 1, templateSet, "301", "", "", "1788220803.001000000"),
		resumedFieldLine(p, 2, "300", "", "", "", "1788220803.002000000"),
		resumedFieldLine(p, 3, templateSet, "300", "", "", "1788220803.003000000"),
		resumedFieldLine(p, 4, "300", "", "192.0.2.1", "8", "1788220803.004000000"),
		resumedFieldLine(p, 5, templateSet, "301", "", "", "1788220803.005000000"),
		resumedFieldLine(p, 6, "300", "", "192.0.2.1", "9", "1788220803.006000000"),
	}, "\n")
}

func TestParseResumedFreshFieldsAcceptsIndependentTemplate301(t *testing.T) {
	for _, name := range []string{"v9", "ipfix"} {
		t.Run(name, func(t *testing.T) {
			got, pre, err := parseResumedFreshFields(validResumedFieldText(protocols[name]), protocols[name], 6)
			if err != nil {
				t.Fatalf("valid resumed transition rejected: %v", err)
			}
			if got.records != 2 || got.templates != 3 || !got.template300 || got.firstTempl != 1 || got.lastTempl != 5 || len(pre) != 1 || pre[0] != 2 {
				t.Fatalf("resumed result=%+v pre=%v, want separate 301 and 300 transitions", got, pre)
			}
			if len(got.identities) != 2 || got.identities[0].identity != 8 || got.identities[1].identity != 9 {
				t.Fatalf("decoded identities=%+v, want 8,9", got.identities)
			}
		})
	}
}

func TestParseResumedFreshFieldsRejectsStrictTransitionControls(t *testing.T) {
	for _, name := range []string{"v9", "ipfix"} {
		p := protocols[name]
		set := "0"
		if p.version == 10 {
			set = "2"
		}
		cases := []struct {
			name string
			text string
			want int
		}{
			{name: "missing template300", text: strings.Join([]string{
				resumedFieldLine(p, 1, set, "301", "", "", "1788220803.001"),
				resumedFieldLine(p, 2, "300", "", "", "", "1788220803.002"),
			}, "\n"), want: 0},
			{name: "data after 301 only", text: strings.Join([]string{
				resumedFieldLine(p, 1, set, "301", "", "", "1788220803.001"),
				resumedFieldLine(p, 2, "300", "", "192.0.2.1", "8", "1788220803.002"),
			}, "\n"), want: 0},
			{name: "mixed template and data sets", text: strings.Join([]string{
				resumedFieldLine(p, 1, set+",300", "300", "", "", "1788220803.001"),
			}, "\n"), want: 1},
			{name: "unexpected flowset", text: resumedFieldLine(p, 1, "999", "", "", "", "1788220803.001"), want: 1},
			{name: "unexpected template id", text: resumedFieldLine(p, 1, set, "302", "", "", "1788220803.001"), want: 1},
			{name: "template id without template set", text: resumedFieldLine(p, 1, "300", "301", "", "", "1788220803.001"), want: 1},
			{name: "source and port mismatch", text: strings.Join([]string{
				resumedFieldLine(p, 1, set, "300", "", "", "1788220803.001"),
				resumedFieldLine(p, 2, "300", "", "192.0.2.1,192.0.2.1", "8", "1788220803.002"),
			}, "\n"), want: 2},
			{name: "post data without pre data", text: strings.Join([]string{
				resumedFieldLine(p, 1, set, "300", "", "", "1788220803.001"),
				resumedFieldLine(p, 2, "300", "", "192.0.2.1", "8", "1788220803.002"),
			}, "\n"), want: 2},
			{name: "no post data", text: strings.Join([]string{
				resumedFieldLine(p, 1, set, "301", "", "", "1788220803.001"),
				resumedFieldLine(p, 2, "300", "", "", "", "1788220803.002"),
				resumedFieldLine(p, 3, set, "300", "", "", "1788220803.003"),
			}, "\n"), want: 3},
		}
		for _, tc := range cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				if _, _, err := parseResumedFreshFields(tc.text, p, tc.want); err == nil {
					t.Fatal("invalid resumed transition was accepted")
				}
			})
		}
	}
}

func TestParseResumedFreshFieldsRejectsFrameAccountingControls(t *testing.T) {
	p := protocols["v9"]
	valid := validResumedFieldText(p)
	for _, tc := range []struct {
		name          string
		text          string
		expectedFrame int
	}{
		{name: "missing frame", text: strings.Join(strings.Split(valid, "\n")[:5], "\n"), expectedFrame: 6},
		{name: "extra frame", text: valid + "\n" + resumedFieldLine(p, 7, "300", "", "192.0.2.1", "10", "1788220803.007"), expectedFrame: 6},
		{name: "out of order", text: strings.Replace(valid, "1|9|", "2|9|", 1), expectedFrame: 6},
		{name: "duplicate frame", text: valid + "\n" + strings.Split(valid, "\n")[5], expectedFrame: 7},
		{name: "short fields", text: "1|9|0|301|||", expectedFrame: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseResumedFreshFields(tc.text, p, tc.expectedFrame); err == nil {
				t.Fatal("invalid frame accounting was accepted")
			}
		})
	}
}

func TestRecoveryOracleRejectsUnknownDuplicateAndMultiRecordFrames(t *testing.T) {
	oracle := map[int]decodedRecord{
		1: {frame: 4, identity: 8},
		2: {frame: 5, identity: 9},
		3: {frame: 6, identity: 10},
	}
	valid := decodeResult{identities: []decodedRecord{{frame: 2, identity: 9}, {frame: 3, identity: 10}}}
	if err := compareFreshResumedToOracle(valid, []int{1}, oracle, 9); err != nil {
		t.Fatalf("valid oracle partition rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		got  []decodedRecord
	}{
		{name: "unknown identity", got: []decodedRecord{{frame: 2, identity: 11}, {frame: 3, identity: 10}}},
		{name: "duplicate identity", got: []decodedRecord{{frame: 2, identity: 9}, {frame: 3, identity: 9}}},
		{name: "multiple records in one frame", got: []decodedRecord{{frame: 2, identity: 9}, {frame: 2, identity: 10}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := compareFreshResumedToOracle(decodeResult{identities: tc.got}, []int{1}, oracle, 9); err == nil {
				t.Fatal("invalid oracle partition was accepted")
			}
		})
	}
	if err := compareFreshResumedToOracle(valid, []int{1, 1}, oracle, 9); err == nil {
		t.Fatal("duplicate pre-template frame was accepted")
	}

	combined := decodeResult{records: 5, identities: []decodedRecord{
		{frame: 1, identity: 1}, {frame: 2, identity: 2}, {frame: 3, identity: 3},
		{frame: 4, identity: 7}, {frame: 5, identity: 8},
	}}
	byIdentity, byFrame, err := verifyCombinedRecovery(combined, 3)
	if err != nil || len(byIdentity) != 5 || len(byFrame) != 2 || byFrame[1].identity != 7 || byFrame[2].identity != 8 {
		t.Fatalf("valid combined accounting=(%v,%v,%v)", byIdentity, byFrame, err)
	}
	for _, tc := range []struct {
		name string
		got  []decodedRecord
	}{
		{name: "duplicate identity", got: []decodedRecord{{frame: 1, identity: 1}, {frame: 2, identity: 2}, {frame: 3, identity: 3}, {frame: 4, identity: 7}, {frame: 5, identity: 7}}},
		{name: "multiple records in one frame", got: []decodedRecord{{frame: 1, identity: 1}, {frame: 2, identity: 2}, {frame: 3, identity: 3}, {frame: 4, identity: 7}, {frame: 4, identity: 8}}},
		{name: "unknown identity", got: []decodedRecord{{frame: 1, identity: 1}, {frame: 2, identity: 2}, {frame: 3, identity: 3}, {frame: 4, identity: 4}, {frame: 5, identity: 8}}},
	} {
		t.Run("combined/"+tc.name, func(t *testing.T) {
			if _, _, err := verifyCombinedRecovery(decodeResult{records: len(tc.got), identities: tc.got}, 3); err == nil {
				t.Fatal("invalid combined accounting was accepted")
			}
		})
	}
}

func TestPrometheusRecoveryParsingIsExactAndPreservesPairs(t *testing.T) {
	text := strings.Join([]string{
		`otelcol_netflow_exporter_admission{reason="accepted",exporter="netflow"} 4`,
		`otelcol_netflow_exporter_endpoint_epochs{exporter="netflow"} 1`,
		`otelcol_netflow_exporter_records{exporter="netflow",outcome="confirmed"} 2`,
		`otelcol_netflow_exporter_records{exporter="netflow",outcome="ambiguous"} 1`,
		`otelcol_netflow_exporter_records{exporter="netflow",outcome="unsent"} 1`,
		`otelcol_netflow_exporter_records{exporter="netflow",outcome="invalid"} 0`,
		`otelcol_netflow_exporter_data_messages{exporter="netflow",outcome="confirmed"} 2`,
		`otelcol_netflow_exporter_data_messages{exporter="netflow",outcome="ambiguous"} 1`,
		`otelcol_netflow_exporter_templates{exporter="netflow",message_kind="bootstrap",outcome="confirmed"} 3`,
		`otelcol_netflow_exporter_templates{exporter="netflow",message_kind="bootstrap",outcome="ambiguous"} 0`,
		`otelcol_netflow_exporter_templates{exporter="netflow",message_kind="refresh",outcome="confirmed"} 4`,
		`otelcol_netflow_exporter_templates{exporter="netflow",message_kind="refresh",outcome="ambiguous"} 0`,
		`otelcol_netflow_exporter_bytes{exporter="netflow",message_kind="data",outcome="confirmed"} 300`,
		`otelcol_netflow_exporter_bytes{exporter="netflow",message_kind="data",outcome="ambiguous"} 20`,
		`otelcol_netflow_exporter_losses{exporter="netflow",loss_class="canonical_source"} 7`,
		`otelcol_netflow_exporter_losses{exporter="netflow",loss_class="exporter"} 8`,
		`unrelated_fractional_metric{kind="test"} 0.25`,
		`otelcol_netflow_exporter_uptime_remaining{exporter="netflow"} 2.570207181e+06`,
	}, "\n")
	got, err := parseRecoveryMetrics(text)
	if err != nil {
		t.Fatalf("valid recovery metrics rejected: %v", err)
	}
	if got.records["confirmed"] != 2 || got.records["ambiguous"] != 1 || got.dataMessages["ambiguous"] != 1 || got.templates["bootstrap/ambiguous"] != 0 || got.bytes["data/ambiguous"] != 20 || got.losses["canonical_source"] != 7 {
		t.Fatalf("parsed recovery pairs/losses=%+v, want exact values", got)
	}
	var report strings.Builder
	appendRecoveryMetricMap(&report, "exporter_records", got.records, false)
	appendRecoveryMetricMap(&report, "exporter_templates", got.templates, true)
	appendRecoveryMetricMap(&report, "exporter_losses", got.losses, false)
	reportText := report.String()
	for _, want := range []string{
		"exporter_records_confirmed=2", "exporter_records_unsent=1", "exporter_records_invalid=0",
		"exporter_templates_bootstrap_ambiguous=0", "exporter_templates_refresh_ambiguous=0",
		"exporter_losses_canonical_source=7", "exporter_losses_exporter=8",
	} {
		if !strings.Contains(reportText, want) {
			t.Fatalf("report omitted %q:\n%s", want, reportText)
		}
	}
}

func TestPrometheusRecoveryParsingRejectsSemanticDuplicatesAndBadIntegers(t *testing.T) {
	duplicate := strings.Join([]string{
		`otelcol_netflow_exporter_admission{exporter="netflow",reason="accepted"} 1`,
		`otelcol_netflow_exporter_admission{reason="accepted",exporter="netflow"} 1`,
	}, "\n")
	if _, err := parsePrometheusMetrics(duplicate); err == nil {
		t.Fatal("duplicate samples with reordered labels were accepted")
	}
	for _, value := range []string{"9223372036854775808", "1.5", "NaN", "+Inf", "-Inf"} {
		t.Run(value, func(t *testing.T) {
			line := fmt.Sprintf(`otelcol_netflow_exporter_records{exporter="netflow",outcome="confirmed"} %s`, value)
			if _, err := parsePrometheusMetrics(line); err == nil {
				t.Fatalf("invalid target integer %q was accepted", value)
			}
		})
	}
	if _, err := parsePrometheusMetrics("unrelated_fractional_metric 0.125\n"); err != nil {
		t.Fatalf("unrelated fractional metric rejected: %v", err)
	}
	for _, value := range []string{"-0.1", "NaN", "+Inf", "-Inf", "not-a-number"} {
		if _, err := parsePrometheusMetrics("otelcol_netflow_exporter_uptime_remaining " + value + "\n"); err == nil {
			t.Fatalf("invalid uptime gauge %q accepted", value)
		}
	}
	zeroEndpoint := strings.Join([]string{
		`otelcol_netflow_exporter_admission{exporter="netflow",reason="accepted"} 1`,
		`otelcol_netflow_exporter_endpoint_epochs{exporter="netflow"} 0`,
		`otelcol_netflow_exporter_endpoint_epochs{exporter="netflow"} 0`,
		`otelcol_netflow_exporter_records{exporter="netflow",outcome="confirmed"} 1`,
		`otelcol_netflow_exporter_data_messages{exporter="netflow",outcome="confirmed"} 1`,
	}, "\n")
	if _, err := parseRecoveryMetrics(zeroEndpoint); err == nil {
		t.Fatal("duplicate zero endpoint series was accepted")
	}
}

func validRecoveryTelemetryForTest() (recoveryTelemetry, []recoveryMeasurement) {
	start := time.Unix(1788220803, 0)
	sends := []recoveryMeasurement{
		{sendMeasurement: sendMeasurement{identity: 1, start: start, end: start.Add(time.Millisecond)}},
		{sendMeasurement: sendMeasurement{identity: 2, start: start.Add(time.Millisecond), end: start.Add(2 * time.Millisecond)}},
		{sendMeasurement: sendMeasurement{identity: 3, start: start.Add(2 * time.Millisecond), end: start.Add(3 * time.Millisecond), failed: true}},
		{sendMeasurement: sendMeasurement{identity: 4, start: start.Add(3 * time.Millisecond), end: start.Add(4 * time.Millisecond), failed: true}},
	}
	telemetry := recoveryTelemetry{
		admissionAccepted: 4, endpointEpochs: 1,
		records:      map[string]int64{"confirmed": 2, "ambiguous": 1, "unsent": 1, "invalid": 0},
		dataMessages: map[string]int64{"confirmed": 2, "ambiguous": 1},
		templates:    map[string]int64{}, failures: map[string]int64{}, bytes: map[string]int64{"data/confirmed": 144, "data/ambiguous": 72}, losses: map[string]int64{},
	}
	return telemetry, sends
}

func TestValidateRecoveryTelemetryChecksEveryEquationAndControl(t *testing.T) {
	telemetry, sends := validRecoveryTelemetryForTest()
	if remaining, err := validateRecoveryTelemetry(telemetry, sends); err != nil || remaining != 0 {
		t.Fatalf("valid telemetry=(%d,%v)", remaining, err)
	}
	busyTelemetry, busySends := validRecoveryTelemetryForTest()
	busyTelemetry.admissionAccepted = 3
	busyTelemetry.admissionBusy = 1
	busyTelemetry.records["unsent"] = 0
	busyTelemetry.failures["busy"] = 1
	if remaining, err := validateRecoveryTelemetry(busyTelemetry, busySends); err != nil || remaining != 0 {
		t.Fatalf("valid nonaccepted admission telemetry=(%d,%v)", remaining, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*recoveryTelemetry, []recoveryMeasurement)
	}{
		{name: "missing active bytes", mutate: func(t *recoveryTelemetry, _ []recoveryMeasurement) { delete(t.bytes, "data/confirmed") }},
		{name: "bytes without template messages", mutate: func(t *recoveryTelemetry, _ []recoveryMeasurement) { t.bytes["refresh/confirmed"] = 72 }},
		{name: "template messages without bytes", mutate: func(t *recoveryTelemetry, _ []recoveryMeasurement) { t.templates["bootstrap/confirmed"] = 2 }},
		{name: "fewer bytes than messages", mutate: func(t *recoveryTelemetry, _ []recoveryMeasurement) { t.bytes["data/confirmed"] = 1 }},
		{name: "admission equation", mutate: func(t *recoveryTelemetry, _ []recoveryMeasurement) { t.admissionAccepted = 3 }},
		{name: "record equation", mutate: func(t *recoveryTelemetry, _ []recoveryMeasurement) { t.records["unsent"] = 0 }},
		{name: "data pair equation", mutate: func(t *recoveryTelemetry, _ []recoveryMeasurement) { t.dataMessages["ambiguous"] = 0 }},
		{name: "success equation", mutate: func(t *recoveryTelemetry, _ []recoveryMeasurement) { t.records["confirmed"] = 1 }},
		{name: "impossible invalid", mutate: func(t *recoveryTelemetry, _ []recoveryMeasurement) { t.records["invalid"] = 1 }},
		{name: "impossible internal", mutate: func(t *recoveryTelemetry, _ []recoveryMeasurement) { t.failures["internal"] = 1 }},
		{name: "busy failure pair", mutate: func(t *recoveryTelemetry, _ []recoveryMeasurement) { t.admissionAccepted = 3; t.admissionBusy = 1 }},
		{name: "negative count", mutate: func(t *recoveryTelemetry, _ []recoveryMeasurement) { t.losses["exporter"] = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate, candidateSends := validRecoveryTelemetryForTest()
			tc.mutate(&candidate, candidateSends)
			if _, err := validateRecoveryTelemetry(candidate, candidateSends); err == nil {
				t.Fatal("inconsistent recovery telemetry was accepted")
			}
		})
	}
}

func TestSummarizeRecoveryReceiptsSeparatesOutageOffers(t *testing.T) {
	start := time.Unix(1788220803, 0)
	sends := []recoveryMeasurement{
		{sendMeasurement: sendMeasurement{identity: 1, start: start, end: start.Add(time.Millisecond)}, phase: "warm"},
		{sendMeasurement: sendMeasurement{identity: 2, start: start.Add(time.Millisecond), end: start.Add(2 * time.Millisecond)}, phase: "outage"},
		{sendMeasurement: sendMeasurement{identity: 3, start: start.Add(2 * time.Millisecond), end: start.Add(3 * time.Millisecond), failed: true}, phase: "outage"},
		{sendMeasurement: sendMeasurement{identity: 7, start: start.Add(3 * time.Millisecond), end: start.Add(4 * time.Millisecond), failed: true}, phase: "resumed"},
		{sendMeasurement: sendMeasurement{identity: 8, start: start.Add(4 * time.Millisecond), end: start.Add(5 * time.Millisecond)}, phase: "resumed"},
	}
	packets := []packet{{b: []byte{1}, t: start.Add(10 * time.Millisecond)}, {b: []byte{2}, t: start.Add(20 * time.Millisecond)}}
	decoded := map[int]decodedRecord{1: {identity: 1, frame: 1}, 8: {identity: 8, frame: 2}}
	summary, err := summarizeRecoveryReceipts(sends, decoded, packets)
	if err != nil {
		t.Fatal(err)
	}
	if summary.received != 2 || summary.receivedFailed != 0 || summary.missingSuccess != 0 || summary.missingFailed != 1 || summary.outageSuccess != 1 || summary.outageFailed != 1 {
		t.Fatalf("receipt summary=%+v, want active missing and outage offers separated", summary)
	}
	if summary.outageUnobservedSuccess != 1 || summary.outageUnobservedFailed != 1 {
		t.Fatalf("receipt summary=%+v, want outage observation counts", summary)
	}
}

type literalRecoveryEvent struct {
	header    recoveryHeader
	timestamp time.Time
	identity  int
}

type literalRecoveryFixture struct {
	p           protocol
	sends       []recoveryMeasurement
	telemetry   recoveryTelemetry
	combined    decodeResult
	warm        []recoveryHeader
	headers     []recoveryHeader
	fresh       []recoveryHeader
	preFrames   []int
	warmFrames  int
	totalFrames int
	captureEnd  time.Time
}

func literalRecoveryTimestamp(t time.Time) string {
	return fmt.Sprintf("%d.%09d", t.Unix(), t.Nanosecond())
}

func literalRecoverySends(outageSuccesses int) []recoveryMeasurement {
	base := time.Unix(1788220803, 0)
	sends := make([]recoveryMeasurement, 0, recoveryRecords)
	for identity := 1; identity <= recoveryRecords; identity++ {
		phase, epoch := "resumed", 2
		if identity <= recoveryWarmRecords {
			phase, epoch = "warm", 1
		} else if identity <= recoveryWarmRecords+recoveryOutageRecords {
			phase, epoch = "outage", 0
		}
		failed := phase == "outage" && identity > recoveryWarmRecords+outageSuccesses
		start := base.Add(time.Duration(identity-1) * time.Second)
		sends = append(sends, recoveryMeasurement{
			sendMeasurement: sendMeasurement{
				identity: identity,
				start:    start,
				end:      start.Add(100 * time.Millisecond),
				failed:   failed,
				errorText: func() string {
					if failed {
						return "receiver socket closed"
					}
					return ""
				}(),
			},
			phase: phase,
			epoch: epoch,
		})
	}
	return sends
}

func literalHeaderFor(p protocol, frame int, sequence uint32, templateID int) recoveryHeader {
	h := recoveryHeader{Frame: frame, Sequence: sequence}
	switch p.version {
	case 5:
		h.EngineType, h.EngineID = 0, 0
	case 9:
		h.SourceID = 42
	case 10:
		h.DomainID = 42
	}
	h.TemplateID = templateID
	return h
}

func literalHeaderFields(p protocol, frame int, sequence uint32, templateID int, identity int, timestamp time.Time) string {
	fields := []string{strconv.Itoa(frame), strconv.Itoa(p.version), strconv.FormatUint(uint64(sequence), 10), "", "", "", "", "", ""}
	if p.version == 5 {
		fields[3], fields[4] = "0", "0"
	} else if p.version == 9 {
		fields[5] = "42"
	} else {
		fields[6] = "42"
	}
	if templateID != 0 {
		if p.version == 10 {
			fields[7] = "2"
		} else {
			fields[7] = "0"
		}
		fields[8] = strconv.Itoa(templateID)
	} else if p.version != 5 {
		fields[7] = "300"
	}
	return strings.Join(fields, "|")
}

func literalRecordFields(p protocol, event literalRecoveryEvent) string {
	flowset, source, port := "", "192.0.2.1", strconv.Itoa(event.identity)
	if p.version != 5 {
		flowset = "300"
	}
	if event.header.TemplateID != 0 {
		if p.version == 10 {
			flowset = "2"
		} else {
			flowset = "0"
		}
		source, port = "", ""
	}
	return strings.Join([]string{
		strconv.Itoa(event.header.Frame), strconv.Itoa(p.version), flowset,
		func() string {
			if event.header.TemplateID == 0 {
				return ""
			}
			return strconv.Itoa(event.header.TemplateID)
		}(), source, port, literalRecoveryTimestamp(event.timestamp),
	}, "|")
}

func literalDataSequence(p protocol, priorCommits int) uint32 {
	sequence := uint32(priorCommits)
	if p.version == 9 {
		sequence += uint32(4 + 2*(priorCommits/recoveryTemplateRefreshCount))
	}
	return sequence
}

func literalRefreshSequence(p protocol, commits, round int) uint32 {
	sequence := uint32(commits)
	if p.version == 9 {
		sequence += uint32(4 + 2*(round-1))
	}
	return sequence
}

func makeLiteralRecoveryFixture(p protocol, outageSuccesses int) literalRecoveryFixture {
	sends := literalRecoverySends(outageSuccesses)
	fixture := literalRecoveryFixture{p: p, sends: sends}
	events := make([]literalRecoveryEvent, 0, recoveryFrameCap)
	commits := 0
	add := func(templateID, identity int, timestamp time.Time, sequence uint32) {
		frame := len(events) + 1
		event := literalRecoveryEvent{
			header:    literalHeaderFor(p, frame, sequence, templateID),
			timestamp: timestamp,
			identity:  identity,
		}
		events = append(events, event)
	}
	if p.version != 5 {
		// The initial catalog is observed before the first offer, which keeps
		// startup template attribution independent of a guessed data sequence.
		for index, templateID := range []int{300, 301, 300, 301} {
			sequence := uint32(0)
			if p.version == 9 {
				sequence = uint32(index)
			}
			add(templateID, 0, sends[0].start.Add(time.Duration(-400+index*100)*time.Millisecond), sequence)
		}
	}
	for identity := 1; identity <= recoveryWarmRecords; identity++ {
		add(0, identity, sends[identity-1].start.Add(200*time.Millisecond), literalDataSequence(p, commits))
		if !sends[identity-1].failed {
			commits++
		}
	}
	for identity := recoveryWarmRecords + 1; identity <= recoveryWarmRecords+recoveryOutageRecords; identity++ {
		if !sends[identity-1].failed {
			commits++
		}
	}
	for identity := recoveryWarmRecords + recoveryOutageRecords + 1; identity <= recoveryRecords; identity++ {
		send := sends[identity-1]
		add(0, identity, send.start.Add(200*time.Millisecond), literalDataSequence(p, commits))
		if !send.failed {
			commits++
		}
		if p.version != 5 && commits > 0 && commits%recoveryTemplateRefreshCount == 0 {
			round := commits / recoveryTemplateRefreshCount
			sequence := literalRefreshSequence(p, commits, round)
			add(300, 0, send.start.Add(400*time.Millisecond), sequence)
			templateSequence := sequence
			if p.version == 9 {
				templateSequence++
			}
			add(301, 0, send.start.Add(500*time.Millisecond), templateSequence)
		}
	}
	fixture.warmFrames = 3
	if p.version != 5 {
		fixture.warmFrames = 7
	}
	fixture.totalFrames = len(events)
	fixture.captureEnd = sends[len(sends)-1].end.Add(time.Second)
	fixture.headers = make([]recoveryHeader, 0, len(events))
	fixture.combined.text = ""
	for index, event := range events {
		fixture.headers = append(fixture.headers, event.header)
		fixture.combined.identities = append(fixture.combined.identities, func() decodedRecord {
			if event.identity == 0 {
				return decodedRecord{}
			}
			return decodedRecord{frame: event.header.Frame, identity: event.identity, frameTime: event.timestamp, frameTimeText: literalRecoveryTimestamp(event.timestamp)}
		}())
		if event.identity == 0 {
			fixture.combined.identities = fixture.combined.identities[:len(fixture.combined.identities)-1]
		}
		if index != 0 {
			fixture.combined.text += "\n"
		}
		fixture.combined.text += literalRecordFields(p, event)
	}
	fixture.combined.records = len(fixture.combined.identities)
	for _, event := range events {
		if event.identity != 0 {
			fixture.combined.firstData = event.header.Frame
			break
		}
	}
	fixture.warm = append([]recoveryHeader(nil), fixture.headers[:fixture.warmFrames]...)
	fixture.fresh = append([]recoveryHeader(nil), fixture.headers[fixture.warmFrames:]...)
	for index := range fixture.fresh {
		fixture.fresh[index].Frame = index + 1
	}
	refreshSeen := false
	for _, event := range events[fixture.warmFrames:] {
		if event.identity == 0 {
			refreshSeen = true
			continue
		}
		if !refreshSeen {
			fixture.preFrames = append(fixture.preFrames, event.header.Frame-fixture.warmFrames)
		}
	}
	fixture.telemetry = literalRecoveryTelemetry(sends, p)
	return fixture
}

func literalRecoveryTelemetry(sends []recoveryMeasurement, p protocol) recoveryTelemetry {
	successes := int64(countSuccesses(sends))
	failures := int64(len(sends)) - successes
	telemetry := recoveryTelemetry{
		admissionAccepted: int64(len(sends)),
		endpointEpochs:    1,
		records:           map[string]int64{"confirmed": successes, "ambiguous": 0, "unsent": failures, "invalid": 0},
		dataMessages:      map[string]int64{"confirmed": successes, "ambiguous": 0},
		templates:         map[string]int64{},
		failures:          map[string]int64{},
		bytes:             map[string]int64{"data/confirmed": successes * 100},
		losses:            map[string]int64{},
	}
	if p.version != 5 {
		rounds := successes / recoveryTemplateRefreshCount
		telemetry.templates["bootstrap/confirmed"] = 4
		telemetry.templates["refresh/confirmed"] = rounds * 2
		telemetry.bytes["bootstrap/confirmed"] = 400
		telemetry.bytes["refresh/confirmed"] = rounds * 200
	}
	return telemetry
}

func buildLiteralRecoveryLedger(f literalRecoveryFixture, telemetry recoveryTelemetry) (recoveryHeaderLedger, error) {
	return buildRecoveryHeaderLedger(f.p, f.sends, telemetry, f.combined, f.warm, f.headers, f.fresh, f.preFrames, f.warmFrames, f.totalFrames, f.captureEnd)
}

func recoveryHeaderTextForTest(p protocol, frame int, sequence uint32, templateID int) string {
	return literalHeaderFields(p, frame, sequence, templateID, 0, time.Unix(1788220803, 0))
}

func setLiteralHeaderSequence(f *literalRecoveryFixture, frame int, sequence uint32) {
	f.headers[frame-1].Sequence = sequence
	if frame <= f.warmFrames {
		f.warm[frame-1].Sequence = sequence
	} else {
		f.fresh[frame-f.warmFrames-1].Sequence = sequence
	}
}

func cloneLiteralFixture(f literalRecoveryFixture) literalRecoveryFixture {
	clone := f
	clone.sends = append([]recoveryMeasurement(nil), f.sends...)
	clone.warm = append([]recoveryHeader(nil), f.warm...)
	clone.headers = append([]recoveryHeader(nil), f.headers...)
	clone.fresh = append([]recoveryHeader(nil), f.fresh...)
	clone.preFrames = append([]int(nil), f.preFrames...)
	clone.combined.identities = append([]decodedRecord(nil), f.combined.identities...)
	clone.telemetry.records = copyRecoveryMetricMap(f.telemetry.records)
	clone.telemetry.dataMessages = copyRecoveryMetricMap(f.telemetry.dataMessages)
	clone.telemetry.templates = copyRecoveryMetricMap(f.telemetry.templates)
	clone.telemetry.failures = copyRecoveryMetricMap(f.telemetry.failures)
	clone.telemetry.bytes = copyRecoveryMetricMap(f.telemetry.bytes)
	clone.telemetry.losses = copyRecoveryMetricMap(f.telemetry.losses)
	return clone
}

func copyRecoveryMetricMap(source map[string]int64) map[string]int64 {
	result := make(map[string]int64, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func dropLiteralFrame(f *literalRecoveryFixture, frame int) {
	if frame <= f.warmFrames || frame < 1 || frame > f.totalFrames {
		panic("literal fixture frame drop must target resumed capture")
	}
	local := frame - f.warmFrames
	f.headers = append(f.headers[:frame-1], f.headers[frame:]...)
	for index := frame - 1; index < len(f.headers); index++ {
		f.headers[index].Frame = index + 1
	}
	f.fresh = append(f.fresh[:local-1], f.fresh[local:]...)
	for index := range f.fresh {
		f.fresh[index].Frame = index + 1
	}
	lines := strings.Split(f.combined.text, "\n")
	lines = append(lines[:frame-1], lines[frame:]...)
	for index := range lines {
		fields := strings.Split(lines[index], "|")
		fields[0] = strconv.Itoa(index + 1)
		lines[index] = strings.Join(fields, "|")
	}
	f.combined.text = strings.Join(lines, "\n")
	for index := 0; index < len(f.combined.identities); index++ {
		record := &f.combined.identities[index]
		if record.frame == frame {
			f.combined.identities = append(f.combined.identities[:index], f.combined.identities[index+1:]...)
			index--
			continue
		}
		if record.frame > frame {
			record.frame--
		}
	}
	f.combined.records = len(f.combined.identities)
	if f.combined.firstData > frame {
		f.combined.firstData--
	}
	for index := 0; index < len(f.preFrames); index++ {
		if f.preFrames[index] == local {
			f.preFrames = append(f.preFrames[:index], f.preFrames[index+1:]...)
			index--
		} else if f.preFrames[index] > local {
			f.preFrames[index]--
		}
	}
	f.totalFrames--
}

func setLiteralFrameTimestamp(f *literalRecoveryFixture, frame int, timestamp time.Time) {
	lines := strings.Split(f.combined.text, "\n")
	fields := strings.Split(lines[frame-1], "|")
	fields[6] = literalRecoveryTimestamp(timestamp)
	lines[frame-1] = strings.Join(fields, "|")
	f.combined.text = strings.Join(lines, "\n")
}

func TestParseRecoveryHeadersStrictScalarAndTemplatePartition(t *testing.T) {
	for _, name := range []string{"v5", "v9", "ipfix"} {
		t.Run(name, func(t *testing.T) {
			p := protocols[name]
			templateID := 0
			if p.version != 5 {
				templateID = 300
			}
			valid := recoveryHeaderTextForTest(p, 1, 7, templateID)
			got, err := parseRecoveryHeaders(valid, p, 1)
			if err != nil || len(got) != 1 || got[0].Sequence != 7 || got[0].TemplateID != templateID {
				t.Fatalf("valid header=%+v, err=%v", got, err)
			}
			fields := strings.Split(valid, "|")
			identityColumn := 3
			if p.version == 9 {
				identityColumn = 5
			} else if p.version == 10 {
				identityColumn = 6
			}
			for _, tc := range []struct {
				name  string
				index int
				value string
			}{
				{name: "missing sequence", index: 2, value: ""},
				{name: "repeated sequence", index: 2, value: "7,7"},
				{name: "overflow sequence", index: 2, value: "4294967296"},
				{name: "whitespace sequence", index: 2, value: " 7"},
				{name: "trailing whitespace identity", index: identityColumn, value: "42 "},
				{name: "missing identity", index: identityColumn, value: ""},
				{name: "repeated identity", index: identityColumn, value: "42,42"},
				{name: "overflow identity", index: identityColumn, value: "4294967296"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					mutated := append([]string(nil), fields...)
					value := tc.value
					if tc.name == "overflow identity" && p.version == 5 {
						value = "256"
					}
					mutated[tc.index] = value
					if _, err := parseRecoveryHeaders(strings.Join(mutated, "|"), p, 1); err == nil {
						t.Fatalf("malformed scalar %q was accepted", value)
					}
				})
			}
			for _, malformed := range []string{
				func() string {
					bad := append([]string(nil), fields...)
					bad[8] = "302"
					return strings.Join(bad, "|")
				}(),
				func() string {
					bad := append([]string(nil), fields...)
					bad[7], bad[8] = "300", "301"
					return strings.Join(bad, "|")
				}(),
			} {
				if p.version != 5 {
					if _, err := parseRecoveryHeaders(malformed, p, 1); err == nil {
						t.Fatalf("invalid template/data partition was accepted: %q", malformed)
					}
				}
			}
		})
	}
}

func TestRecoveryFakeTshark(t *testing.T) {
	mode := os.Getenv("RECOVERY_FAKE_TSHARK_MODE")
	if mode == "" {
		return
	}
	if marker := os.Getenv("RECOVERY_FAKE_TSHARK_MARKER"); marker != "" {
		if err := os.WriteFile(marker, []byte("started\n"), 0o600); err != nil {
			os.Exit(3)
		}
	}
	switch mode {
	case "cancel":
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "overflow":
		_, _ = io.WriteString(os.Stderr, "overflow cap\n")
		_, _ = io.WriteString(os.Stdout, strings.Repeat("x", recoveryDecoderCap+1))
		os.Exit(0)
	case "valid":
		_, _ = io.WriteString(os.Stdout, strings.Join([]string{
			"1|9|300||192.0.2.1|1|1788220803.001000000|7|||42|",
			"2|9|0|300||||8|||42|",
		}, "\n"))
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

func makeRecoveryFakeTshark(t *testing.T, root string) string {
	t.Helper()
	script := filepath.Join(root, "fake-tshark.sh")
	contents := "#!/bin/sh\nexec \"$RECOVERY_FAKE_TEST_BINARY\" -test.run='^TestRecoveryFakeTshark$'\n"
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RECOVERY_FAKE_TEST_BINARY", os.Args[0])
	t.Setenv("TSHARK_BIN", script)
	return script
}

func recoveryFakeStarted(path string) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func TestDecodeRecoveryHeadersHonorsCancellationAndOutputCaps(t *testing.T) {
	root := t.TempDir()
	p := protocols["v9"]
	pcap := filepath.Join(root, "view.pcap")
	if err := os.WriteFile(pcap, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	makeRecoveryFakeTshark(t, root)
	t.Setenv("RECOVERY_FAKE_TSHARK_MODE", "valid")
	view, err := decodeRecoveryHeaders(context.Background(), root, "view", p, 2)
	if err != nil {
		t.Fatalf("finite fake decoder failed: %v", err)
	}
	if len(view.headers) != 2 || view.headers[0].Sequence != 7 || view.headers[1].TemplateID != 300 {
		t.Fatalf("decoded header view=%+v", view.headers)
	}
	if want := "1|9|300||192.0.2.1|1|1788220803.001000000\n2|9|0|300|||"; view.fields != want {
		t.Fatalf("record fields=%q, want %q", view.fields, want)
	}

	t.Setenv("RECOVERY_FAKE_TSHARK_MODE", "cancel")
	if err := os.WriteFile(filepath.Join(root, "cancel.pcap"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	cancelMarker := filepath.Join(root, "cancel.started")
	t.Setenv("RECOVERY_FAKE_TSHARK_MARKER", cancelMarker)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, decodeErr := decodeRecoveryHeaders(ctx, root, "cancel", p, 1)
		done <- decodeErr
	}()
	if !recoveryFakeStarted(cancelMarker) {
		cancel()
		t.Fatal("cancel fake decoder did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled header decoder err=%v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled header decoder did not terminate")
	}

	t.Setenv("RECOVERY_FAKE_TSHARK_MODE", "overflow")
	if err := os.WriteFile(filepath.Join(root, "overflow.pcap"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	overflowMarker := filepath.Join(root, "overflow.started")
	t.Setenv("RECOVERY_FAKE_TSHARK_MARKER", overflowMarker)
	if _, err := decodeRecoveryHeaders(context.Background(), root, "overflow", p, 1); err == nil {
		t.Fatal("header decoder accepted output over its cap")
	} else if !strings.Contains(err.Error(), "recovery TShark command") {
		t.Fatalf("output cap err=%v, want command failure", err)
	}
	if !recoveryFakeStarted(overflowMarker) {
		t.Fatal("overflow fake decoder did not start")
	}
	for _, suffix := range []string{".headers.fields", ".headers.stderr"} {
		data, readErr := os.ReadFile(filepath.Join(root, "overflow"+suffix))
		if readErr != nil {
			t.Fatalf("read retained overflow diagnostic %s: %v", suffix, readErr)
		}
		if suffix == ".headers.fields" && len(data) != recoveryDecoderCap {
			t.Fatalf("retained overflow diagnostic %s=%d bytes, want cap threshold=%d", suffix, len(data), recoveryDecoderCap)
		}
		if suffix == ".headers.stderr" && len(data) == 0 {
			t.Fatalf("retained overflow diagnostic %s is empty", suffix)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "large.pcap"), make([]byte, recoveryDecoderCap+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRecoveryHeaders(context.Background(), root, "large", p, 1); err == nil || !strings.Contains(err.Error(), "input cap") {
		t.Fatalf("large input err=%v, want input cap rejection", err)
	}
}

func TestRecoveryHeaderLedgerQualifiesLiteralIndependentSchedule(t *testing.T) {
	for _, name := range []string{"v5", "v9", "ipfix"} {
		t.Run(name, func(t *testing.T) {
			fixture := makeLiteralRecoveryFixture(protocols[name], recoveryOutageRecords)
			ledger, err := buildLiteralRecoveryLedger(fixture, fixture.telemetry)
			if err != nil {
				t.Fatalf("literal schedule rejected: %v\nproblems=%v", err, ledger.Problems)
			}
			if ledger.Status != "pass" || !ledger.CommitInference || len(ledger.Offers) != recoveryRecords || len(ledger.Packets) != fixture.totalFrames {
				t.Fatalf("ledger status=%q commits=%t offers=%d packets=%d problems=%v", ledger.Status, ledger.CommitInference, len(ledger.Offers), len(ledger.Packets), ledger.Problems)
			}
			for _, offer := range ledger.Offers[recoveryWarmRecords : recoveryWarmRecords+recoveryOutageRecords] {
				if offer.Receipt != "unobserved_socket_closed" {
					t.Fatalf("outage offer=%+v, want observation-first missing label", offer)
				}
			}
			if name != "v5" {
				ids := make([]int, 0, 8)
				finalRound := false
				for _, packet := range ledger.Packets {
					if packet.Kind == "template" {
						ids = append(ids, packet.Header.TemplateID)
						if strings.Contains(packet.Association, "refresh:offer:40") {
							finalRound = true
						}
					}
				}
				if want := []int{300, 301, 300, 301, 300, 301, 300, 301}; fmt.Sprint(ids) != fmt.Sprint(want) {
					t.Fatalf("template catalog=%v, want %v", ids, want)
				}
				if !finalRound {
					t.Fatalf("template catalog lacks second refresh round at offer 40")
				}
			}
			root := t.TempDir()
			if err := writeRecoveryHeaderLedger(root, ledger); err != nil {
				t.Fatalf("write literal ledger: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(root, "header-ledger.json"))
			if err != nil || !strings.Contains(string(data), `"Status": "pass"`) {
				t.Fatalf("ledger artifact err=%v data=%s", err, data)
			}
		})
	}
}

func TestRecoveryHeaderLedgerQualifiesZeroOneAndSeveralOutageSuccesses(t *testing.T) {
	for _, name := range []string{"v5", "v9", "ipfix"} {
		for _, outageSuccesses := range []int{0, 1, recoveryOutageRecords} {
			t.Run(fmt.Sprintf("%s/%d", name, outageSuccesses), func(t *testing.T) {
				fixture := makeLiteralRecoveryFixture(protocols[name], outageSuccesses)
				ledger, err := buildLiteralRecoveryLedger(fixture, fixture.telemetry)
				if err != nil || ledger.Status != "pass" || !ledger.CommitInference {
					t.Fatalf("outage=%d err=%v status=%q commits=%t problems=%v", outageSuccesses, err, ledger.Status, ledger.CommitInference, ledger.Problems)
				}
				for index := recoveryWarmRecords; index < recoveryWarmRecords+recoveryOutageRecords; index++ {
					wantOutcome := "failure"
					if index-recoveryWarmRecords < outageSuccesses {
						wantOutcome = "success"
					}
					if ledger.Offers[index].Outcome != wantOutcome || ledger.Offers[index].Receipt != "unobserved_socket_closed" {
						t.Fatalf("outage offer=%+v, want outcome=%s and socket-closed observation", ledger.Offers[index], wantOutcome)
					}
				}
				wantTemplates := 0
				if name != "v5" {
					wantTemplates = 4 + 2*(countSuccesses(fixture.sends)/recoveryTemplateRefreshCount)
				}
				gotTemplates := 0
				for _, packet := range ledger.Packets {
					if packet.Kind == "template" {
						gotTemplates++
					}
				}
				if gotTemplates != wantTemplates {
					t.Fatalf("template rows=%d, want %d for %d outage successes", gotTemplates, wantTemplates, outageSuccesses)
				}
			})
		}
	}
}

func literalReceiptInputs(f literalRecoveryFixture) (map[int]decodedRecord, []packet) {
	decoded := make(map[int]decodedRecord, len(f.combined.identities))
	packets := make([]packet, f.totalFrames)
	for index := range packets {
		packets[index].t = f.sends[0].start.Add(time.Duration(index+1) * time.Millisecond)
	}
	for _, record := range f.combined.identities {
		receipt := f.sends[record.identity-1].start.Add(200 * time.Millisecond)
		record.frameTime = receipt
		record.frameTimeText = literalRecoveryTimestamp(receipt)
		decoded[record.identity] = record
		packets[record.frame-1].t = receipt
	}
	return decoded, packets
}

func TestRecoveryReceiptAccountingCoversZeroOneAndSeveralOutageSuccesses(t *testing.T) {
	for _, outageSuccesses := range []int{0, 1, recoveryOutageRecords} {
		t.Run(strconv.Itoa(outageSuccesses), func(t *testing.T) {
			fixture := makeLiteralRecoveryFixture(protocols["v5"], outageSuccesses)
			decoded, packets := literalReceiptInputs(fixture)
			summary, err := summarizeRecoveryReceipts(fixture.sends, decoded, packets)
			if err != nil {
				t.Fatal(err)
			}
			if summary.outageSuccess != outageSuccesses || summary.outageFailed != recoveryOutageRecords-outageSuccesses || summary.outageUnobservedSuccess != outageSuccesses || summary.outageUnobservedFailed != recoveryOutageRecords-outageSuccesses {
				t.Fatalf("summary=%+v, want outage successes=%d", summary, outageSuccesses)
			}
		})
	}
}

func TestRecoveryReceiptAccountingSeparatesActiveMissingConfirmedData(t *testing.T) {
	fixture := makeLiteralRecoveryFixture(protocols["v5"], recoveryOutageRecords)
	decoded, packets := literalReceiptInputs(fixture)
	delete(decoded, 7)
	fixture.sends[7].failed = true
	fixture.sends[7].errorText = "active receiver handoff failed"
	delete(decoded, 8)
	summary, err := summarizeRecoveryReceipts(fixture.sends, decoded, packets)
	if err != nil {
		t.Fatal(err)
	}
	if summary.missingSuccess != 1 || summary.missingFailed != 1 {
		t.Fatalf("summary=%+v, want active missing success/failed split", summary)
	}
}

func TestRecoveryLedgerAllowsActiveConfirmedPacketOmissionAndRejectsNextSequence(t *testing.T) {
	fixture := makeLiteralRecoveryFixture(protocols["v5"], recoveryOutageRecords)
	// Remove the first resumed data frame and reindex every later retained row,
	// header, and timestamp. The offer remains a missing_success observation.
	dropLiteralFrame(&fixture, 4)
	ledger, err := buildLiteralRecoveryLedger(fixture, fixture.telemetry)
	if err != nil || ledger.Status != "pass" || ledger.Offers[recoveryWarmRecords+recoveryOutageRecords].Receipt != "missing_success" {
		t.Fatalf("active omission err=%v status=%q offer7=%+v problems=%v", err, ledger.Status, ledger.Offers[recoveryWarmRecords+recoveryOutageRecords], ledger.Problems)
	}
	var nextFrame int
	for _, record := range fixture.combined.identities {
		if record.identity == recoveryWarmRecords+recoveryOutageRecords+2 {
			nextFrame = record.frame
			break
		}
	}
	nextExpected := *ledger.Offers[recoveryWarmRecords+recoveryOutageRecords+1].ExpectedSequence
	setLiteralHeaderSequence(&fixture, nextFrame, nextExpected+1)
	ledger, err = buildLiteralRecoveryLedger(fixture, fixture.telemetry)
	if err == nil || !strings.Contains(strings.Join(ledger.Problems, " "), "header sequence") {
		t.Fatalf("wrong continuation after omission err=%v problems=%v", err, ledger.Problems)
	}
}

func TestRecoveryLedgerSupportsReceivedAmbiguousDataWithUnchangedSequence(t *testing.T) {
	fixture := makeLiteralRecoveryFixture(protocols["v5"], recoveryOutageRecords)
	fixture.sends[6].failed = true
	fixture.sends[6].errorText = "ambiguous data handoff"
	fixture.telemetry.records["confirmed"]--
	fixture.telemetry.records["ambiguous"]++
	fixture.telemetry.dataMessages["confirmed"]--
	fixture.telemetry.dataMessages["ambiguous"]++
	fixture.telemetry.bytes["data/ambiguous"] = 100
	// Offer 7 failed after admission; offer 8 remains on the same sequence.
	commits := 6
	for identity := recoveryWarmRecords + recoveryOutageRecords + 1; identity <= recoveryRecords; identity++ {
		var frame int
		for _, record := range fixture.combined.identities {
			if record.identity == identity {
				frame = record.frame
				break
			}
		}
		setLiteralHeaderSequence(&fixture, frame, literalDataSequence(protocols["v5"], commits))
		if identity != recoveryWarmRecords+recoveryOutageRecords+1 {
			commits++
		}
	}
	ledger, err := buildLiteralRecoveryLedger(fixture, fixture.telemetry)
	if err != nil {
		t.Fatalf("ambiguous data was rejected despite unchanged sequence: %v\nproblems=%v", err, ledger.Problems)
	}
	if ledger.Offers[6].Outcome != "failure" || ledger.Offers[6].Receipt != "received_after_error" || ledger.Offers[6].Committed {
		t.Fatalf("ambiguous offer=%+v, want received-after-error and uncommitted", ledger.Offers[6])
	}
	if ledger.Offers[7].PriorCommits != ledger.Offers[6].PriorCommits {
		t.Fatalf("following offer=%+v, want unchanged prior commit count", ledger.Offers[7])
	}
}

func TestRecoveryLedgerRejectsResetsIdentityAndTemplateCharges(t *testing.T) {
	for _, name := range []string{"v5", "v9", "ipfix"} {
		t.Run(name, func(t *testing.T) {
			base := makeLiteralRecoveryFixture(protocols[name], recoveryOutageRecords)
			findDataFrame := func(f literalRecoveryFixture, identity int) int {
				for _, record := range f.combined.identities {
					if record.identity == identity {
						return record.frame
					}
				}
				return 0
			}
			reset := cloneLiteralFixture(base)
			frame := findDataFrame(reset, 21)
			setLiteralHeaderSequence(&reset, frame, 0)
			ledger, err := buildLiteralRecoveryLedger(reset, reset.telemetry)
			if err == nil || ledger.Status != "nonpassing" || !strings.Contains(strings.Join(ledger.Problems, " "), "header sequence") {
				t.Fatalf("sequence reset err=%v status=%q problems=%v", err, ledger.Status, ledger.Problems)
			}
			if len(ledger.Offers) != recoveryRecords || len(ledger.Packets) != base.totalFrames {
				t.Fatalf("reset ledger lost observations: offers=%d packets=%d", len(ledger.Offers), len(ledger.Packets))
			}

			identity := cloneLiteralFixture(base)
			identity.headers[frame-1].SourceID, identity.headers[frame-1].DomainID = 43, 43
			if frame <= identity.warmFrames {
				identity.warm[frame-1] = identity.headers[frame-1]
			} else {
				identity.fresh[frame-identity.warmFrames-1] = identity.headers[frame-1]
			}
			ledger, err = buildLiteralRecoveryLedger(identity, identity.telemetry)
			if name == "v5" {
				// v5 identity fields are engine type/ID; mutate those explicitly.
				identity.headers[frame-1].EngineType = 1
				identity.headers[frame-1].EngineID = 1
				if frame <= identity.warmFrames {
					identity.warm[frame-1] = identity.headers[frame-1]
				} else {
					identity.fresh[frame-identity.warmFrames-1] = identity.headers[frame-1]
				}
				ledger, err = buildLiteralRecoveryLedger(identity, identity.telemetry)
			}
			if err == nil || ledger.Status != "nonpassing" {
				t.Fatalf("wrong identity accepted: err=%v status=%q problems=%v", err, ledger.Status, ledger.Problems)
			}

			if name != "v5" {
				charge := cloneLiteralFixture(base)
				if name == "v9" {
					setLiteralHeaderSequence(&charge, frame, literalDataSequence(protocols[name], 20)-2)
				} else {
					setLiteralHeaderSequence(&charge, frame, literalDataSequence(protocols[name], 20)+2)
				}
				ledger, err = buildLiteralRecoveryLedger(charge, charge.telemetry)
				if err == nil || !strings.Contains(strings.Join(ledger.Problems, " "), "header sequence") {
					t.Fatalf("wrong refresh charge err=%v problems=%v", err, ledger.Problems)
				}
			}
		})
	}
}

func TestRecoveryLedgerAmbiguousTemplateAndPartialCatalogRemainNonpassing(t *testing.T) {
	fixture := makeLiteralRecoveryFixture(protocols["v9"], recoveryOutageRecords)
	ambiguous := cloneLiteralFixture(fixture)
	ambiguous.telemetry.templates["bootstrap/ambiguous"] = 1
	ambiguous.telemetry.bytes["bootstrap/ambiguous"] = 1
	ledger, err := buildLiteralRecoveryLedger(ambiguous, ambiguous.telemetry)
	if err == nil || ledger.Status != "nonpassing" || len(ledger.Offers) != recoveryRecords || len(ledger.Packets) != fixture.totalFrames || !strings.Contains(strings.Join(ledger.Problems, " "), "ambiguous") {
		t.Fatalf("ambiguous template result err=%v status=%q offers=%d packets=%d problems=%v", err, ledger.Status, len(ledger.Offers), len(ledger.Packets), ledger.Problems)
	}

	partial := cloneLiteralFixture(fixture)
	partial.headers = partial.headers[:len(partial.headers)-1]
	ledger, err = buildLiteralRecoveryLedger(partial, partial.telemetry)
	if err == nil || len(ledger.Offers) != recoveryRecords || len(ledger.Packets) != fixture.totalFrames || !strings.Contains(strings.Join(ledger.Problems, " "), "missing header") {
		t.Fatalf("partial catalog result err=%v offers=%d packets=%d problems=%v", err, len(ledger.Offers), len(ledger.Packets), ledger.Problems)
	}

	catalog := cloneLiteralFixture(fixture)
	for index := range catalog.headers {
		if catalog.headers[index].TemplateID != 0 {
			catalog.headers[index].TemplateID = 301
			if index < catalog.warmFrames {
				catalog.warm[index] = catalog.headers[index]
			} else {
				catalog.fresh[index-catalog.warmFrames] = catalog.headers[index]
			}
			break
		}
	}
	ledger, err = buildLiteralRecoveryLedger(catalog, catalog.telemetry)
	if err == nil || !strings.Contains(strings.Join(ledger.Problems, " "), "catalog") {
		t.Fatalf("wrong template catalog result err=%v problems=%v", err, ledger.Problems)
	}

	outside := cloneLiteralFixture(fixture)
	lines := strings.Split(outside.combined.text, "\n")
	for index, line := range lines {
		if index >= outside.warmFrames && outside.headers[index].TemplateID != 0 {
			fields := strings.Split(line, "|")
			fields[6] = literalRecoveryTimestamp(outside.sends[0].start.Add(-time.Second))
			lines[index] = strings.Join(fields, "|")
			break
		}
	}
	outside.combined.text = strings.Join(lines, "\n")
	ledger, err = buildLiteralRecoveryLedger(outside, outside.telemetry)
	if err == nil || !strings.Contains(strings.Join(ledger.Problems, " "), "outside triggering offer windows") {
		t.Fatalf("outside-window catalog result err=%v problems=%v", err, ledger.Problems)
	}
}

func TestRecoveryLedgerAndCSVAreObservationFirstForWarmAndLateOutageRows(t *testing.T) {
	fixture := makeLiteralRecoveryFixture(protocols["v5"], recoveryOutageRecords)
	missingWarm := cloneLiteralFixture(fixture)
	for index, record := range missingWarm.combined.identities {
		if record.identity == 1 {
			missingWarm.combined.identities = append(missingWarm.combined.identities[:index], missingWarm.combined.identities[index+1:]...)
			break
		}
	}
	ledger, err := buildLiteralRecoveryLedger(missingWarm, missingWarm.telemetry)
	if err == nil || len(ledger.Offers) != recoveryRecords || len(ledger.Packets) != fixture.totalFrames || !strings.Contains(strings.Join(ledger.Problems, " "), "retained-cache prerequisite") {
		t.Fatalf("missing warm result err=%v offers=%d packets=%d problems=%v", err, len(ledger.Offers), len(ledger.Packets), ledger.Problems)
	}
	late := cloneLiteralFixture(fixture)
	for index := range late.combined.identities {
		if late.combined.identities[index].identity == recoveryWarmRecords+recoveryOutageRecords+1 {
			late.combined.identities[index].identity = recoveryWarmRecords + 1
			break
		}
	}
	ledger, err = buildLiteralRecoveryLedger(late, late.telemetry)
	if err == nil || ledger.Status != "nonpassing" || ledger.Offers[recoveryWarmRecords].Receipt != "received" || !strings.Contains(strings.Join(ledger.Problems, " "), "outage") {
		t.Fatalf("late outage ledger err=%v status=%q offer4=%+v problems=%v", err, ledger.Status, ledger.Offers[recoveryWarmRecords], ledger.Problems)
	}

	start := time.Unix(1788220803, 0)
	sends := []recoveryMeasurement{{sendMeasurement: sendMeasurement{identity: 4, start: start, end: start.Add(time.Millisecond)}, phase: "outage", epoch: 0}}
	decoded := map[int]decodedRecord{4: {identity: 4, frame: 1, frameTime: start.Add(2 * time.Millisecond)}}
	root := t.TempDir()
	path := filepath.Join(root, "measurements.csv")
	if err := writeRecoveryMeasurements(path, sends, decoded); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(file).ReadAll()
	_ = file.Close()
	if err != nil || len(rows) != 2 || rows[1][7] != "received" {
		t.Fatalf("late outage CSV rows=%v err=%v, want received observation", rows, err)
	}

	active := []recoveryMeasurement{{sendMeasurement: sendMeasurement{identity: 7, start: start, end: start.Add(time.Millisecond)}, phase: "resumed", epoch: 2}}
	if err := writeRecoveryMeasurements(filepath.Join(root, "active.csv"), active, nil); err != nil {
		t.Fatal(err)
	}
	activeFile, err := os.Open(filepath.Join(root, "active.csv"))
	if err != nil {
		t.Fatal(err)
	}
	activeRows, err := csv.NewReader(activeFile).ReadAll()
	_ = activeFile.Close()
	if err != nil || len(activeRows) != 2 || activeRows[1][7] != "not_observed" {
		t.Fatalf("active missing CSV rows=%v err=%v, want not_observed", activeRows, err)
	}
}

func TestRecoveryLedgerAssociatesRefreshWithinNextCallAndRejectsFinalCutoff(t *testing.T) {
	fixture := makeLiteralRecoveryFixture(protocols["v9"], recoveryOutageRecords)
	refreshFrame := 0
	for index := fixture.warmFrames; index < len(fixture.headers); index++ {
		if fixture.headers[index].TemplateID != 0 {
			refreshFrame = index + 1
			break
		}
	}
	if refreshFrame == 0 {
		t.Fatal("literal v9 fixture has no refresh frame")
	}
	// The first refresh is emitted during offer 21, after offer 20 triggered it.
	// Its timestamp is inside offer 21's call window, which the ledger must accept.
	setLiteralFrameTimestamp(&fixture, refreshFrame, fixture.sends[20].start.Add(50*time.Millisecond))
	ledger, err := buildLiteralRecoveryLedger(fixture, fixture.telemetry)
	if err != nil || ledger.Status != "pass" {
		t.Fatalf("refresh drained during next call err=%v status=%q problems=%v", err, ledger.Status, ledger.Problems)
	}
	if !strings.Contains(ledger.Packets[refreshFrame-1].Association, "refresh:offer:20") {
		t.Fatalf("refresh packet association=%q, want trigger offer 20", ledger.Packets[refreshFrame-1].Association)
	}

	cutoff := makeLiteralRecoveryFixture(protocols["v9"], recoveryOutageRecords)
	dropLiteralFrame(&cutoff, cutoff.totalFrames)
	ledger, err = buildLiteralRecoveryLedger(cutoff, cutoff.telemetry)
	if err == nil || ledger.Status != "nonpassing" || !strings.Contains(strings.Join(ledger.Problems, " "), "cutoff") {
		t.Fatalf("final refresh cutoff err=%v status=%q problems=%v", err, ledger.Status, ledger.Problems)
	}
}
