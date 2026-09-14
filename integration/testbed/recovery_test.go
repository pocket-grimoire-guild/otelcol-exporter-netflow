//go:build linux

package main

import (
	"fmt"
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
}
