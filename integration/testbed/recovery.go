//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/testbed/testbed"
)

// Recovery is deliberately small enough to complete inside the ordinary
// 30-second one-case deadline. The first three records establish a receiver
// epoch, the next three are sent while that socket is closed, and the final
// records exercise a fresh decoder cache plus the packet-count refresh.
const (
	recoveryRecords              = 40
	recoveryPacing               = 10 * time.Millisecond
	recoveryWarmRecords          = 3
	recoveryOutageRecords        = 3
	recoveryResumeRecords        = recoveryRecords - recoveryWarmRecords - recoveryOutageRecords
	recoveryTemplateRefreshCount = 20
)

type recoveryMeasurement struct {
	sendMeasurement
	phase string
	epoch int
}

type recoveryTelemetry struct {
	admissionAccepted       int64
	admissionBusy           int64
	admissionClosed         int64
	admissionPreflight      int64
	admissionInvalidContext int64
	endpointEpochs          int64
	records                 map[string]int64
	dataMessages            map[string]int64
	templates               map[string]int64
	failures                map[string]int64
	bytes                   map[string]int64
	losses                  map[string]int64
}

type prometheusMetric struct {
	name   string
	labels map[string]string
	value  int64
}

func recoveryConfigFor(p protocol, in, out, pprof, metrics int) (string, error) {
	config := configFor(p, in, out, pprof)
	marker := "    mapping:\n"
	if p.name == "v9" {
		config = strings.Replace(config, marker, fmt.Sprintf("    netflow_v9:\n      template_refresh_packets: %d\n%s", recoveryTemplateRefreshCount, marker), 1)
	}
	if p.name == "ipfix" {
		config = strings.Replace(config, marker, fmt.Sprintf("    ipfix:\n      template_refresh_data_packets: %d\n%s", recoveryTemplateRefreshCount, marker), 1)
	}
	old := "  telemetry:\n    metrics:\n      level: none\n"
	new := fmt.Sprintf("  telemetry:\n    metrics:\n      level: detailed\n      readers:\n        - pull:\n            exporter:\n              prometheus:\n                host: 127.0.0.1\n                port: %d\n", metrics)
	if !strings.Contains(config, old) {
		return "", errors.New("recovery config is missing the baseline telemetry stanza")
	}
	return strings.Replace(config, old, new, 1), nil
}

func newCaptureOnPort(port int) (*capture, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return nil, err
	}
	c := &capture{conn: conn, stop: make(chan struct{}), done: make(chan struct{})}
	go c.read()
	return c, nil
}

func waitCapturePackets(ctx context.Context, c *capture, count int) error {
	if c == nil {
		return errors.New("nil capture")
	}
	for {
		if c.packetCount() >= count {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for %d captured packets: %w", count, ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func capturePeer(c *capture) (*net.UDPAddr, error) {
	if c == nil {
		return nil, errors.New("nil capture")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peer == nil {
		return nil, errors.New("capture observed no exporter peer")
	}
	return &net.UDPAddr{IP: append(net.IP(nil), c.peer.IP...), Port: c.peer.Port}, nil
}

func sendRecoveryPhase(ctx context.Context, sender testbed.LogDataSender, provider *canonicalProvider, count, epoch int, phase string, sends *[]recoveryMeasurement) error {
	for range count {
		logs, done := provider.GenerateLogs()
		if done {
			return fmt.Errorf("recovery provider ended during %s", phase)
		}
		identity, err := canonicalIdentity(logs)
		if err != nil {
			return err
		}
		start := time.Now()
		callErr := sender.ConsumeLogs(ctx, logs)
		end := time.Now()
		*sends = append(*sends, recoveryMeasurement{
			sendMeasurement: sendMeasurement{identity: identity, start: start, end: end, failed: callErr != nil, errorText: boundedErrorText(callErr)},
			phase:           phase, epoch: epoch,
		})
		// A closed receiver can surface an asynchronous ICMP error at a later
		// OTLP call. Preserve that outcome for reconciliation; it does not
		// establish UDP receipt or loss of a particular flow record.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(recoveryPacing):
		}
	}
	return nil
}

func readRecoveryMetrics(ctx context.Context, port int) (recoveryTelemetry, string, error) {
	var lastErr error
	var lastText string
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	for attempt := 0; attempt < 40; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return recoveryTelemetry{}, "", err
		}
		resp, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, outputCap+1))
			closeErr := resp.Body.Close()
			lastText = string(body)
			if resp.StatusCode == http.StatusOK && readErr == nil && closeErr == nil && len(body) <= outputCap {
				telemetry, parseErr := parseRecoveryMetrics(string(body))
				if parseErr == nil {
					return telemetry, string(body), nil
				}
				lastErr = parseErr
			} else {
				lastErr = fmt.Errorf("metrics HTTP status=%s read=%v close=%v body_bytes=%d", resp.Status, readErr, closeErr, len(body))
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return recoveryTelemetry{}, lastText, fmt.Errorf("metrics endpoint %s: %w (last=%v)", endpoint, ctx.Err(), lastErr)
		case <-time.After(50 * time.Millisecond):
		}
	}
	return recoveryTelemetry{}, lastText, fmt.Errorf("metrics endpoint %s did not produce valid Prometheus text: %v", endpoint, lastErr)
}

func parseRecoveryMetrics(text string) (recoveryTelemetry, error) {
	metrics, err := parsePrometheusMetrics(text)
	if err != nil {
		return recoveryTelemetry{}, err
	}
	result := recoveryTelemetry{
		records: map[string]int64{}, dataMessages: map[string]int64{}, templates: map[string]int64{},
		failures: map[string]int64{}, bytes: map[string]int64{}, losses: map[string]int64{},
	}
	seenAdmission := make(map[string]struct{})
	seenEndpointEpochs := false
	for _, metric := range metrics {
		name := strings.TrimSuffix(metric.name, "_total")
		switch name {
		case "otelcol_netflow_exporter_admission":
			reason, ok := metric.labels["reason"]
			if !ok || metric.labels["exporter"] != "netflow" || len(metric.labels) != 2 {
				return recoveryTelemetry{}, fmt.Errorf("admission metric has invalid labels: %q", metric.labels)
			}
			if _, exists := seenAdmission[reason]; exists {
				return recoveryTelemetry{}, fmt.Errorf("duplicate admission reason series %q", reason)
			}
			seenAdmission[reason] = struct{}{}
			switch reason {
			case "accepted":
				result.admissionAccepted = metric.value
			case "busy":
				result.admissionBusy = metric.value
			case "closed":
				result.admissionClosed = metric.value
			case "preflight":
				result.admissionPreflight = metric.value
			case "invalid_context":
				result.admissionInvalidContext = metric.value
			default:
				return recoveryTelemetry{}, fmt.Errorf("admission metric has unsupported reason %q", reason)
			}
		case "otelcol_netflow_exporter_endpoint_epochs":
			if metric.labels["exporter"] != "netflow" || len(metric.labels) != 1 {
				return recoveryTelemetry{}, fmt.Errorf("endpoint epoch metric has invalid labels: %q", metric.labels)
			}
			if seenEndpointEpochs {
				return recoveryTelemetry{}, errors.New("duplicate endpoint epoch series")
			}
			seenEndpointEpochs = true
			result.endpointEpochs = metric.value
		case "otelcol_netflow_exporter_records":
			if err := addLabeledMetric(result.records, metric, "outcome", []string{"confirmed", "ambiguous", "unsent", "invalid"}, ""); err != nil {
				return recoveryTelemetry{}, err
			}
		case "otelcol_netflow_exporter_data_messages":
			if err := addLabeledMetric(result.dataMessages, metric, "outcome", []string{"confirmed", "ambiguous"}, ""); err != nil {
				return recoveryTelemetry{}, err
			}
		case "otelcol_netflow_exporter_templates":
			if err := addLabeledMetric(result.templates, metric, "message_kind", []string{"bootstrap", "refresh"}, "outcome"); err != nil {
				return recoveryTelemetry{}, err
			}
		case "otelcol_netflow_exporter_failures":
			if err := addLabeledMetric(result.failures, metric, "reason", []string{"busy", "closed", "unavailable", "internal", "candidate", "bootstrap", "refresh"}, ""); err != nil {
				return recoveryTelemetry{}, err
			}
		case "otelcol_netflow_exporter_bytes":
			if err := addLabeledMetric(result.bytes, metric, "message_kind", []string{"data", "bootstrap", "refresh"}, "outcome"); err != nil {
				return recoveryTelemetry{}, err
			}
		case "otelcol_netflow_exporter_losses":
			if err := addLabeledMetric(result.losses, metric, "loss_class", []string{"exporter", "canonical_source"}, ""); err != nil {
				return recoveryTelemetry{}, err
			}
		}
	}
	if result.admissionAccepted < 1 {
		return recoveryTelemetry{}, fmt.Errorf("missing active accepted admission metric")
	}
	if result.endpointEpochs != 1 {
		return recoveryTelemetry{}, fmt.Errorf("endpoint epoch telemetry=%d, want exactly one", result.endpointEpochs)
	}
	if result.records["confirmed"] < 1 || result.dataMessages["confirmed"] < 1 {
		return recoveryTelemetry{}, fmt.Errorf("missing active confirmed record/data metrics: records=%v data=%v", result.records, result.dataMessages)
	}
	return result, nil
}

func addLabeledMetric(dst map[string]int64, metric prometheusMetric, label string, allowed []string, secondLabel string) error {
	if metric.labels["exporter"] != "netflow" {
		return fmt.Errorf("metric %s has invalid exporter label: %q", metric.name, metric.labels)
	}
	wantLabels := 2
	if secondLabel != "" {
		wantLabels++
	}
	if len(metric.labels) != wantLabels {
		return fmt.Errorf("metric %s has unexpected labels: %q", metric.name, metric.labels)
	}
	value, ok := metric.labels[label]
	if !ok {
		return fmt.Errorf("metric %s missing label %s", metric.name, label)
	}
	for _, candidate := range allowed {
		if value == candidate {
			key := value
			if secondLabel != "" {
				second, ok := metric.labels[secondLabel]
				if !ok {
					return fmt.Errorf("metric %s missing label %s", metric.name, secondLabel)
				}
				if second != "confirmed" && second != "ambiguous" {
					return fmt.Errorf("metric %s has unsupported %s=%q", metric.name, secondLabel, second)
				}
				key += "/" + second
			}
			if _, exists := dst[key]; exists {
				return fmt.Errorf("metric %s duplicates label series %s", metric.name, key)
			}
			dst[key] = metric.value
			if secondLabel != "" {
				// Retain a family total for the compact result while keeping the
				// composite key above for confirmed/ambiguous reconciliation.
				dst[value] += metric.value
			}
			return nil
		}
	}
	return fmt.Errorf("metric %s has unsupported %s=%q", metric.name, label, value)
}

func parsePrometheusMetrics(text string) ([]prometheusMetric, error) {
	var result []prometheusMetric
	seen := map[string]struct{}{}
	for lineNo, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, labelsText, valueText, err := splitPrometheusSample(line)
		if err != nil {
			return nil, fmt.Errorf("Prometheus line %d: %w", lineNo+1, err)
		}
		metricFamily := strings.TrimSuffix(name, "_total")
		// The remaining-uptime gauge is fractional seconds, not an accounting
		// counter. Validate its numeric value without truncating it into the
		// integer handoff ledger; retain exact parsing for every counter.
		uptimeGauge := metricFamily == "otelcol_netflow_exporter_uptime_remaining"
		exporterMetric := strings.HasPrefix(metricFamily, "otelcol_netflow_exporter_") && !uptimeGauge
		stored := int64(0)
		if exporterMetric {
			exact, parseErr := strconv.ParseInt(valueText, 10, 64)
			if parseErr != nil || exact < 0 {
				return nil, fmt.Errorf("Prometheus line %d has invalid nonnegative exporter integer value %q", lineNo+1, valueText)
			}
			stored = exact
		} else {
			value, parseErr := strconv.ParseFloat(valueText, 64)
			if parseErr != nil || math.IsNaN(value) || math.IsInf(value, 0) || uptimeGauge && value < 0 {
				return nil, fmt.Errorf("Prometheus line %d has invalid numeric value %q", lineNo+1, valueText)
			}
		}
		labels, err := parsePrometheusLabels(labelsText)
		if err != nil {
			return nil, fmt.Errorf("Prometheus line %d: %w", lineNo+1, err)
		}
		key := canonicalPrometheusSampleKey(name, labels)
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("Prometheus line %d duplicates sample %q", lineNo+1, key)
		}
		seen[key] = struct{}{}
		result = append(result, prometheusMetric{name: name, labels: labels, value: stored})
	}
	if len(result) == 0 {
		return nil, errors.New("Prometheus response contains no samples")
	}
	return result, nil
}

func canonicalPrometheusSampleKey(name string, labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(name)
	b.WriteByte('{')
	for i, key := range keys {
		if i != 0 {
			b.WriteByte(',')
		}
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(labels[key]))
	}
	b.WriteByte('}')
	return b.String()
}

func splitPrometheusSample(line string) (name, labels, value string, err error) {
	space := strings.LastIndexAny(line, " \t")
	if space <= 0 || space == len(line)-1 {
		return "", "", "", errors.New("sample must end with a numeric value")
	}
	value = strings.TrimSpace(line[space:])
	left := strings.TrimSpace(line[:space])
	if brace := strings.IndexByte(left, '{'); brace >= 0 {
		if !strings.HasSuffix(left, "}") {
			return "", "", "", errors.New("unterminated label set")
		}
		name, labels = left[:brace], left[brace+1:len(left)-1]
	} else {
		name = left
	}
	if name == "" {
		return "", "", "", errors.New("empty metric name")
	}
	for i, ch := range name {
		if !(ch == '_' || ch == ':' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || i > 0 && ch >= '0' && ch <= '9') {
			return "", "", "", fmt.Errorf("invalid metric name %q", name)
		}
	}
	return name, labels, value, nil
}

func parsePrometheusLabels(text string) (map[string]string, error) {
	labels := map[string]string{}
	if strings.TrimSpace(text) == "" {
		return labels, nil
	}
	for len(text) > 0 {
		text = strings.TrimSpace(text)
		eq := strings.IndexByte(text, '=')
		if eq <= 0 {
			return nil, errors.New("label is missing name or equals")
		}
		name := strings.TrimSpace(text[:eq])
		text = strings.TrimSpace(text[eq+1:])
		if len(text) == 0 || text[0] != '"' {
			return nil, fmt.Errorf("label %s is not quoted", name)
		}
		end := -1
		escaped := false
		for i := 1; i < len(text); i++ {
			if escaped {
				escaped = false
				continue
			}
			if text[i] == '\\' {
				escaped = true
				continue
			}
			if text[i] == '"' {
				end = i
				break
			}
		}
		if end < 0 {
			return nil, fmt.Errorf("label %s is unterminated", name)
		}
		value, err := strconv.Unquote(text[:end+1])
		if err != nil {
			return nil, fmt.Errorf("label %s: %w", name, err)
		}
		if _, exists := labels[name]; exists {
			return nil, fmt.Errorf("duplicate label %s", name)
		}
		labels[name] = value
		text = strings.TrimSpace(text[end+1:])
		if text == "" {
			break
		}
		if text[0] != ',' {
			return nil, errors.New("labels must be comma separated")
		}
		text = text[1:]
	}
	return labels, nil
}

func writeRecoveryMeasurements(path string, sends []recoveryMeasurement, decoded map[int]decodedRecord) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{"identity", "phase", "epoch", "send_start_unix_nano", "send_end_unix_nano", "otlp_status", "otlp_error", "receipt_status", "frame", "receipt_unix_nano", "send_start_to_udp_receipt_ns"}); err != nil {
		return err
	}
	for _, send := range sends {
		status, receiptStatus, frame, receiptNanos, latency := "success", "not_observed", "", "", ""
		if send.failed {
			status = "failure"
		}
		if record, ok := decoded[send.identity]; ok {
			receiptStatus = "received"
			if send.failed {
				receiptStatus = "received_after_error"
			}
			frame = strconv.Itoa(record.frame)
			receipt := record.frameTime
			receiptNanos = strconv.FormatInt(receipt.UnixNano(), 10)
			delta := receipt.Sub(send.start)
			if delta < 0 {
				return fmt.Errorf("identity %d receipt precedes send start", send.identity)
			}
			latency = strconv.FormatInt(delta.Nanoseconds(), 10)
		} else if send.phase == "outage" {
			receiptStatus = "unobserved_socket_closed"
		}
		if err := w.Write([]string{strconv.Itoa(send.identity), send.phase, strconv.Itoa(send.epoch), strconv.FormatInt(send.start.UnixNano(), 10), strconv.FormatInt(send.end.UnixNano(), 10), status, send.errorText, receiptStatus, frame, receiptNanos, latency}); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return f.Sync()
}

type recoveryReceiptSummary struct {
	received, receivedFailed, missingSuccess, missingFailed int
	outageSuccess, outageFailed                             int
	outageUnobservedSuccess, outageUnobservedFailed         int
	reordered                                               bool
	offeredWindow, receiptWindow                            time.Duration
	callStats, latencyStats                                 durationSummary
}

func summarizeRecoveryReceipts(sends []recoveryMeasurement, decoded map[int]decodedRecord, packets []packet) (recoveryReceiptSummary, error) {
	var summary recoveryReceiptSummary
	if len(sends) == 0 || len(packets) == 0 {
		return summary, errors.New("recovery timing requires sends and captured packets")
	}
	sendByIdentity := make(map[int]recoveryMeasurement, len(sends))
	callDurations := make([]time.Duration, 0, len(sends))
	ordered := append([]recoveryMeasurement(nil), sends...)
	for _, send := range sends {
		if send.identity < 1 || send.identity > recoveryRecords || !send.end.After(send.start) {
			return summary, fmt.Errorf("invalid recovery timing identity=%d", send.identity)
		}
		if _, exists := sendByIdentity[send.identity]; exists {
			return summary, fmt.Errorf("duplicate recovery send identity %d", send.identity)
		}
		sendByIdentity[send.identity] = send
		callDurations = append(callDurations, send.end.Sub(send.start))
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].start.Equal(ordered[j].start) {
			return ordered[i].identity < ordered[j].identity
		}
		return ordered[i].start.Before(ordered[j].start)
	})
	if !ordered[len(ordered)-1].end.After(ordered[0].start) {
		return summary, errors.New("recovery offered timing window is not positive")
	}
	summary.offeredWindow = ordered[len(ordered)-1].end.Sub(ordered[0].start)
	rank := make(map[int]int, len(ordered))
	for index, send := range ordered {
		rank[send.identity] = index
	}
	decodedRecords := make([]decodedRecord, 0, len(decoded))
	for _, record := range decoded {
		decodedRecords = append(decodedRecords, record)
	}
	sort.Slice(decodedRecords, func(i, j int) bool { return decodedRecords[i].frame < decodedRecords[j].frame })
	latencies := make([]time.Duration, 0, len(decodedRecords))
	var firstReceipt, lastReceipt time.Time
	previousRank := -1
	for _, record := range decodedRecords {
		send, ok := sendByIdentity[record.identity]
		if !ok {
			return summary, fmt.Errorf("receipt identity %d has no send timing", record.identity)
		}
		if record.frame < 1 || record.frame > len(packets) {
			return summary, fmt.Errorf("receipt identity %d references frame %d outside %d packets", record.identity, record.frame, len(packets))
		}
		receipt := packets[record.frame-1].t
		if receipt.Before(send.start) {
			return summary, fmt.Errorf("receipt identity %d precedes send start", record.identity)
		}
		latencies = append(latencies, receipt.Sub(send.start))
		if firstReceipt.IsZero() || receipt.Before(firstReceipt) {
			firstReceipt = receipt
		}
		if lastReceipt.IsZero() || receipt.After(lastReceipt) {
			lastReceipt = receipt
		}
		if current := rank[record.identity]; current < previousRank {
			summary.reordered = true
		}
		previousRank = rank[record.identity]
		summary.received++
		if send.failed {
			summary.receivedFailed++
		}
	}
	if !firstReceipt.IsZero() {
		summary.receiptWindow = lastReceipt.Sub(firstReceipt)
	}
	for _, send := range sends {
		if send.phase == "outage" {
			if send.failed {
				summary.outageFailed++
			} else {
				summary.outageSuccess++
			}
			if _, observed := decoded[send.identity]; !observed {
				if send.failed {
					summary.outageUnobservedFailed++
				} else {
					summary.outageUnobservedSuccess++
				}
			}
			continue
		}
		if _, ok := decoded[send.identity]; ok {
			continue
		}
		if send.failed {
			summary.missingFailed++
		} else {
			summary.missingSuccess++
		}
	}
	summary.callStats = summarizeDurations(callDurations)
	summary.latencyStats = summarizeDurations(latencies)
	return summary, nil
}

func decodeRecoveryEpoch(ctx context.Context, root string, name string, p protocol, packets []packet, first, last int) (decodeResult, error) {
	if len(packets) == 0 {
		return decodeResult{}, fmt.Errorf("%s epoch has no packets", name)
	}
	path := filepath.Join(root, name+".pcap")
	if err := writePCAP(path, packets, 40000, p.port); err != nil {
		return decodeResult{}, err
	}
	decoded, err := decodeExpected(ctx, path, p.port, p.version, len(packets))
	if err != nil {
		return decoded, err
	}
	if err := verifyIdentityRange(decoded.identities, first, last); err != nil {
		return decoded, err
	}
	return decoded, nil
}

// decodeResumedFresh runs a new TShark process over only the post-rebind
// capture. The exporter retains its template state, so the first resumed data
// packets are expected to be structurally valid Set 300 frames that TShark
// cannot project until a refresh template arrives. This parser accepts only
// that precise transition and rejects arbitrary decoder/tool failures.
func decodeResumedFresh(ctx context.Context, path string, p protocol, expectedFrames int) (decodeResult, []int, error) {
	var out limitedBuffer
	out.limit = outputCap
	decodeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(decodeCtx, tsharkExecutable(), "-r", path, "-d", fmt.Sprintf("udp.port==%d,cflow", p.port), "-T", "fields", "-E", "separator=|", "-E", "occurrence=a", "-e", "frame.number", "-e", "cflow.version", "-e", "cflow.flowset_id", "-e", "cflow.template_id", "-e", "cflow.srcaddr", "-e", "cflow.srcport", "-e", "frame.time_epoch")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return decodeResult{text: out.String()}, nil, fmt.Errorf("TShark resumed fresh-cache command: %w", err)
	}
	return parseResumedFreshFields(out.String(), p, expectedFrames)
}

// parseResumedFreshFields validates the structured fields emitted by the
// independent resumed-capture TShark process. Keeping this parser separate
// makes the cache transition and its negative controls testable without a
// live capture or decoder.
func parseResumedFreshFields(text string, p protocol, expectedFrames int) (decodeResult, []int, error) {
	result := decodeResult{firstData: -1, firstTempl: -1, lastTempl: -1, lastBootstrap: -1, text: strings.TrimSpace(text)}
	preTemplateFrames := make([]int, 0)
	if result.text == "" {
		return result, preTemplateFrames, errors.New("TShark resumed fresh-cache output is empty")
	}
	seenFrames := make(map[int]struct{})
	template300Seen := false
	postTemplateRecords := 0
	for lineNumber, line := range strings.Split(result.text, "\n") {
		fields := strings.Split(line, "|")
		if len(fields) != 7 || fields[1] != strconv.Itoa(p.version) {
			return result, preTemplateFrames, fmt.Errorf("TShark resumed frame line %d is short or has version %q, want %d", lineNumber+1, fieldAt(fields, 1), p.version)
		}
		frame, err := strconv.Atoi(fields[0])
		if err != nil || frame != lineNumber+1 {
			return result, preTemplateFrames, fmt.Errorf("TShark resumed frame line %d has invalid or out-of-order frame %q", lineNumber+1, fields[0])
		}
		if _, exists := seenFrames[frame]; exists {
			return result, preTemplateFrames, fmt.Errorf("TShark resumed duplicate frame %d", frame)
		}
		seenFrames[frame] = struct{}{}
		flowsets := splitFields(fields[2])
		templateIDs := splitFields(fields[3])
		sources := splitFields(fields[4])
		sourcePorts := splitFields(fields[5])
		templateFlowset := "0"
		if p.version == 10 {
			templateFlowset = "2"
		}
		for _, id := range flowsets {
			if id != templateFlowset && id != "300" {
				return result, preTemplateFrames, fmt.Errorf("resumed frame %d contains unexpected flowset %q", frame, id)
			}
		}
		hasTemplateSet := contains(flowsets, templateFlowset)
		hasDataSet := contains(flowsets, "300")
		if hasTemplateSet && hasDataSet {
			return result, preTemplateFrames, fmt.Errorf("resumed frame %d mixes template and data flowsets", frame)
		}
		if hasTemplateSet && len(templateIDs) == 0 {
			return result, preTemplateFrames, fmt.Errorf("resumed template frame %d has no template ID", frame)
		}
		if hasDataSet && len(templateIDs) != 0 {
			return result, preTemplateFrames, fmt.Errorf("resumed data frame %d unexpectedly has template IDs", frame)
		}
		if !hasTemplateSet && len(templateIDs) != 0 {
			return result, preTemplateFrames, fmt.Errorf("resumed frame %d has template IDs without a template flowset", frame)
		}
		if hasTemplateSet {
			if len(sources) != 0 || len(sourcePorts) != 0 {
				return result, preTemplateFrames, fmt.Errorf("resumed frame %d mixes template and data fields", frame)
			}
			for _, id := range templateIDs {
				if id != "300" && id != "301" {
					return result, preTemplateFrames, fmt.Errorf("resumed frame %d has unexpected template id %q", frame, id)
				}
				if id == "300" {
					result.template300 = true
				}
			}
			result.templates += len(templateIDs)
			if result.firstTempl < 0 {
				result.firstTempl = frame
			}
			result.lastTempl = frame
			if result.firstData < 0 {
				result.lastBootstrap = frame
			}
			if contains(templateIDs, "300") {
				template300Seen = true
			}
			continue
		}
		if len(sources) != len(sourcePorts) {
			return result, preTemplateFrames, fmt.Errorf("resumed frame %d source/port occurrence mismatch: %d/%d", frame, len(sources), len(sourcePorts))
		}
		if len(sources) == 0 {
			if p.version == 5 || !contains(flowsets, "300") || template300Seen {
				return result, preTemplateFrames, fmt.Errorf("resumed frame %d is not the expected pre-template Set 300 data frame", frame)
			}
			if _, err := parseEpoch(fields[6]); err != nil {
				return result, preTemplateFrames, fmt.Errorf("resumed pre-template frame %d has invalid frame time %q: %w", frame, fields[6], err)
			}
			preTemplateFrames = append(preTemplateFrames, frame)
			continue
		}
		if p.version != 5 && (!contains(flowsets, "300") || !template300Seen) {
			return result, preTemplateFrames, fmt.Errorf("resumed frame %d decoded data without a preceding template 300", frame)
		}
		for i, source := range sources {
			if source != "192.0.2.1" {
				return result, preTemplateFrames, fmt.Errorf("resumed frame %d has unexpected source %q", frame, source)
			}
			identity, err := strconv.Atoi(sourcePorts[i])
			if err != nil || identity < 1 || identity > 65535 {
				return result, preTemplateFrames, fmt.Errorf("resumed frame %d has invalid source-port %q", frame, sourcePorts[i])
			}
			frameTime, err := parseEpoch(fields[6])
			if err != nil {
				return result, preTemplateFrames, fmt.Errorf("resumed frame %d has invalid frame time %q: %w", frame, fields[6], err)
			}
			result.records++
			postTemplateRecords++
			if result.firstData < 0 {
				result.firstData = frame
			}
			result.identities = append(result.identities, decodedRecord{frame: frame, identity: identity, frameTime: frameTime, frameTimeText: fields[6]})
		}
	}
	if len(seenFrames) != expectedFrames {
		return result, preTemplateFrames, fmt.Errorf("TShark resumed decoded %d frames, want %d", len(seenFrames), expectedFrames)
	}
	if p.version == 5 {
		return result, preTemplateFrames, nil
	}
	if !result.template300 || len(preTemplateFrames) == 0 || postTemplateRecords == 0 {
		return result, preTemplateFrames, fmt.Errorf("resumed fresh-cache transition lacks template300/pre-template/post-template data: template=%t pre=%d post=%d", result.template300, len(preTemplateFrames), postTemplateRecords)
	}
	return result, preTemplateFrames, nil
}

func verifyIdentitySubset(got []decodedRecord, first, last int) error {
	seen := make(map[int]struct{}, len(got))
	for _, record := range got {
		if record.identity < first || record.identity > last {
			return fmt.Errorf("decoded identity %d outside %d..%d", record.identity, first, last)
		}
		if _, ok := seen[record.identity]; ok {
			return fmt.Errorf("decoded duplicate identity %d", record.identity)
		}
		seen[record.identity] = struct{}{}
	}
	return nil
}

func verifyCombinedRecovery(decoded decodeResult, warmFrames int) (map[int]decodedRecord, map[int]decodedRecord, error) {
	if decoded.records != len(decoded.identities) || decoded.records < recoveryWarmRecords {
		return nil, nil, fmt.Errorf("combined decoded records=%d, identities=%d; warm receipt cannot be partial", decoded.records, len(decoded.identities))
	}
	byIdentity := make(map[int]decodedRecord, len(decoded.identities))
	byResumeFrame := make(map[int]decodedRecord, recoveryResumeRecords)
	frameSeen := make(map[int]struct{}, len(decoded.identities))
	for _, record := range decoded.identities {
		if record.identity >= recoveryWarmRecords+1 && record.identity <= recoveryWarmRecords+recoveryOutageRecords {
			return nil, nil, fmt.Errorf("combined decode observed outage identity %d", record.identity)
		}
		if record.identity < 1 || record.identity > recoveryRecords {
			return nil, nil, fmt.Errorf("combined decoded identity %d outside recovery range", record.identity)
		}
		if _, exists := byIdentity[record.identity]; exists {
			return nil, nil, fmt.Errorf("combined duplicate identity %d", record.identity)
		}
		if _, exists := frameSeen[record.frame]; exists {
			return nil, nil, fmt.Errorf("combined frame %d carries multiple decoded records", record.frame)
		}
		frameSeen[record.frame] = struct{}{}
		if record.identity <= recoveryWarmRecords {
			if record.frame > warmFrames {
				return nil, nil, fmt.Errorf("warm identity %d appears after receiver rebind at frame %d", record.identity, record.frame)
			}
		} else {
			if record.frame <= warmFrames {
				return nil, nil, fmt.Errorf("resumed identity %d appears in warm capture at frame %d", record.identity, record.frame)
			}
			byResumeFrame[record.frame-warmFrames] = record
		}
		byIdentity[record.identity] = record
	}
	for identity := 1; identity <= recoveryWarmRecords; identity++ {
		if _, ok := byIdentity[identity]; !ok {
			return nil, nil, fmt.Errorf("combined decode missing warm identity %d", identity)
		}
	}
	return byIdentity, byResumeFrame, nil
}

func compareFreshResumedToOracle(fresh decodeResult, preFrames []int, oracle map[int]decodedRecord, version int) error {
	if len(preFrames) == 0 && version != 5 {
		return errors.New("fresh resumed decode observed no pre-template data frames")
	}
	if version != 5 && len(fresh.identities) == 0 {
		return errors.New("fresh resumed decode observed no post-refresh records")
	}
	seen := make(map[int]struct{}, len(fresh.identities))
	covered := make(map[int]struct{}, len(oracle))
	for _, frame := range preFrames {
		if _, duplicate := covered[frame]; duplicate {
			return fmt.Errorf("pre-template frame %d is duplicated", frame)
		}
		if _, ok := oracle[frame]; !ok {
			return fmt.Errorf("pre-template frame %d has no warm-cache identity", frame)
		}
		covered[frame] = struct{}{}
	}
	if err := verifyIdentitySubset(fresh.identities, recoveryWarmRecords+recoveryOutageRecords+1, recoveryRecords); err != nil {
		return err
	}
	for _, record := range fresh.identities {
		want, ok := oracle[record.frame]
		if !ok {
			return fmt.Errorf("fresh resumed frame %d has no warm-cache identity", record.frame)
		}
		if want.identity != record.identity {
			return fmt.Errorf("fresh resumed frame %d identity=%d, warm-cache identity=%d", record.frame, record.identity, want.identity)
		}
		if _, exists := seen[record.identity]; exists {
			return fmt.Errorf("fresh resumed duplicate identity %d", record.identity)
		}
		seen[record.identity] = struct{}{}
		if _, exists := covered[record.frame]; exists {
			return fmt.Errorf("fresh resumed frame %d is covered more than once", record.frame)
		}
		covered[record.frame] = struct{}{}
	}
	if len(covered) != len(oracle) {
		return fmt.Errorf("fresh resumed frame partition covers %d oracle records, want %d", len(covered), len(oracle))
	}
	return nil
}

func verifyIdentityRange(got []decodedRecord, first, last int) error {
	if first < 1 || last < first || len(got) != last-first+1 {
		return fmt.Errorf("decoded identity count %d, want range %d..%d", len(got), first, last)
	}
	seen := map[int]struct{}{}
	for i, record := range got {
		want := first + i
		if record.identity != want {
			return fmt.Errorf("decoded identity %d at position %d, want %d", record.identity, i, want)
		}
		if _, ok := seen[record.identity]; ok {
			return fmt.Errorf("decoded duplicate identity %d", record.identity)
		}
		seen[record.identity] = struct{}{}
	}
	return nil
}

func runRecoveryCaseContext(parent context.Context, root, collector string, p protocol) (err error) {
	if root == "" || collector == "" {
		return errors.New("artifact root and collector are required")
	}
	if err = os.Mkdir(root, 0o700); err != nil {
		return err
	}
	defer func() {
		status := "pass"
		if err != nil {
			status = "nonpassing"
		}
		text := fmt.Sprintf("status=%s\nerror=%s\n", status, boundedErrorText(err))
		if writeErr := os.WriteFile(filepath.Join(root, "qualification.txt"), []byte(text), 0o600); err == nil {
			err = writeErr
		}
	}()
	defer func() {
		if e := checkArtifactCap(root); err == nil {
			err = e
		}
	}()
	warm, err := newCapture()
	if err != nil {
		return err
	}
	defer func() {
		_, closeErr := warm.closeCapture()
		if err == nil {
			err = closeErr
		}
	}()
	outPort := warm.conn.LocalAddr().(*net.UDPAddr).Port
	ports, err := freePorts(3)
	if err != nil {
		return err
	}
	in, pprofPort, metricsPort := ports[0], ports[1], ports[2]
	configPath := filepath.Join(root, "collector.yaml")
	recoveryConfig, configErr := recoveryConfigFor(p, in, outPort, pprofPort, metricsPort)
	if configErr != nil {
		return configErr
	}
	if err = os.WriteFile(configPath, []byte(recoveryConfig), 0o600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, caseTimeout)
	defer cancel()
	clockTicks, err := procClockTicks(ctx)
	if err != nil {
		return fmt.Errorf("/proc CPU clock: %w", err)
	}
	collectorID, err := collectorBuildID(ctx, collector)
	if err != nil {
		return fmt.Errorf("Collector build ID: %w", err)
	}
	proc, err := startChild(ctx, collector, configPath, filepath.Join(root, "collector.log"))
	if err != nil {
		return err
	}
	defer func() {
		if stopErr := proc.stopProcess(); err == nil && stopErr != nil {
			err = stopErr
		}
	}()
	if err = waitPprof(ctx, pprofPort, proc); err != nil {
		return err
	}
	fdLimit, err := collectorFDLimit(proc.cmd.Process.Pid)
	if err != nil {
		return fmt.Errorf("collector fd limit: %w", err)
	}
	if err = os.WriteFile(filepath.Join(root, "collector.fd-limit"), []byte(fdLimit+"\n"), 0o600); err != nil {
		return err
	}
	procMetrics, err := startProcSampler(proc.cmd.Process.Pid)
	if err != nil {
		return fmt.Errorf("start /proc sampler: %w", err)
	}
	defer func() {
		if _, sampleErr := procMetrics.stopSampling(); err == nil && sampleErr != nil {
			err = fmt.Errorf("/proc sampler: %w", sampleErr)
		}
	}()

	provider := &canonicalProvider{limit: recoveryRecords, unique: true}
	sender := testbed.NewOTLPLogsDataSender("127.0.0.1", in)
	if err = sender.Start(); err != nil {
		return fmt.Errorf("start Testbed logs sender: %w", err)
	}
	sends := make([]recoveryMeasurement, 0, recoveryRecords)
	cpuPath := filepath.Join(root, "cpu.pb.gz")
	cpuDone := make(chan error, 1)
	go func() { cpuDone <- profile(ctx, pprofPort, "profile?seconds=2", cpuPath) }()
	if err = sendRecoveryPhase(ctx, sender, provider, recoveryWarmRecords, 1, "warm", &sends); err != nil {
		return err
	}
	// ConsumeLogs is synchronous at the Collector input boundary; let the
	// independent reader drain the kernel receive queue before this epoch is
	// closed and retained.
	time.Sleep(250 * time.Millisecond)
	warmPackets, err := warm.closeCapture()
	if err != nil {
		return err
	}
	if err = sendRecoveryPhase(ctx, sender, provider, recoveryOutageRecords, 0, "outage", &sends); err != nil {
		return err
	}
	// Rebind the exact endpoint only after the outage offers. The ledger retains
	// any late outage receipt; absence alone is labeled socket-closed.
	resumed, err := newCaptureOnPort(outPort)
	if err != nil {
		return fmt.Errorf("rebind receiver endpoint: %w", err)
	}
	defer func() {
		_, closeErr := resumed.closeCapture()
		if err == nil {
			err = closeErr
		}
	}()
	if err = sendRecoveryPhase(ctx, sender, provider, recoveryResumeRecords, 2, "resumed", &sends); err != nil {
		return err
	}
	time.Sleep(250 * time.Millisecond)
	resumedPackets, err := resumed.closeCapture()
	captureEnd := time.Now()
	if err != nil {
		return err
	}
	warmPeer, peerErr := capturePeer(warm)
	resumedPeer, resumedPeerErr := capturePeer(resumed)
	peerErr = errors.Join(peerErr, resumedPeerErr)
	if peerErr == nil && (!warmPeer.IP.Equal(resumedPeer.IP) || warmPeer.Port != resumedPeer.Port) {
		peerErr = fmt.Errorf("exporter UDP peer changed across receiver rebind: warm=%s resumed=%s", warmPeer, resumedPeer)
	}
	if provider.count.Load() != recoveryRecords {
		return fmt.Errorf("recovery offered %d records, want %d", provider.count.Load(), recoveryRecords)
	}
	if err = <-cpuDone; err != nil {
		return fmt.Errorf("CPU profile: %w", err)
	}
	telemetry, telemetryText, telemetryReadErr := readRecoveryMetrics(ctx, metricsPort)
	if err = os.WriteFile(filepath.Join(root, "collector.metrics"), []byte(telemetryText), 0o600); err != nil {
		return err
	}
	if err = profile(ctx, pprofPort, "heap", filepath.Join(root, "heap.pb.gz")); err != nil {
		return fmt.Errorf("heap profile: %w", err)
	}
	if err = profile(ctx, pprofPort, "heap?debug=1", filepath.Join(root, "heap-stats.txt")); err != nil {
		return fmt.Errorf("heap stats: %w", err)
	}
	if err = profile(ctx, pprofPort, "goroutine?debug=1", filepath.Join(root, "goroutine.txt")); err != nil {
		return fmt.Errorf("goroutine profile: %w", err)
	}
	time.Sleep(250 * time.Millisecond)
	procStats, err := procMetrics.stopSampling()
	if err != nil {
		return fmt.Errorf("/proc sampler: %w", err)
	}
	if err = proc.stopProcess(); err != nil {
		return err
	}

	evidence, qualificationErr := qualifyRecoveryOriginal(ctx, root, p, sends, telemetry, warmPackets, resumedPackets, captureEnd, errors.Join(telemetryReadErr, peerErr))
	if qualificationErr != nil {
		return qualificationErr
	}
	allPackets := append(append([]packet(nil), warmPackets...), resumedPackets...)
	decodedByIdentity, freshResumed, preFrames, receiptSummary := evidence.records, evidence.fresh, evidence.preFrames, evidence.receipts
	mutants, err := qualifyRecoveryMutants(ctx, root, p, sends, telemetry, warmPackets, resumedPackets, evidence)
	if err != nil {
		return err
	}
	if _, err = parseProfileForBuild(ctx, filepath.Join(root, "cpu.pb.gz"), collectorID); err != nil {
		return fmt.Errorf("CPU parse: %w", err)
	}
	if _, err = parseProfileForBuild(ctx, filepath.Join(root, "heap.pb.gz"), collectorID); err != nil {
		return fmt.Errorf("heap parse: %w", err)
	}
	if _, err = parseProfileForBuildIndex(ctx, filepath.Join(root, "heap.pb.gz"), collectorID, "alloc_space"); err != nil {
		return fmt.Errorf("alloc_space heap parse: %w", err)
	}
	heapStats, err := parseHeapStats(filepath.Join(root, "heap-stats.txt"))
	if err != nil {
		return fmt.Errorf("heap stats parse: %w", err)
	}
	goroutines, err := parseGoroutineCount(filepath.Join(root, "goroutine.txt"))
	if err != nil {
		return fmt.Errorf("goroutine parse: %w", err)
	}
	if procStats.after.userTicks < procStats.before.userTicks || procStats.after.systemTicks < procStats.before.systemTicks {
		return errors.New("/proc CPU counters moved backwards")
	}
	beforeCPU := procStats.before.userTicks + procStats.before.systemTicks
	afterCPU := procStats.after.userTicks + procStats.after.systemTicks
	warmDecodedRecords, resumedDecodedRecords := 0, 0
	for identity := range decodedByIdentity {
		switch {
		case identity >= 1 && identity <= recoveryWarmRecords:
			warmDecodedRecords++
		case identity >= recoveryWarmRecords+recoveryOutageRecords+1 && identity <= recoveryRecords:
			resumedDecodedRecords++
		}
	}
	var result strings.Builder
	fmt.Fprintf(&result, "protocol=%s\nscenario=recovery\nrecords_per_case=%d\nwarm_records=%d\noutage_records=%d\nresumed_records=%d\ntemplate_refresh_count=%d\noffered_records=%d\n", p.name, recoveryRecords, recoveryWarmRecords, recoveryOutageRecords, recoveryResumeRecords, recoveryTemplateRefreshCount, provider.count.Load())
	fmt.Fprintf(&result, "receiver_epoch_sequence=warm,closed_outage,resumed\nconsumer_outage_boundary=udp_socket_closed_before_outage_sends\noutage_identity_range=4..6\noutage_receipt_status=per_offer_observation_first\nindependent_udp_receipt=true\n")
	fmt.Fprintf(&result, "warm_received_datagrams=%d\nresumed_received_datagrams=%d\nwarm_decoded_records=%d\nresumed_decoded_records=%d\ncombined_received_datagrams=%d\ncombined_decoded_records=%d\n", len(warmPackets), len(resumedPackets), warmDecodedRecords, resumedDecodedRecords, len(allPackets), len(decodedByIdentity))
	fmt.Fprintf(&result, "collector_udp_peer_warm=%s\ncollector_udp_peer_resumed=%s\nendpoint_epochs=%d\n", warmPeer, resumedPeer, telemetry.endpointEpochs)
	postRefresh := "decoded_after_template300"
	if p.version == 5 {
		postRefresh = "immediate_decode_no_templates"
	}
	fmt.Fprintf(&result, "wire_decode=combined_fresh_tshark_with_warm_cache_plus_separate_fresh_resumed_tshark\ncombined_fields_artifact=tshark.combined.fields\nresumed_fields_artifact=tshark.resumed.fields\nfresh_cache_oracle_partition=all_resumed_data_frames_exactly_once\npre_template_frames=%d\npre_template_undecoded_records=%d\npost_template_records=%d\nfresh_cache_template300_seen=%t\nfresh_cache_first_any_template_frame=%d\nfresh_cache_pre_refresh_result=%s\npost_refresh_cache_result=%s\n", len(preFrames), len(preFrames), freshResumed.records, freshResumed.template300, freshResumed.firstTempl, preRefreshResult(p), postRefresh)
	if p.version == 5 {
		fmt.Fprintln(&result, "fresh_cache_transition=not_applicable_v5")
	} else {
		fmt.Fprintln(&result, "fresh_cache_transition=pre_template_set300_undecoded_then_template300_then_decoded_records")
		fmt.Fprintln(&result, "pre_refresh_fields_artifact=tshark.pre-refresh.fields")
	}
	fmt.Fprintf(&result, "header_qualification=pass\nheader_ledger_artifact=header-ledger.json\nheader_views=warm,combined,resumed\nheader_origin=independent_tshark\nheader_negative_controls=%d\nheader_negative_controls_artifact=mutants.csv\n", mutants)
	fmt.Fprintf(&result, "receipt_outage_unobserved_success=%d\nreceipt_outage_unobserved_failed=%d\n", receiptSummary.outageUnobservedSuccess, receiptSummary.outageUnobservedFailed)
	fmt.Fprintln(&result, "exporter_handoff_metrics=collector_internal_prometheus_pull")
	fmt.Fprintf(&result, "otlp_attempts=%d\notlp_successes=%d\notlp_failures=%d\notlp_call_rate_per_second=%.6f\n", len(sends), countSuccesses(sends), len(sends)-countSuccesses(sends), ratePerSecond(len(sends), receiptSummary.offeredWindow))
	fmt.Fprintf(&result, "receipt_retained_records=%d\nreceipt_received_after_otlp_error=%d\nreceipt_missing_scope=warm_and_resumed_active_receiver_only\nreceipt_missing_success=%d\nreceipt_missing_failed=%d\nreceipt_active_receiver_missing_success=%d\nreceipt_active_receiver_missing_failed=%d\nreceipt_outage_success=%d\nreceipt_outage_failed=%d\nreceipt_reordered=%t\nreceipt_rate_per_second=%.6f\n", receiptSummary.received, receiptSummary.receivedFailed, receiptSummary.missingSuccess, receiptSummary.missingFailed, receiptSummary.missingSuccess, receiptSummary.missingFailed, receiptSummary.outageSuccess, receiptSummary.outageFailed, receiptSummary.reordered, ratePerSecond(receiptSummary.received, receiptSummary.receiptWindow))
	fmt.Fprintf(&result, "offered_window_ns=%d\nreceipt_window_ns=%d\n", receiptSummary.offeredWindow.Nanoseconds(), receiptSummary.receiptWindow.Nanoseconds())
	appendRecoveryDuration(&result, "otlp_call", receiptSummary.callStats)
	appendRecoveryDuration(&result, "udp_receipt_latency", receiptSummary.latencyStats)
	fmt.Fprintf(&result, "exporter_admission_accepted=%d\nexporter_admission_busy=%d\nexporter_admission_closed=%d\nexporter_admission_preflight=%d\nexporter_admission_invalid_context=%d\n", telemetry.admissionAccepted, telemetry.admissionBusy, telemetry.admissionClosed, telemetry.admissionPreflight, telemetry.admissionInvalidContext)
	appendRecoveryMetricMap(&result, "exporter_records", telemetry.records, false)
	appendRecoveryMetricMap(&result, "exporter_data_messages", telemetry.dataMessages, false)
	appendRecoveryMetricMap(&result, "exporter_templates", telemetry.templates, true)
	appendRecoveryMetricMap(&result, "exporter_bytes", telemetry.bytes, true)
	appendRecoveryMetricMap(&result, "exporter_failures", telemetry.failures, false)
	appendRecoveryMetricMap(&result, "exporter_losses", telemetry.losses, false)
	fmt.Fprintln(&result, "telemetry_equations=admissions_equal_otlp_calls;records_equal_accepted;confirmed_equal_successes;one_record_data_messages_reconciled")
	fmt.Fprintln(&result, "telemetry_conditional_absence_policy=validated_active_series_then_absent_series_zero")
	fmt.Fprintf(&result, "collector_metrics_artifact=collector.metrics\nmeasurements_artifact=measurements.csv\ncollector_fd_limit=%s\nproc_pid=%d\nproc_cpu_user_hz=%d\nproc_cpu_seconds_delta=%.6f\nproc_rss_kb_before=%d\nproc_rss_kb_after=%d\nproc_rss_kb_peak=%d\nproc_samples=%d\ngoroutine_count=%d\nheap_stats=%s\nrun_end_unix_nano=%d\n", strings.TrimSpace(fdLimit), proc.cmd.Process.Pid, clockTicks, float64(afterCPU-beforeCPU)/float64(clockTicks), procStats.before.rssKB, procStats.after.rssKB, procStats.peakRSS, procStats.samples, goroutines, strings.TrimSpace(heapStats), time.Now().UnixNano())
	return os.WriteFile(filepath.Join(root, "result.txt"), []byte(result.String()), 0o600)
}

func countSuccesses(sends []recoveryMeasurement) int {
	count := 0
	for _, send := range sends {
		if !send.failed {
			count++
		}
	}
	return count
}

func validateRecoveryTelemetry(telemetry recoveryTelemetry, sends []recoveryMeasurement) (int64, error) {
	attempts := int64(len(sends))
	successes := int64(countSuccesses(sends))
	if err := validateRecoveryTelemetryNonnegative(telemetry); err != nil {
		return 0, err
	}
	admissionObserved := telemetry.admissionAccepted + telemetry.admissionBusy + telemetry.admissionClosed + telemetry.admissionPreflight + telemetry.admissionInvalidContext
	if admissionObserved != attempts {
		return 0, fmt.Errorf("admission telemetry=%d does not reconcile to OTLP attempts=%d", admissionObserved, attempts)
	}
	records := telemetry.records["confirmed"] + telemetry.records["ambiguous"] + telemetry.records["unsent"] + telemetry.records["invalid"]
	if records != telemetry.admissionAccepted {
		return 0, fmt.Errorf("record outcome telemetry=%d does not reconcile to accepted admissions=%d", records, telemetry.admissionAccepted)
	}
	if telemetry.records["confirmed"] != telemetry.dataMessages["confirmed"] || telemetry.records["ambiguous"] != telemetry.dataMessages["ambiguous"] {
		return 0, fmt.Errorf("one-record data telemetry mismatch: records confirmed/ambiguous=%d/%d data=%d/%d", telemetry.records["confirmed"], telemetry.records["ambiguous"], telemetry.dataMessages["confirmed"], telemetry.dataMessages["ambiguous"])
	}
	for _, kind := range []string{"data", "bootstrap", "refresh"} {
		for _, outcome := range []string{"confirmed", "ambiguous"} {
			key := kind + "/" + outcome
			messages := telemetry.templates[key]
			if kind == "data" {
				messages = telemetry.dataMessages[outcome]
			}
			bytes := telemetry.bytes[key]
			if (messages == 0) != (bytes == 0) || bytes < messages {
				return 0, fmt.Errorf("handoff byte/message telemetry mismatch for %s: bytes=%d messages=%d", key, bytes, messages)
			}
		}
	}
	if telemetry.records["confirmed"] != successes {
		return 0, fmt.Errorf("confirmed record telemetry=%d does not reconcile to successful OTLP calls=%d", telemetry.records["confirmed"], successes)
	}
	if telemetry.records["invalid"] != 0 || telemetry.admissionPreflight != 0 || telemetry.admissionClosed != 0 || telemetry.admissionInvalidContext != 0 || telemetry.failures["internal"] != 0 || telemetry.failures["unavailable"] != 0 || telemetry.failures["candidate"] != 0 || telemetry.failures["bootstrap"] != 0 {
		return 0, fmt.Errorf("unexpected invalid/preflight/closed/context/internal/unavailable/candidate/bootstrap telemetry: invalid=%d preflight=%d closed=%d invalid_context=%d internal=%d unavailable=%d candidate=%d bootstrap=%d", telemetry.records["invalid"], telemetry.admissionPreflight, telemetry.admissionClosed, telemetry.admissionInvalidContext, telemetry.failures["internal"], telemetry.failures["unavailable"], telemetry.failures["candidate"], telemetry.failures["bootstrap"])
	}
	if telemetry.failures["busy"] != telemetry.admissionBusy {
		return 0, fmt.Errorf("busy failure telemetry=%d does not match busy admissions=%d", telemetry.failures["busy"], telemetry.admissionBusy)
	}
	if telemetry.failures["closed"] != telemetry.admissionClosed {
		return 0, fmt.Errorf("closed failure telemetry=%d does not match closed admissions=%d", telemetry.failures["closed"], telemetry.admissionClosed)
	}
	failures := attempts - successes
	expectedFailures := (attempts - telemetry.admissionAccepted) + telemetry.records["ambiguous"] + telemetry.records["unsent"] + telemetry.records["invalid"]
	if failures != expectedFailures {
		return 0, fmt.Errorf("OTLP failures=%d do not reconcile to nonaccepted admissions plus ambiguous/unsent/invalid records=%d", failures, expectedFailures)
	}
	return attempts - admissionObserved, nil
}

func validateRecoveryTelemetryNonnegative(telemetry recoveryTelemetry) error {
	if telemetry.admissionAccepted < 0 || telemetry.admissionBusy < 0 || telemetry.admissionClosed < 0 || telemetry.admissionPreflight < 0 || telemetry.admissionInvalidContext < 0 || telemetry.endpointEpochs < 0 {
		return errors.New("recovery telemetry contains a negative admission or endpoint count")
	}
	for family, metrics := range map[string]map[string]int64{
		"records": telemetry.records, "data_messages": telemetry.dataMessages, "templates": telemetry.templates,
		"failures": telemetry.failures, "bytes": telemetry.bytes, "losses": telemetry.losses,
	} {
		for key, value := range metrics {
			if value < 0 {
				return fmt.Errorf("recovery telemetry %s/%s is negative: %d", family, key, value)
			}
		}
	}
	return nil
}

func appendRecoveryMetricMap(result *strings.Builder, prefix string, metrics map[string]int64, compositeOnly bool) {
	keys := recoveryMetricKeys(prefix, compositeOnly)
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		seen[key] = struct{}{}
	}
	for key := range metrics {
		isComposite := strings.Contains(key, "/")
		if isComposite != compositeOnly {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		keys = append(keys, key)
		seen[key] = struct{}{}
	}
	sort.Strings(keys)
	for _, originalKey := range keys {
		outputKey := strings.ReplaceAll(originalKey, "/", "_")
		fmt.Fprintf(result, "%s_%s=%d\n", prefix, outputKey, metrics[originalKey])
	}
}

func recoveryMetricKeys(prefix string, compositeOnly bool) []string {
	if compositeOnly {
		switch prefix {
		case "exporter_templates":
			return []string{"bootstrap/ambiguous", "bootstrap/confirmed", "refresh/ambiguous", "refresh/confirmed"}
		case "exporter_bytes":
			return []string{"bootstrap/ambiguous", "bootstrap/confirmed", "data/ambiguous", "data/confirmed", "refresh/ambiguous", "refresh/confirmed"}
		}
		return nil
	}
	switch prefix {
	case "exporter_records":
		return []string{"ambiguous", "confirmed", "invalid", "unsent"}
	case "exporter_data_messages":
		return []string{"ambiguous", "confirmed"}
	case "exporter_failures":
		return []string{"bootstrap", "busy", "candidate", "closed", "internal", "refresh", "unavailable"}
	case "exporter_losses":
		return []string{"canonical_source", "exporter"}
	}
	return nil
}

func appendRecoveryDuration(result *strings.Builder, prefix string, summary durationSummary) {
	fmt.Fprintf(result, "%s_count=%d\n%s_min_ns=%d\n%s_p50_ns=%d\n%s_p95_ns=%d\n%s_max_ns=%d\n", prefix, summary.count, prefix, summary.min.Nanoseconds(), prefix, summary.p50.Nanoseconds(), prefix, summary.p95.Nanoseconds(), prefix, summary.max.Nanoseconds())
}

func preRefreshResult(p protocol) string {
	if p.version == 5 {
		return "not_applicable_v5"
	}
	return "structured_set300_undecoded_before_template300"
}

// Headers are observations from TShark, including data frames for which a
// fresh cache cannot decode a record. Raw payload reads are used only to make
// negative controls; none supplies an expected or observed oracle value.
const recoveryDecoderCap = 64 << 10
const recoveryFrameCap = 64

type recoveryHeader struct {
	Frame                                              int
	Sequence, EngineType, EngineID, SourceID, DomainID uint32
	TemplateID                                         int // zero is a one-record data packet
}

type recoveryHeaderView struct {
	headers []recoveryHeader
	fields  string // the existing decoder's seven record/cache fields
}

// Do not embed bytes.Buffer: its promoted ReadFrom lets io.Copy (used by
// os/exec) bypass Write and therefore bypass an output limit.
type recoveryDecoderOutput struct {
	buffer bytes.Buffer
}

func (b *recoveryDecoderOutput) Write(p []byte) (int, error) {
	remaining := recoveryDecoderCap - b.buffer.Len()
	if len(p) > remaining {
		n, _ := b.buffer.Write(p[:remaining])
		return n, io.ErrShortWrite
	}
	return b.buffer.Write(p)
}

func (b *recoveryDecoderOutput) String() string { return b.buffer.String() }
func (b *recoveryDecoderOutput) Len() int       { return b.buffer.Len() }

func recoveryScalar(s string, bits int) (uint32, error) {
	if s == "" {
		return 0, errors.New("missing scalar")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("malformed or repeated scalar %q", s)
		}
	}
	n, err := strconv.ParseUint(s, 10, bits)
	return uint32(n), err
}

// Columns: frame, version, sequence, engine type, engine ID, source ID,
// observation domain ID, flowset ID, template ID. All occurrences are retained
// by TShark so missing, repeated and overflowing values fail closed.
func parseRecoveryHeaders(text string, p protocol, frames int) ([]recoveryHeader, error) {
	var headers []recoveryHeader
	if frames < 0 || frames > recoveryFrameCap || len(text) > recoveryDecoderCap {
		return headers, errors.New("header input exceeds bounded frame/byte range")
	}
	if frames == 0 && text == "" {
		return headers, nil
	}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		f := strings.Split(line, "|")
		if len(f) != 9 {
			return headers, errors.New("header row does not have nine fields")
		}
		frame, err := recoveryScalar(f[0], 32)
		if err != nil || int(frame) != len(headers)+1 || f[1] != strconv.Itoa(p.version) {
			return headers, fmt.Errorf("header frame/version invalid at row %d", len(headers)+1)
		}
		h := recoveryHeader{Frame: int(frame)}
		if h.Sequence, err = recoveryScalar(f[2], 32); err != nil {
			return headers, fmt.Errorf("header sequence frame %d: %w", frame, err)
		}
		for i, dst := range []*uint32{&h.EngineType, &h.EngineID, &h.SourceID, &h.DomainID} {
			applicable := p.version == 5 && i < 2 || p.version == 9 && i == 2 || p.version == 10 && i == 3
			if !applicable {
				if f[3+i] != "" {
					return headers, fmt.Errorf("header inapplicable identity at frame %d", frame)
				}
				continue
			}
			bits := 32
			if p.version == 5 {
				bits = 8
			}
			if *dst, err = recoveryScalar(f[3+i], bits); err != nil {
				return headers, fmt.Errorf("header identity frame %d column %d: %w", frame, i, err)
			}
		}
		templateSet := "0"
		if p.version == 10 {
			templateSet = "2"
		}
		switch {
		case p.version == 5:
			if f[7] != "" || f[8] != "" {
				return headers, errors.New("v5 header has template fields")
			}
		case f[7] == templateSet && (f[8] == "300" || f[8] == "301"):
			h.TemplateID, _ = strconv.Atoi(f[8])
		case f[7] == "300" && f[8] == "":
		default:
			return headers, fmt.Errorf("header template/data partition invalid at frame %d", frame)
		}
		headers = append(headers, h)
	}
	if len(headers) != frames {
		return headers, fmt.Errorf("header frames=%d want=%d", len(headers), frames)
	}
	return headers, nil
}

// A separate bounded command leaves shared decoders and their five-second
// limits untouched. Stdout and stderr cannot contaminate each other's parser.
func decodeRecoveryHeaders(ctx context.Context, root, name string, p protocol, frames int) (recoveryHeaderView, error) {
	var view recoveryHeaderView
	path := filepath.Join(root, name+".pcap")
	info, err := os.Stat(path)
	if err != nil {
		return view, err
	}
	if info.Size() > recoveryDecoderCap || frames < 0 || frames > recoveryFrameCap {
		return view, errors.New("recovery decoder input cap exceeded")
	}
	decodeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	args := []string{"-r", path, "-d", fmt.Sprintf("udp.port==%d,cflow", p.port), "-T", "fields", "-E", "separator=|", "-E", "occurrence=a"}
	for _, field := range []string{"frame.number", "cflow.version", "cflow.flowset_id", "cflow.template_id", "cflow.srcaddr", "cflow.srcport", "frame.time_epoch", "cflow.sequence", "cflow.engine_type", "cflow.engine_id", "cflow.source_id", "cflow.od_id"} {
		args = append(args, "-e", field)
	}
	out, stderr := &recoveryDecoderOutput{}, &recoveryDecoderOutput{}
	cmd := exec.CommandContext(decodeCtx, tsharkExecutable(), args...)
	cmd.Stdout, cmd.Stderr = out, stderr
	commandErr := cmd.Run()
	for suffix, text := range map[string]string{".headers.fields": out.String(), ".headers.stderr": stderr.String()} {
		if err := os.WriteFile(filepath.Join(root, name+suffix), []byte(text), 0o600); err != nil {
			return view, err
		}
	}
	if commandErr != nil {
		return view, fmt.Errorf("recovery TShark command: %w", errors.Join(commandErr, decodeCtx.Err()))
	}
	if frames == 0 && out.Len() == 0 {
		return view, nil
	}
	var records, headers []string
	for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		f := strings.Split(line, "|")
		if len(f) != 12 {
			return view, errors.New("recovery TShark output does not have twelve fields")
		}
		records = append(records, strings.Join(f[:7], "|"))
		headers = append(headers, strings.Join(append(append([]string{f[0], f[1]}, f[7:]...), f[2:4]...), "|"))
	}
	view.fields = strings.Join(records, "\n")
	view.headers, err = parseRecoveryHeaders(strings.Join(headers, "\n"), p, frames)
	return view, err
}

type recoveryOfferRow struct {
	Identity, ReceiverEpoch int
	Phase, Outcome, Receipt string
	Start, End              time.Time
	Committed               bool
	PriorCommits            int
	ExpectedSequence        *uint32
	Frame                   int
}

type recoveryPacketRow struct {
	Frame, ViewFrame, ReceiverEpoch int
	View, Kind, FreshCache          string
	RecordID                        int
	Header, OtherViewHeader         *recoveryHeader
	ExpectedSequence                *uint32
	SequenceCharge                  int
	Association                     string
}

type recoveryHeaderLedger struct {
	CaptureEnd      time.Time
	Status          string
	Problems        []string
	CommitInference bool
	Offers          []recoveryOfferRow
	Packets         []recoveryPacketRow
}

func (l *recoveryHeaderLedger) problem(format string, args ...any) {
	l.Problems = append(l.Problems, fmt.Sprintf(format, args...))
}

func (l *recoveryHeaderLedger) result() error {
	l.Status = "pass"
	if len(l.Problems) == 0 {
		return nil
	}
	l.Status = "nonpassing"
	return errors.New(strings.Join(l.Problems, "; "))
}

// Build every offer and received-frame row before checking fixture guards.
// Missing receipts never determine commits. Only reconciled synchronous call
// outcomes do, and ambiguous templates prevent exact template qualification.
func buildRecoveryHeaderLedger(p protocol, sends []recoveryMeasurement, telemetry recoveryTelemetry, combined decodeResult, warm, headers, fresh []recoveryHeader, preFrames []int, warmFrames, totalFrames int, captureEnd time.Time) (recoveryHeaderLedger, error) {
	l := recoveryHeaderLedger{CaptureEnd: captureEnd}
	byIdentity, byFrame := map[int]decodedRecord{}, map[int]decodedRecord{}
	for _, r := range combined.identities {
		if _, ok := byIdentity[r.identity]; ok {
			l.problem("duplicate record identity %d", r.identity)
		}
		if _, ok := byFrame[r.frame]; ok {
			l.problem("multiple records at frame %d", r.frame)
		}
		if r.identity < 1 || r.identity > recoveryRecords || r.frame < 1 || r.frame > totalFrames {
			l.problem("unknown record/frame %d/%d", r.identity, r.frame)
		}
		byIdentity[r.identity], byFrame[r.frame] = r, r
	}
	pre := map[int]bool{}
	for _, frame := range preFrames {
		pre[frame] = true
	}
	for _, s := range sends {
		o := recoveryOfferRow{Identity: s.identity, Phase: s.phase, ReceiverEpoch: s.epoch, Start: s.start, End: s.end, Outcome: "success", Receipt: "missing_success"}
		if s.failed {
			o.Outcome, o.Receipt = "failure", "missing_failed"
		}
		if r, ok := byIdentity[s.identity]; ok {
			o.Frame, o.Receipt = r.frame, "received"
			if s.failed {
				o.Receipt = "received_after_error"
			}
		} else if s.phase == "outage" {
			o.Receipt = "unobserved_socket_closed"
		}
		l.Offers = append(l.Offers, o)
	}
	for frame := 1; frame <= totalFrames; frame++ {
		r := recoveryPacketRow{Frame: frame, ViewFrame: frame, ReceiverEpoch: 1, View: "warm", Kind: "unknown", FreshCache: "warm_cache"}
		other := warm
		if frame > warmFrames {
			r.ViewFrame, r.ReceiverEpoch, r.View, r.FreshCache = frame-warmFrames, 2, "resumed", "decoded"
			other = fresh
			if pre[r.ViewFrame] {
				r.FreshCache = "received_undecodable_pre_template"
			}
		}
		if frame <= len(headers) {
			h := headers[frame-1]
			r.Header = &h
			r.Kind = "data"
			if h.TemplateID != 0 {
				r.Kind, r.FreshCache = "template", "template"
			}
		}
		if r.ViewFrame <= len(other) {
			h := other[r.ViewFrame-1]
			r.OtherViewHeader = &h
		}
		if record, ok := byFrame[frame]; ok {
			r.RecordID = record.identity
		}
		l.Packets = append(l.Packets, r)
	}
	// Validate all existing telemetry equations before assigning charges.
	_, telemetryErr := validateRecoveryTelemetry(telemetry, sends)
	if telemetryErr != nil {
		l.problem("telemetry precondition: %v", telemetryErr)
	}
	if telemetry.endpointEpochs != 1 {
		l.problem("endpoint epoch count=%d want=1", telemetry.endpointEpochs)
	}
	offersValid := len(sends) == recoveryRecords
	for i, s := range sends {
		phase, epoch := "resumed", 2
		if i < recoveryWarmRecords {
			phase, epoch = "warm", 1
		} else if i < recoveryWarmRecords+recoveryOutageRecords {
			phase, epoch = "outage", 0
		}
		if s.identity != i+1 || s.phase != phase || s.epoch != epoch || !s.end.After(s.start) || i > 0 && s.start.Before(sends[i-1].end) {
			offersValid = false
		}
	}
	receivedFailed := 0
	for _, o := range l.Offers {
		if o.Receipt == "received_after_error" {
			receivedFailed++
		}
	}
	if int64(receivedFailed) > telemetry.dataMessages["ambiguous"] {
		l.problem("received failed records=%d exceed ambiguous data messages=%d", receivedFailed, telemetry.dataMessages["ambiguous"])
	}
	if captureEnd.IsZero() || len(sends) > 0 && captureEnd.Before(sends[len(sends)-1].end) {
		l.problem("invalid capture end bound")
	}
	if !offersValid {
		l.problem("offer schedule must be forty unique serial warm/outage/resumed calls")
	}
	l.CommitInference = offersValid && telemetryErr == nil && telemetry.endpointEpochs == 1
	exactTemplates := telemetry.templates["bootstrap/ambiguous"] == 0 && telemetry.templates["refresh/ambiguous"] == 0
	if !exactTemplates {
		l.problem("inconclusive template handoff: ambiguous bootstrap/refresh writes")
	}
	commits := 0
	// Template expectations come from the configuration and successful-call
	// thresholds, never header values. The timestamp window associates a whole
	// catalog round with its triggering offer, including a final 40th success.
	type round struct {
		offer, count int
		kind         string
		base         uint32
		ids          []int
	}
	rounds := []round{}
	if p.version != 5 {
		rounds = append(rounds, round{offer: 0, kind: "bootstrap", ids: []int{300, 301, 300, 301}})
	}
	if l.CommitInference {
		for i, s := range sends {
			o := &l.Offers[i]
			o.PriorCommits, o.Committed = commits, !s.failed
			seq := uint32(commits)
			if p.version == 9 {
				seq += uint32(4 + 2*(commits/recoveryTemplateRefreshCount))
			}
			if p.version != 9 || exactTemplates {
				o.ExpectedSequence = &seq
			}
			if !s.failed {
				commits++
				if p.version != 5 && commits%recoveryTemplateRefreshCount == 0 {
					n := commits / recoveryTemplateRefreshCount
					base := uint32(commits)
					if p.version == 9 {
						base += uint32(4 + 2*(n-1))
					}
					rounds = append(rounds, round{offer: i, kind: "refresh", base: base, ids: []int{300, 301}})
				}
			}
		}
		if p.version == 5 {
			if telemetry.templates["bootstrap/confirmed"] != 0 || telemetry.templates["refresh/confirmed"] != 0 || !exactTemplates {
				l.problem("v5 false template charge")
			}
		} else if exactTemplates && (telemetry.templates["bootstrap/confirmed"] != 4 || telemetry.templates["refresh/confirmed"] != int64(2*(commits/recoveryTemplateRefreshCount))) {
			l.problem("inconclusive template counts: bootstrap=%d refresh=%d expected=4/%d", telemetry.templates["bootstrap/confirmed"], telemetry.templates["refresh/confirmed"], 2*(commits/recoveryTemplateRefreshCount))
		}
	}
	if len(headers) != totalFrames || len(warm) != warmFrames || len(fresh) != totalFrames-warmFrames {
		l.problem("missing header view rows")
	}
	for i := range l.Packets {
		r := &l.Packets[i]
		if r.Header == nil || r.OtherViewHeader == nil {
			continue
		}
		h, other := *r.Header, *r.OtherViewHeader
		other.Frame += r.Frame - r.ViewFrame
		if h.Frame != r.Frame || h != other {
			l.problem("header view mismatch frame %d", r.Frame)
		}
		switch {
		case p.version == 5 && h.EngineType != 0:
			l.problem("header engine_type frame %d=%d want=0", r.Frame, h.EngineType)
		case p.version == 5 && h.EngineID != 0:
			l.problem("header engine_id frame %d=%d want=0", r.Frame, h.EngineID)
		case p.version == 9 && h.SourceID != 42:
			l.problem("header source_id frame %d=%d want=42", r.Frame, h.SourceID)
		case p.version == 10 && h.DomainID != 42:
			l.problem("header observation_domain frame %d=%d want=42", r.Frame, h.DomainID)
		}
		if h.TemplateID == 0 {
			if r.RecordID < 1 || r.RecordID > len(l.Offers) {
				l.problem("header data frame %d lacks retained record", r.Frame)
				continue
			}
			o := l.Offers[r.RecordID-1]
			r.ExpectedSequence = o.ExpectedSequence
			r.Association = fmt.Sprintf("offer:%d", o.Identity)
			if l.CommitInference && o.Committed {
				r.SequenceCharge = 1
			}
		} else {
			if r.RecordID != 0 {
				l.problem("header template frame %d carries a record", r.Frame)
			}
			if l.CommitInference && exactTemplates {
				recordTime, err := recoveryFrameTime(combined.text, r.Frame)
				if err != nil {
					l.problem("inconclusive template association: %v", err)
					continue
				}
				matched := false
				for j := range rounds {
					round := &rounds[j]
					if round.kind == "bootstrap" {
						// Startup hands off templates before the first OTLP call.
						if r.ReceiverEpoch != 1 || r.Frame >= combined.firstData {
							continue
						}
					} else {
						end := captureEnd
						if round.offer+1 < len(sends) {
							end = sends[round.offer+1].end
						}
						// The maintenance worker or the next Pack may drain this
						// round. Receipt need not precede the next call's start.
						if recordTime.Before(sends[round.offer].start) || !recordTime.Before(end) {
							continue
						}
					}
					matched = true
					if round.count >= len(round.ids) || h.TemplateID != round.ids[round.count] || round.kind == "bootstrap" && r.ReceiverEpoch != 1 {
						l.problem("inconclusive template catalog association frame %d", r.Frame)
						break
					}
					seq := round.base
					if p.version == 9 {
						seq += uint32(round.count)
						r.SequenceCharge = 1
					}
					r.ExpectedSequence, r.Association = &seq, fmt.Sprintf("%s:offer:%d:copy_index:%d", round.kind, round.offer+1, round.count)
					if round.kind == "bootstrap" {
						r.Association = fmt.Sprintf("bootstrap:startup:copy_index:%d", round.count)
					}
					round.count++
					break
				}
				if !matched {
					l.problem("inconclusive template association frame %d outside triggering offer windows", r.Frame)
				}
			}
		}
		if r.ExpectedSequence != nil && h.Sequence != *r.ExpectedSequence {
			l.problem("header sequence frame %d=%d want=%d (%s)", r.Frame, h.Sequence, *r.ExpectedSequence, r.Association)
		}
	}
	if l.CommitInference && exactTemplates {
		for _, round := range rounds {
			if round.count != len(round.ids) {
				l.problem("inconclusive partial/cutoff %s round at offer %d: received=%d want=%d", round.kind, round.offer+1, round.count, len(round.ids))
			}
		}
	}
	// These original guards remain strict. The fully populated ledger survives
	// their failure, including a received outage record or missing warm seed.
	if _, _, err := verifyCombinedRecovery(combined, warmFrames); err != nil {
		l.problem("inconclusive retained-cache prerequisite: %v", err)
	}
	return l, l.result()
}

func recoveryFrameTime(text string, frame int) (time.Time, error) {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if frame < 1 || frame > len(lines) {
		return time.Time{}, errors.New("missing template frame timestamp")
	}
	f := strings.Split(lines[frame-1], "|")
	if len(f) != 7 || f[0] != strconv.Itoa(frame) {
		return time.Time{}, errors.New("invalid template frame timestamp row")
	}
	return parseEpoch(f[6])
}

func writeRecoveryHeaderLedger(root string, l recoveryHeaderLedger) error {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	if len(data)+1 > recoveryDecoderCap {
		return errors.New("recovery ledger output cap exceeded")
	}
	return os.WriteFile(filepath.Join(root, "header-ledger.json"), append(data, '\n'), 0o600)
}

type recoveryEvidence struct {
	captureEnd                        time.Time
	combined, fresh                   decodeResult
	preFrames                         []int
	warmView, combinedView, freshView recoveryHeaderView
	ledger                            recoveryHeaderLedger
	records                           map[int]decodedRecord
	receipts                          recoveryReceiptSummary
}

func qualifyRecoveryOriginal(ctx context.Context, root string, p protocol, sends []recoveryMeasurement, telemetry recoveryTelemetry, warmPackets, resumedPackets []packet, captureEnd time.Time, telemetryReadErr error) (recoveryEvidence, error) {
	e := recoveryEvidence{records: map[int]decodedRecord{}, captureEnd: captureEnd}
	all := append(append([]packet(nil), warmPackets...), resumedPackets...)
	for _, capture := range []struct {
		name    string
		packets []packet
	}{{"warm", warmPackets}, {"combined", all}, {"resumed", resumedPackets}} {
		if err := writeRecoveryPCAP(filepath.Join(root, capture.name+".pcap"), capture.packets, p); err != nil {
			return e, err
		}
	}
	var combinedErr, freshErr, warmHeaderErr, combinedHeaderErr, freshHeaderErr error
	e.combined, combinedErr = decodeExpected(ctx, filepath.Join(root, "combined.pcap"), p.port, p.version, len(all))
	if p.version == 5 {
		e.fresh, freshErr = decodeExpected(ctx, filepath.Join(root, "resumed.pcap"), p.port, p.version, len(resumedPackets))
	} else {
		e.fresh, e.preFrames, freshErr = decodeResumedFresh(ctx, filepath.Join(root, "resumed.pcap"), p, len(resumedPackets))
		if err := os.WriteFile(filepath.Join(root, "tshark.pre-refresh.fields"), []byte(e.fresh.text+"\n"), 0o600); err != nil {
			return e, err
		}
	}
	for name, text := range map[string]string{"tshark.combined.fields": e.combined.text, "tshark.resumed.fields": e.fresh.text} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(text+"\n"), 0o600); err != nil {
			return e, err
		}
	}
	e.warmView, warmHeaderErr = decodeRecoveryHeaders(ctx, root, "warm", p, len(warmPackets))
	e.combinedView, combinedHeaderErr = decodeRecoveryHeaders(ctx, root, "combined", p, len(all))
	e.freshView, freshHeaderErr = decodeRecoveryHeaders(ctx, root, "resumed", p, len(resumedPackets))
	e.ledger, _ = buildRecoveryHeaderLedger(p, sends, telemetry, e.combined, e.warmView.headers, e.combinedView.headers, e.freshView.headers, e.preFrames, len(warmPackets), len(all), captureEnd)
	for _, err := range []error{telemetryReadErr, combinedErr, freshErr, warmHeaderErr, combinedHeaderErr, freshHeaderErr} {
		if err != nil {
			e.ledger.problem("independent receipt/telemetry prerequisite: %v", err)
		}
	}
	if e.combinedView.fields != e.combined.text || e.freshView.fields != e.fresh.text {
		e.ledger.problem("header/record decoder field join differs")
	}
	lines := strings.Split(e.combined.text, "\n")
	if len(lines) < len(warmPackets) || e.warmView.fields != strings.Join(lines[:min(len(lines), len(warmPackets))], "\n") {
		e.ledger.problem("warm/retained decoder field join differs")
	}
	oracle := map[int]decodedRecord{}
	for _, record := range e.combined.identities {
		e.records[record.identity] = record
		if record.frame > len(warmPackets) {
			oracle[record.frame-len(warmPackets)] = record
		}
	}
	if err := compareFreshResumedToOracle(e.fresh, e.preFrames, oracle, p.version); err != nil {
		e.ledger.problem("fresh cache partition: %v", err)
	}
	if len(warmPackets) == 0 || len(resumedPackets) == 0 || !resumedPackets[0].t.After(warmPackets[len(warmPackets)-1].t) {
		e.ledger.problem("combined capture timing is not monotonic across rebind")
	}
	var timingErr error
	e.receipts, timingErr = summarizeRecoveryReceipts(sends, e.records, all)
	if timingErr != nil {
		e.ledger.problem("receipt timing: %v", timingErr)
	}
	if err := os.WriteFile(filepath.Join(root, "receipt-summary.txt"), []byte(fmt.Sprintf("%+v\n", e.receipts)), 0o600); err != nil {
		return e, err
	}
	if err := writeRecoveryMeasurements(filepath.Join(root, "measurements.csv"), sends, e.records); err != nil {
		e.ledger.problem("measurement persistence: %v", err)
	}
	qualificationErr := e.ledger.result()
	if err := writeRecoveryHeaderLedger(root, e.ledger); err != nil {
		return e, err
	}
	return e, qualificationErr
}

func writeRecoveryPCAP(path string, packets []packet, p protocol) error {
	size := 24
	for _, packet := range packets {
		size += 16 + 42 + len(packet.b)
	}
	if len(packets) > recoveryFrameCap || size > recoveryDecoderCap {
		return errors.New("recovery PCAP exceeds 64-frame/64-KiB cap")
	}
	return writePCAP(path, packets, 40000, p.port)
}

// Mutants contain the original timestamped packets, changing only selected
// header bytes. Rebuilding the synthetic envelope updates its checksums. Every
// variant must independently reproduce the original seven record/cache fields
// in both halves and the combined view before a named header rejection counts.
func qualifyRecoveryMutants(ctx context.Context, root string, p protocol, sends []recoveryMeasurement, telemetry recoveryTelemetry, warmPackets, resumedPackets []packet, original recoveryEvidence) (int, error) {
	type mutation struct {
		name, rejection string
		change          func([]packet)
	}
	all := append(append([]packet(nil), warmPackets...), resumedPackets...)
	sequenceOffset := 16
	if p.version == 9 {
		sequenceOffset = 12
	} else if p.version == 10 {
		sequenceOffset = 8
	}
	setSequence := func(packets []packet, frame int, seq uint32) {
		binary.BigEndian.PutUint32(packets[frame-1].b[sequenceOffset:sequenceOffset+4], seq)
	}
	firstResumedData := 0
	for _, row := range original.ledger.Packets {
		if row.View == "resumed" && row.Kind == "data" {
			firstResumedData = row.Frame
			break
		}
	}
	if firstResumedData == 0 {
		return 0, errors.New("mutants require a resumed data frame")
	}
	mutations := []mutation{{"resumed-false-reset", "header sequence", func(packets []packet) { setSequence(packets, firstResumedData, 0) }}}
	if p.version == 5 {
		for _, identity := range []struct {
			name   string
			offset int
		}{{"engine_type", 20}, {"engine_id", 21}} {
			mutations = append(mutations, mutation{"wrong-" + identity.name, "header " + identity.name, func(packets []packet) {
				for _, packet := range packets {
					packet.b[identity.offset] = 1
				}
			}})
		}
	} else {
		identity, offset := "source_id", 16
		if p.version == 10 {
			identity, offset = "observation_domain", 12
		}
		mutations = append(mutations, mutation{"wrong-" + identity, "header " + identity, func(packets []packet) {
			for _, packet := range packets {
				binary.BigEndian.PutUint32(packet.b[offset:offset+4], 43)
			}
		}})
		mutations = append(mutations, mutation{"wrong-refresh-charge", "header sequence", func(packets []packet) {
			for _, row := range original.ledger.Packets {
				if row.Kind != "data" || row.RecordID < 1 {
					continue
				}
				offer := original.ledger.Offers[row.RecordID-1]
				rounds := offer.PriorCommits / recoveryTemplateRefreshCount
				if rounds == 0 {
					continue
				}
				seq := *row.ExpectedSequence
				if p.version == 9 {
					seq -= uint32(2 * rounds)
				} else {
					seq += uint32(2 * rounds)
				}
				setSequence(packets, row.Frame, seq)
			}
		}})
		if len(original.preFrames) == 0 {
			return 0, errors.New("mutants require a pre-template frame")
		}
		frame := len(warmPackets) + original.preFrames[0]
		mutations = append(mutations, mutation{"pre-template-sequence", "header sequence", func(packets []packet) {
			setSequence(packets, frame, *original.ledger.Packets[frame-1].ExpectedSequence+1)
		}})
	}
	// Fixed campaign: 3 + 4 + 4 = 11, below the global sixteen-mutant ceiling.
	if len(mutations) > 4 {
		return 0, errors.New("recovery per-protocol mutant budget exceeded")
	}
	f, err := os.OpenFile(filepath.Join(root, "mutants.csv"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"mutant", "record_cache_partition", "required_rejection", "observed_rejection"}); err != nil {
		return 0, err
	}
	for index, mutation := range mutations {
		packets := make([]packet, len(all))
		for i, packet := range all {
			packets[i] = packet
			packets[i].b = append([]byte(nil), packet.b...)
		}
		mutation.change(packets)
		dir := filepath.Join(root, "mutant-"+mutation.name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			return index, err
		}
		views := make([]recoveryHeaderView, 3)
		for i, capture := range []struct {
			name    string
			packets []packet
			fields  string
		}{{"warm", packets[:len(warmPackets)], original.warmView.fields}, {"combined", packets, original.combinedView.fields}, {"resumed", packets[len(warmPackets):], original.freshView.fields}} {
			if err := writeRecoveryPCAP(filepath.Join(dir, capture.name+".pcap"), capture.packets, p); err != nil {
				return index, err
			}
			views[i], err = decodeRecoveryHeaders(ctx, dir, capture.name, p, len(capture.packets))
			if err != nil {
				return index, fmt.Errorf("mutant %s %s tool/parse failure: %w", mutation.name, capture.name, err)
			}
			if views[i].fields != capture.fields {
				return index, fmt.Errorf("mutant %s %s record/cache partition changed", mutation.name, capture.name)
			}
		}
		ledger, rejection := buildRecoveryHeaderLedger(p, sends, telemetry, original.combined, views[0].headers, views[1].headers, views[2].headers, original.preFrames, len(warmPackets), len(all), original.captureEnd)
		if err := writeRecoveryHeaderLedger(dir, ledger); err != nil {
			return index, err
		}
		if rejection == nil || !strings.Contains(rejection.Error(), mutation.rejection) {
			return index, fmt.Errorf("mutant %s lacks named rejection %q: %v", mutation.name, mutation.rejection, rejection)
		}
		// No incidental non-header failure can satisfy a sensitivity control.
		for _, problem := range ledger.Problems {
			if !strings.HasPrefix(problem, mutation.rejection) {
				return index, fmt.Errorf("mutant %s incidental rejection: %s", mutation.name, problem)
			}
		}
		if err := w.Write([]string{mutation.name, "unchanged_independent_decode", mutation.rejection, rejection.Error()}); err != nil {
			return index, err
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return index, err
		}
	}
	return len(mutations), f.Sync()
}
