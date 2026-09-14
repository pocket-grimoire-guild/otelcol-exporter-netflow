package ocb_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// Independent payload comparisons must reject corrupted packets even when
// Collector startup and exit were successful. These run without an OCB build.
func TestPacketValidation(t *testing.T) {
	origin := time.Unix(1788220800, 0)
	for _, protocol := range []string{"v5", "v9", "ipfix"} {
		t.Run(protocol, func(t *testing.T) {
			golden := goldenFile(t, protocol, "canonical-ipv4-v1.bin")
			header, _ := offsets(protocol)
			want := projectedData(flowCase{Protocol: protocol, Records: 1}, golden, false)
			good := append(bytes.Clone(golden[:header]), want...)
			if protocol == "v5" {
				good[21] = 1 // output identity is operator config, not input identity
			}
			if protocol == "ipfix" {
				binary.BigEndian.PutUint16(good[2:], uint16(len(good)))
				binary.BigEndian.PutUint32(good[12:], 42)
			} else {
				binary.BigEndian.PutUint16(good[2:], 1)
			}
			check := func(packet []byte) error {
				return validatePacket(protocol, packet, want, 0, 1, 42, 1788220800, 1788220803, origin)
			}
			must(t, check(good))
			variants := map[string][]byte{
				"empty":            nil,
				"truncated-header": good[:header-1],
				"truncated-record": good[:len(good)-1],
				"extra-record":     append(bytes.Clone(good), want...),
			}
			for name, offset := range map[string]int{
				"version":             1,
				"count-or-length":     3,
				"data-value":          header + 8,
				"padding-or-fraction": len(good) - 1,
			} {
				packet := bytes.Clone(good)
				packet[offset] ^= 1
				variants[name] = packet
			}
			seqOffset, timeOffset := 16, 8
			if protocol == "v9" {
				seqOffset = 12
			} else if protocol == "ipfix" {
				seqOffset, timeOffset = 8, 4
			}
			for name, offset := range map[string]int{"sequence": seqOffset, "export-time": timeOffset} {
				packet := bytes.Clone(good)
				binary.BigEndian.PutUint32(packet[offset:], ^uint32(0))
				variants[name] = packet
			}
			if protocol == "v5" {
				packet := bytes.Clone(good)
				packet[20]++
				variants["engine"] = packet
				packet = bytes.Clone(good)
				packet[23]++
				variants["sampling"] = packet
				packet = bytes.Clone(good)
				binary.BigEndian.PutUint32(packet[12:], 1_000_000_000)
				variants["nanoseconds"] = packet
			} else {
				packet := bytes.Clone(good)
				binary.BigEndian.PutUint32(packet[header-4:], 43)
				variants["domain"] = packet
				// Restoring the original nonzero IE 34 must fail the explicitly
				// documented receiver projection, not be silently normalized away.
				_, offset := offsets(protocol)
				variants["unprojected-sampling"] = append(bytes.Clone(good[:header]), golden[offset:]...)
			}
			if protocol != "ipfix" {
				packet := bytes.Clone(good)
				binary.BigEndian.PutUint32(packet[4:], ^uint32(0))
				variants["uptime"] = packet
			}
			for name, packet := range variants {
				t.Run(name, func(t *testing.T) {
					if check(packet) == nil {
						t.Fatal("corrupted packet accepted")
					}
				})
			}
		})
	}
}

// A receiver's propagated error or an unrelated component name must never
// substitute for the built exporter's own transient handoff evidence.
func TestTransportErrorEvidence(t *testing.T) {
	const event = `{"level":"error","msg":"Exporting failed. Rejecting data.","otelcol.component.id":"netflow/failing","otelcol.component.kind":"exporter","otelcol.signal":"logs","error":"netflow: transient packet handoff","rejected_items":1}` + "\n"
	must(t, checkTransportErrors("", false))
	must(t, checkTransportErrors(event, true))
	for name, log := range map[string]string{
		"missing":         "",
		"duplicate":       event + event,
		"different-owner": strings.Replace(event, "netflow/failing", "netflow/healthy", 1),
		"receiver-only":   strings.Replace(event, `"exporter"`, `"receiver"`, 1),
		"wrong-signal":    strings.Replace(event, `"logs"`, `"metrics"`, 1),
		"wrong-message":   strings.Replace(event, "Exporting failed. Rejecting data.", "startup", 1),
		"wrong-error":     strings.Replace(event, "netflow: transient packet handoff", "netflow: records rejected", 1),
		"wrong-count":     strings.Replace(event, `"rejected_items":1`, `"rejected_items":2`, 1),
		"missing-count":   strings.Replace(event, `,"rejected_items":1`, "", 1),
		"wrong-level":     strings.Replace(event, `"error","msg"`, `"info","msg"`, 1),
		"truncated":       event[:len(event)/2] + "\n",
		"log-overflow":    event + "LOG LIMIT EXCEEDED",
		"healthy-error":   event + strings.ReplaceAll(strings.Replace(event, "netflow/failing", "netflow/healthy", 1), `"rejected_items":1`, `"rejected_items":0`),
	} {
		t.Run(name, func(t *testing.T) {
			if checkTransportErrors(log, true) == nil {
				t.Fatal("invalid transport-failure evidence accepted")
			}
		})
	}
	if checkTransportErrors(event, false) == nil {
		t.Fatal("failure accepted before injection")
	}
	// Interleaved upstream diagnostics do not double-count the helper event.
	receiver := strings.Replace(event, `"exporter"`, `"receiver"`, 1)
	must(t, checkTransportErrors(receiver+event, true))
}
