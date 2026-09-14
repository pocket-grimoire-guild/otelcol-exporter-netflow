package destination

import (
	"errors"
	"testing"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

func TestPackPMTUCompilationAndStateMatrix(t *testing.T) {
	tests := []struct {
		name     string
		pathMTU  uint64
		payload  uint64
		endpoint string
		valid    bool
	}{
		{name: "absent-464", payload: 464, endpoint: "", valid: true},
		{name: "absent-465", payload: 465},
		{name: "ipv4-512-484", pathMTU: 512, payload: 484, endpoint: "192.0.2.1:4739", valid: true},
		{name: "ipv4-512-485", pathMTU: 512, payload: 485, endpoint: "192.0.2.1:4739"},
		{name: "ipv6-512-464", pathMTU: 512, payload: 464, endpoint: "[2001:db8::1]:4739", valid: true},
		{name: "ipv6-512-465", pathMTU: 512, payload: 465, endpoint: "[2001:db8::1]:4739"},
		{name: "hostname-512-464", pathMTU: 512, payload: 464, endpoint: "collector.example:4739", valid: true},
		{name: "hostname-512-465", pathMTU: 512, payload: 465, endpoint: "collector.example:4739"},
		{name: "ipv4-max-65507", pathMTU: 65535, payload: 65507, endpoint: "192.0.2.1:4739", valid: true},
		{name: "ipv4-max-65508", pathMTU: 65535, payload: 65508, endpoint: "192.0.2.1:4739"},
		{name: "ipv6-max-65487", pathMTU: 65535, payload: 65487, endpoint: "[2001:db8::1]:4739", valid: true},
		{name: "ipv6-max-65488", pathMTU: 65535, payload: 65488, endpoint: "[2001:db8::1]:4739"},
		{name: "hostname-max-65487", pathMTU: 65535, payload: 65487, endpoint: "collector.example:4739", valid: true},
		{name: "hostname-max-65488", pathMTU: 65535, payload: 65488, endpoint: "collector.example:4739"},
		{name: "path-mtu-511", pathMTU: 511, payload: 464},
		{name: "path-mtu-65536", pathMTU: 65536, payload: 464},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := mapping.Config{
				Protocol:        wire.ProtocolIPFIX,
				Fields:          []mapping.FieldSelection{{Canonical: "source.port"}},
				LossPolicy:      mapping.LossPolicyEncodeAndCount,
				MaxDatagramSize: tc.payload,
				PathMTU:         tc.pathMTU,
				Endpoint:        tc.endpoint,
			}
			compiled, err := mapping.Compile(config)
			if !tc.valid {
				if err == nil {
					t.Fatal("invalid PMTU budget accepted by compiler")
				}
				return
			}
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got := compiled.MaxDatagramSize(); got != tc.payload {
				t.Fatalf("compiled payload=%d, want %d", got, tc.payload)
			}
			state, err := NewState(compiled, &recordingWriter{}, Config{
				Protocol:            wire.ProtocolIPFIX,
				ObservationDomainID: 42,
				MaxDatagramSize:     tc.payload,
			})
			if err != nil {
				t.Fatalf("state construction: %v", err)
			}
			if got := state.Config().MaxDatagramSize; got != tc.payload {
				t.Fatalf("state payload=%d, want %d", got, tc.payload)
			}
		})
	}
}

func TestPackCompiledPayloadCapInvariant(t *testing.T) {
	config := mapping.Config{
		Protocol:        wire.ProtocolIPFIX,
		Fields:          []mapping.FieldSelection{{Canonical: "source.port"}},
		LossPolicy:      mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize: 484,
		PathMTU:         512,
		Endpoint:        "192.0.2.1:4739",
	}
	compiled, err := mapping.Compile(config)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, tc := range []struct {
		name    string
		payload uint64
		valid   bool
	}{
		{name: "equal", payload: 484, valid: true},
		{name: "smaller", payload: 464, valid: true},
		{name: "normalized-default", valid: true},
		{name: "post-compile-increase", payload: 485},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer := new(recordingWriter)
			state, err := NewState(compiled, writer, Config{
				Protocol:            wire.ProtocolIPFIX,
				ObservationDomainID: 42,
				MaxDatagramSize:     tc.payload,
			})
			if !tc.valid {
				if !errors.Is(err, ErrInvalidConfig) || state != nil {
					t.Fatalf("state=%v err=%v, want invalid config without state", state, err)
				}
				if len(writer.requests) != 0 {
					t.Fatalf("invalid construction emitted %d requests", len(writer.requests))
				}
				return
			}
			if err != nil {
				t.Fatalf("state construction: %v", err)
			}
			want := tc.payload
			if tc.name == "normalized-default" {
				want = 464
			}
			if got := state.Config().MaxDatagramSize; got != want {
				t.Fatalf("state payload=%d, want %d", got, want)
			}
		})
	}

	if state, err := NewState(mapping.CompiledMapping{}, &recordingWriter{}, Config{Protocol: wire.ProtocolIPFIX}); state != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("zero mapping state=%v err=%v, want invalid config without state", state, err)
	}
}

func TestPackCompiledCapNormalizationGuards(t *testing.T) {
	base := mapping.Config{
		Protocol:   wire.ProtocolIPFIX,
		Fields:     []mapping.FieldSelection{{Canonical: "source.port"}},
		LossPolicy: mapping.LossPolicyEncodeAndCount,
	}
	compiledDefault, err := mapping.Compile(base)
	if err != nil {
		t.Fatalf("compile default: %v", err)
	}
	if got := compiledDefault.MaxDatagramSize(); got != 464 {
		t.Fatalf("default compiled payload=%d, want 464", got)
	}
	if state, err := NewState(compiledDefault, &recordingWriter{}, Config{
		Protocol:            wire.ProtocolIPFIX,
		ObservationDomainID: 42,
		MaxDatagramSize:     465,
	}); state != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("default cap state=%v err=%v, want invalid config without state", state, err)
	}

	base.MaxDatagramSize = 128
	compiledSmall, err := mapping.Compile(base)
	if err != nil {
		t.Fatalf("compile 128: %v", err)
	}
	if state, err := NewState(compiledSmall, &recordingWriter{}, Config{
		Protocol:            wire.ProtocolIPFIX,
		ObservationDomainID: 42,
	}); state != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("normalized default state=%v err=%v, want invalid config without state", state, err)
	}
}

func TestPackCompiledCapTooSmallForCatalog(t *testing.T) {
	compiled, err := customPENMapping(t, 32)
	if err != nil {
		t.Fatalf("compile custom mapping: %v", err)
	}
	if _, err := NewState(compiled, &recordingWriter{}, Config{
		Protocol:        wire.ProtocolIPFIX,
		MaxDatagramSize: 128,
	}); !errors.Is(err, wire.ErrBounds) {
		t.Fatalf("small state cap err=%v, want %v", err, wire.ErrBounds)
	}
}

func TestPackCompiledCapAcrossProtocols(t *testing.T) {
	for _, protocol := range []wire.Protocol{wire.ProtocolV5, wire.ProtocolV9, wire.ProtocolIPFIX} {
		t.Run(protocol.String(), func(t *testing.T) {
			config := packFullMappingConfig(protocol, 65507)
			compiled, err := mapping.Compile(config)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			stateConfig := DefaultConfig(protocol)
			stateConfig.MaxDatagramSize = 65507
			switch protocol {
			case wire.ProtocolV5:
				stateConfig.HasUptimeOrigin = true
			case wire.ProtocolV9:
				stateConfig.SourceID, stateConfig.ObservationDomainID = 42, 42
			case wire.ProtocolIPFIX:
				stateConfig.ObservationDomainID = 42
			}
			state, err := NewState(compiled, &recordingWriter{}, stateConfig)
			if err != nil {
				t.Fatalf("state construction: %v", err)
			}
			if got := state.Mapping().MaxDatagramSize(); got != 65507 {
				t.Fatalf("mapping payload=%d, want 65507", got)
			}
		})
	}
}

func packFullMappingConfig(protocol wire.Protocol, maxDatagram uint64) mapping.Config {
	config := mapping.Config{
		Protocol:        protocol,
		LossPolicy:      mapping.LossPolicyEncodeAndCount,
		MaxDatagramSize: maxDatagram,
		PathMTU:         65535,
		Endpoint:        "192.0.2.1:4739",
		ProtocolIdentifiers: []mapping.ProtocolIdentifier{
			{Token: "tcp", Number: 6},
		},
	}
	switch protocol {
	case wire.ProtocolV5:
		config.Profile = mapping.ProfileV5
		config.InputGuarantees.FlowIOBytes = "layer3_total_octets"
		config.HasUptimeOrigin = true
	case wire.ProtocolV9:
		config.Profile = mapping.ProfileV9
		config.NetworkTypeVersions = []mapping.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
	case wire.ProtocolIPFIX:
		config.Profile = mapping.ProfileIPFIX
		config.NetworkTypeVersions = []mapping.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
	}
	return config
}
