package independent_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"go.opentelemetry.io/collector/pdata/plog"
)

type fixtureCase struct {
	Name            string `json:"name"`
	FixtureID       string `json:"fixture_id"`
	ExpectedRecords int    `json:"expected_records"`
}

type fixtureLedger struct {
	Protocol      string        `json:"protocol"`
	Profile       string        `json:"profile"`
	CanonicalHash string        `json:"canonical_file_sha256"`
	Cases         []fixtureCase `json:"cases"`
}

// Consume the same authored inputs and source hash as the OTel roundtrip,
// without importing that receiver or its GoFlow2 decoder into this module.
func fixtureLogs(t *testing.T, ledger fixtureLedger, tc fixtureCase) plog.Logs {
	t.Helper()
	data := readFile(t, filepath.Join("..", "testdata", "canonical", "fixtures.json"))
	if fmt.Sprintf("%x", sha256.Sum256(data)) != ledger.CanonicalHash {
		t.Fatal("canonical fixture hash differs from reviewed ledger")
	}
	type attrs struct {
		Attributes map[string]any `json:"attributes"`
	}
	type fixture struct {
		ID   string `json:"id"`
		Base string `json:"base_fixture_id"`
		attrs
		Overrides attrs                       `json:"overrides"`
		Records   []struct{ Overrides attrs } `json:"records"`
	}
	var manifest struct{ Fixtures []fixture }
	decodeJSON(t, data, &manifest)
	byID := map[string]fixture{}
	for _, f := range manifest.Fixtures {
		byID[f.ID] = f
	}
	var resolve func(string, int) map[string]any
	resolve = func(id string, depth int) map[string]any {
		f, ok := byID[id]
		if !ok || depth > len(byID) {
			t.Fatalf("invalid fixture reference %q", id)
		}
		values := map[string]any{}
		if f.Base != "" {
			values = resolve(f.Base, depth+1)
		}
		for k, v := range f.Attributes {
			values[k] = v
		}
		for k, v := range f.Overrides.Attributes {
			values[k] = v
		}
		return values
	}
	values := resolve(tc.FixtureID, 0)
	f := byID[tc.FixtureID]
	count := max(1, len(f.Records))
	if count != tc.ExpectedRecords {
		t.Fatal("fixture record count differs from ledger")
	}
	logs := plog.NewLogs()
	sl := logs.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	sl.Scope().SetName("otelcol/netflowreceiver")
	sl.Scope().Attributes().PutStr("receiver", "netflow")
	for i := range count {
		r := sl.LogRecords().AppendEmpty()
		put := func(key string, value any) {
			switch v := value.(type) {
			case string:
				r.Attributes().PutStr(key, v)
			case json.Number:
				n, err := v.Int64()
				must(t, err)
				r.Attributes().PutInt(key, n)
			default:
				t.Fatalf("unexpected fixture value %T", value)
			}
		}
		for k, v := range values {
			put(k, v)
		}
		if len(f.Records) != 0 {
			for k, v := range f.Records[i].Overrides.Attributes {
				put(k, v)
			}
		}
	}
	return logs
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	must(t, err)
	return data
}

func decodeJSON(t *testing.T, data []byte, out any) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	must(t, d.Decode(out))
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	must(t, err)
	must(t, os.WriteFile(path, append(data, '\n'), 0600))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
