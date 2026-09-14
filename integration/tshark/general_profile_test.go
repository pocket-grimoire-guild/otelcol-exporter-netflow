//go:build linux

package tshark_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/integration/tshark/internal/oracle"
)

func TestGeneralProfileLiteralGoldens(t *testing.T) {
	repo := repositoryRoot(t)
	fixtures := []struct {
		name, hash                                    string
		length, templateID, recordLength, startOffset int
	}{
		{"general-ipv4-v1.bin", "d13784d17f685d41faa64d40b371b4037031ababecc52b534fe0aafab4a12b01", 180, 256, 72, 56},
		{"general-ipv6-v1.bin", "7ef96d2a3b76ad904d3c08d91a98122f6f6d4f01b790c3f3c166a67820ddbed6", 204, 257, 96, 80},
	}
	wantIDs := []uint16{1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 34, 52, 60, 152, 153}
	wantWidths := []uint16{8, 8, 1, 1, 2, 2, 4, 1, 4, 2, 4, 1, 4, 4, 4, 4, 1, 1, 8, 8}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join(repo, "integration/testdata/golden/ipfix", fixture.name))
			if err != nil {
				t.Fatal(err)
			}
			if len(payload) != fixture.length || fmt.Sprintf("%x", sha256.Sum256(payload)) != fixture.hash {
				t.Fatalf("literal fixture length/hash %d/%x, want %d/%s", len(payload), sha256.Sum256(payload), fixture.length, fixture.hash)
			}
			if binary.BigEndian.Uint16(payload[0:2]) != 10 || binary.BigEndian.Uint16(payload[2:4]) != uint16(fixture.length) ||
				binary.BigEndian.Uint32(payload[4:8]) != 1_788_220_803 || binary.BigEndian.Uint32(payload[8:12]) != 0 || binary.BigEndian.Uint32(payload[12:16]) != 42 {
				t.Fatalf("IPFIX header changed: %x", payload[:16])
			}
			if binary.BigEndian.Uint16(payload[16:18]) != 2 || binary.BigEndian.Uint16(payload[18:20]) != 88 ||
				binary.BigEndian.Uint16(payload[20:22]) != uint16(fixture.templateID) || binary.BigEndian.Uint16(payload[22:24]) != 20 {
				t.Fatalf("template envelope changed: %x", payload[16:24])
			}
			ids, widths := wantIDs, wantWidths
			if fixture.templateID == 257 {
				ids = append([]uint16(nil), wantIDs...)
				widths = append([]uint16(nil), wantWidths...)
				ids[6], widths[6] = 27, 16
				ids[7] = 29
				ids[10], widths[10] = 28, 16
				ids[11] = 30
			}
			for i, wantID := range ids {
				offset := 24 + i*4
				if gotID, gotWidth := binary.BigEndian.Uint16(payload[offset:offset+2]), binary.BigEndian.Uint16(payload[offset+2:offset+4]); gotID != wantID || gotWidth != widths[i] {
					t.Fatalf("template field %d=%d/%d, want %d/%d", i, gotID, gotWidth, wantID, widths[i])
				}
			}
			data := 104
			if binary.BigEndian.Uint16(payload[data:data+2]) != uint16(fixture.templateID) || binary.BigEndian.Uint16(payload[data+2:data+4]) != uint16(fixture.recordLength+4) {
				t.Fatalf("data envelope changed: %x", payload[data:data+4])
			}
			record := data + 4
			if got := binary.BigEndian.Uint64(payload[record+fixture.startOffset : record+fixture.startOffset+8]); got != 1_788_220_800_123 {
				t.Fatalf("start milliseconds %d, want 1788220800123", got)
			}
			if got := binary.BigEndian.Uint64(payload[record+fixture.startOffset+8 : record+fixture.startOffset+16]); got != 1_788_220_801_123 {
				t.Fatalf("end milliseconds %d, want 1788220801123", got)
			}
		})
	}
}

func TestGeneralProfileTShark(t *testing.T) {
	if os.Getenv("NETFLOW_TSHARK_RUN_GENERAL") != "1" {
		t.Skip("set NETFLOW_TSHARK_RUN_GENERAL=1 for the pinned rootless TShark oracle")
	}
	repo := repositoryRoot(t)
	image, err := os.ReadFile(filepath.Join(repo, "integration/tshark/IMAGE_DIGEST"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := oracle.RunGeneral(ctx, oracle.Config{Repo: repo, Image: strings.TrimSpace(string(image)), Artifacts: os.Getenv("NETFLOW_TSHARK_ARTIFACTS")}); err != nil {
		t.Fatal(err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}
