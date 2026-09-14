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

func TestTimedProfileTShark(t *testing.T) {
	if os.Getenv("NETFLOW_TSHARK_RUN_TIMED") != "1" {
		t.Skip("set NETFLOW_TSHARK_RUN_TIMED=1 for the pinned fresh timed-profile decode")
	}
	repo := timedRepositoryRoot(t)
	image, err := os.ReadFile(filepath.Join(repo, "integration/tshark/IMAGE_DIGEST"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := oracle.RunTimed(ctx, oracle.Config{Repo: repo, Image: strings.TrimSpace(string(image)), Artifacts: os.Getenv("NETFLOW_TSHARK_ARTIFACTS")}); err != nil {
		t.Fatal(err)
	}
}

func TestTimedProfileLiteralGoldens(t *testing.T) {
	fixtures := []struct {
		name, hash     string
		length, record int
		timeOffset     int
	}{
		{name: "timed-ipv4-v1.bin", hash: "204cd5586cc098c407ebfbae6dab6587710b80dc82d8eb27c0b9b6ce156dd20b", length: 164, record: 51, timeOffset: 43},
		{name: "timed-ipv6-v1.bin", hash: "66f7a79d1304e3921824dbb90bcfe0577f0fdd75024591b54bdd67b9f4e0d4e8", length: 188, record: 75, timeOffset: 67},
	}
	root := timedRepositoryRoot(t)
	ids := []uint16{1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 34, 52, 60, 22, 21}
	widths := []uint16{4, 4, 1, 1, 1, 2, 4, 1, 2, 2, 4, 1, 2, 4, 4, 4, 1, 1, 4, 4}
	for index, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join(root, "integration/testdata/golden/v9", fixture.name))
			if err != nil {
				t.Fatal(err)
			}
			if len(payload) != fixture.length || fmt.Sprintf("%x", sha256.Sum256(payload)) != fixture.hash {
				t.Fatalf("literal fixture length/hash %d/%x, want %d/%s", len(payload), sha256.Sum256(payload), fixture.length, fixture.hash)
			}
			if binary.BigEndian.Uint16(payload[0:2]) != 9 || binary.BigEndian.Uint16(payload[2:4]) != 2 || binary.BigEndian.Uint32(payload[4:8]) != 5000 || binary.BigEndian.Uint32(payload[8:12]) != 1788220805 || binary.BigEndian.Uint32(payload[12:16]) != 0 || binary.BigEndian.Uint32(payload[16:20]) != uint32(42+index) {
				t.Fatalf("timed header drift: %x", payload[:20])
			}
			if binary.BigEndian.Uint16(payload[20:22]) != 0 || binary.BigEndian.Uint16(payload[22:24]) != 88 || binary.BigEndian.Uint16(payload[24:26]) != uint16(256+index) || binary.BigEndian.Uint16(payload[26:28]) != 20 {
				t.Fatalf("timed template envelope drift: %x", payload[20:28])
			}
			fieldIDs := append([]uint16(nil), ids...)
			fieldWidths := append([]uint16(nil), widths...)
			if index == 1 {
				fieldIDs[6], fieldWidths[6] = 27, 16
				fieldIDs[7] = 29
				fieldIDs[10], fieldWidths[10] = 28, 16
				fieldIDs[11] = 30
			}
			for field, id := range fieldIDs {
				offset := 28 + field*4
				if gotID, gotWidth := binary.BigEndian.Uint16(payload[offset:offset+2]), binary.BigEndian.Uint16(payload[offset+2:offset+4]); gotID != id || gotWidth != fieldWidths[field] {
					t.Fatalf("timed template field %d=%d/%d, want %d/%d", field, gotID, gotWidth, id, fieldWidths[field])
				}
			}
			data := 108
			if binary.BigEndian.Uint16(payload[data:data+2]) != uint16(256+index) || binary.BigEndian.Uint16(payload[data+2:data+4]) != uint16(fixture.record+5) {
				t.Fatalf("timed data envelope drift: %x", payload[data:data+4])
			}
			record := data + 4
			if got := binary.BigEndian.Uint32(payload[record+fixture.timeOffset : record+fixture.timeOffset+4]); got != 3000 {
				t.Fatalf("timed FIRST_SWITCHED=%d, want 3000", got)
			}
			if got := binary.BigEndian.Uint32(payload[record+fixture.timeOffset+4 : record+fixture.timeOffset+8]); got != 4000 {
				t.Fatalf("timed LAST_SWITCHED=%d, want 4000", got)
			}
			if payload[len(payload)-1] != 0 {
				t.Fatalf("timed padding=%x, want zero", payload[len(payload)-1])
			}
		})
	}
}

func timedRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}
