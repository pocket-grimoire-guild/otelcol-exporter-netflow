package oracle

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTimedPacketInputs(t *testing.T) {
	repo, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	packets, err := readTimedPackets(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 2 {
		t.Fatalf("packets=%d", len(packets))
	}
	for _, packet := range packets {
		for n := 0; n < len(packet.Payload); n++ {
			if validateTimedPayload(packet.Payload[:n]) == nil {
				t.Fatalf("accepted truncated %s at %d", packet.SlotID, n)
			}
		}
	}
}

// Validate retained output from actual pinned decoder execution. This check
// does not itself claim a fresh decoder run.
func TestRecordedTimedPDML(t *testing.T) {
	dir := os.Getenv("NETFLOW_TSHARK_TIMED_PDML_DIR")
	if dir == "" {
		t.Skip("set NETFLOW_TSHARK_TIMED_PDML_DIR to retained timed PDML")
	}
	repo, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	packets, err := readTimedPackets(repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, packet := range packets {
		data, err := os.ReadFile(filepath.Join(dir, packet.SlotID+".stdout"))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyTimedPDML(data, packet); err != nil {
			t.Fatalf("%s: %v", packet.SlotID, err)
		}
		bad := bytes.Replace(data, []byte(`show="3.000000000"`), []byte(`show="2.000000000"`), 1)
		if bytes.Equal(data, bad) || VerifyTimedPDML(bad, packet) == nil {
			t.Fatalf("%s accepted altered measured time", packet.SlotID)
		}
	}
}
