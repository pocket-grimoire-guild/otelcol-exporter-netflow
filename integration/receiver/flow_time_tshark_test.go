//go:build tshark

package receiver_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReceiverFirstFlowTimeTShark is intentionally tagged because it starts
// an external decoder. The ordinary receiver suite remains independent of
// TShark. Every accepted finite output from the bounded 15-case matrix is
// wrapped in a labelled synthetic Ethernet/IPv4/UDP PCAP; the UDP payloads
// themselves are the actual local exporter reads.
func TestReceiverFirstFlowTimeTShark(t *testing.T) {
	if _, err := exec.LookPath("tshark"); err != nil {
		t.Fatalf("tshark is required for -tags=tshark: %v", err)
	}
	artifactDir := os.Getenv("FLOW_TIME_ARTIFACT_DIR")
	if artifactDir == "" {
		artifactDir = t.TempDir()
	} else if err := os.MkdirAll(artifactDir, 0750); err != nil {
		t.Fatalf("create FLOW_TIME_ARTIFACT_DIR=%s: %v", artifactDir, err)
	}
	version, stderr, err := runFlowTSharkCommand([]string{"--version"})
	if err != nil {
		t.Fatalf("tshark --version: %v\n%s", err, stderr)
	}
	versionText := strings.TrimSpace(string(version))
	t.Logf("TShark version: %s", versionText)
	versionPath := filepath.Join(artifactDir, "tshark-version.txt")
	if err := os.WriteFile(versionPath, version, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("TShark version artifact: %s", versionPath)

	base := uint64(time.Now().Unix() - 3)
	profiles := []string{"netflow-v5-fixed-v1", "netflow-v9-core-v1", "netflow-v9-timed-v1", "ipfix-core-v1", "ipfix-general-v1"}
	var attempts, accepted, rejected int
	for _, tc := range flowTimeFixtures(base) {
		t.Run(tc.name, func(t *testing.T) {
			result := receiveFlowTimeFixture(t, tc, base)
			for _, profile := range profiles {
				if tc.ipv6 && profile == "netflow-v5-fixed-v1" {
					continue
				}
				t.Run(profile, func(t *testing.T) {
					out := exportFlowTime(t, result, profile)
					dataCount := len(dataRecordsFlowTime(t, out.packets, profile))
					wantData := 1
					if out.rejected {
						wantData = 0
					}
					if dataCount != wantData {
						t.Fatalf("%s TShark precheck data records=%d, want %d", profile, dataCount, wantData)
					}
					attempts++
					if out.rejected {
						rejected++
					} else {
						accepted++
					}
					if len(out.packets) == 0 {
						if out.rejected && profile == "netflow-v5-fixed-v1" {
							return
						}
						t.Fatalf("%s output has no finite UDP payloads", profile)
					}
					artifactBase := tc.name + "-" + profile
					pcapPath := filepath.Join(artifactDir, artifactBase+"-synthetic.pcap")
					if err := os.WriteFile(pcapPath, syntheticFlowPCAP(out.packets), 0600); err != nil {
						t.Fatal(err)
					}
					t.Logf("synthetic PCAP envelope: %s (payload bytes are exact local UDP reads)", pcapPath)
					stdoutPath := filepath.Join(artifactDir, artifactBase+"-tshark.stdout")
					rows := runFlowTShark(t, pcapPath, stdoutPath)
					assertFlowTSharkRows(t, rows, len(out.packets), profile, tc, wantData)
				})
			}
		})
	}
	if attempts != 73 || accepted != 67 || rejected != 6 {
		t.Fatalf("flow-time TShark attempts=%d accepted=%d rejected=%d, want 73/67/6", attempts, accepted, rejected)
	}
}

func syntheticFlowPCAP(packets [][]byte) []byte {
	const linkEthernet = 1
	pcap := make([]byte, 24)
	binary.LittleEndian.PutUint32(pcap[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(pcap[4:], 2)
	binary.LittleEndian.PutUint16(pcap[6:], 4)
	binary.LittleEndian.PutUint32(pcap[16:], 65535)
	binary.LittleEndian.PutUint32(pcap[20:], linkEthernet)
	for i, payload := range packets {
		udpLen := 8 + len(payload)
		ipLen := 20 + udpLen
		frameLen := 14 + ipLen
		frame := make([]byte, frameLen)
		binary.BigEndian.PutUint16(frame[12:], 0x0800)
		ip := frame[14:]
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(ipLen))
		binary.BigEndian.PutUint16(ip[4:], uint16(i))
		ip[8], ip[9] = 64, 17
		copy(ip[12:16], net.ParseIP("127.0.0.1").To4())
		copy(ip[16:20], net.ParseIP("127.0.0.1").To4())
		binary.BigEndian.PutUint16(ip[10:], flowInternetChecksum(ip[:20]))
		udp := ip[20:]
		binary.BigEndian.PutUint16(udp[0:], 40000)
		binary.BigEndian.PutUint16(udp[2:], 2055)
		binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
		copy(udp[8:], payload)
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record[0:], uint32(1_789_330_000+i))
		binary.LittleEndian.PutUint32(record[8:], uint32(frameLen))
		binary.LittleEndian.PutUint32(record[12:], uint32(frameLen))
		pcap = append(pcap, record...)
		pcap = append(pcap, frame...)
	}
	return pcap
}

func flowInternetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

func runFlowTSharkCommand(args []string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "tshark", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return stdout.Bytes(), stderr.Bytes(), ctx.Err()
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

func runFlowTShark(t *testing.T, pcapPath, stdoutPath string) [][]string {
	t.Helper()
	args := []string{"-n", "-r", pcapPath, "-d", "udp.port==2055,cflow", "-T", "fields", "-E", "separator=|", "-e", "frame.number", "-e", "cflow.version", "-e", "cflow.srcport", "-e", "cflow.timestart", "-e", "cflow.timeend", "-e", "cflow.timedelta", "-e", "_ws.expert.message"}
	data, stderr, err := runFlowTSharkCommand(args)
	if writeErr := os.WriteFile(stdoutPath, data, 0600); writeErr != nil {
		t.Fatalf("save TShark stdout %s: %v", stdoutPath, writeErr)
	}
	t.Logf("TShark stdout artifact: %s", stdoutPath)
	if err != nil {
		t.Fatalf("tshark %s: %v\n%s", pcapPath, err, stderr)
	}
	var rows [][]string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			rows = append(rows, strings.Split(line, "|"))
		}
	}
	return rows
}

func assertFlowTSharkRows(t *testing.T, rows [][]string, packetCount int, profile string, tc flowTimeFixture, wantData int) {
	t.Helper()
	if len(rows) != packetCount {
		t.Fatalf("%s TShark rows=%d, want %d", profile, len(rows), packetCount)
	}
	version := "10"
	if profileProtocol(profile) == "netflow_v9" {
		version = "9"
	} else if profileProtocol(profile) == "netflow_v5" {
		version = "5"
	}
	dataRows := 0
	for _, row := range rows {
		if len(row) != 7 {
			t.Fatalf("%s malformed TShark row=%q", profile, row)
		}
		if row[1] != version || row[6] != "" {
			t.Fatalf("%s TShark version/expert=%q", profile, row)
		}
		if row[2] != "" {
			dataRows++
			if row[2] != "12345" {
				t.Fatalf("%s TShark source port=%q", profile, row[2])
			}
			if profile == "netflow-v9-core-v1" && (row[3] != "" || row[4] != "" || row[5] != "") {
				t.Fatalf("v9 core unexpectedly exposed timing row=%q", row)
			}
			if wantData != 0 && profile != "netflow-v9-core-v1" && row[5] == "" {
				t.Fatalf("%s data row has no independent duration", profile)
			}
		} else if row[3] != "" || row[4] != "" || row[5] != "" {
			t.Fatalf("%s template row has timing values=%q", profile, row[3:6])
		}
	}
	if dataRows != wantData {
		t.Fatalf("%s TShark data rows=%d, want %d", profile, dataRows, wantData)
	}
	if wantData == 0 {
		return
	}
	if profile == "netflow-v9-core-v1" {
		return
	} // core intentionally omits FIRST/LAST.
	for _, row := range rows {
		if row[2] == "" {
			continue
		}
		got, err := time.ParseDuration(row[5] + "s")
		if err != nil {
			t.Fatalf("%s duration %q: %v", profile, row[5], err)
		}
		want := time.Duration(tc.end - tc.start)
		if profile == "ipfix-general-v1" {
			want = time.Duration((tc.end/1_000_000 - tc.start/1_000_000) * 1_000_000)
		}
		if profile == "ipfix-core-v1" {
			difference := got - want
			if difference < -time.Nanosecond || difference > time.Nanosecond {
				t.Fatalf("%s TShark duration=%q, want %s ±1ns", profile, row[5], want)
			}
		} else if got != want {
			t.Fatalf("%s TShark duration=%q, want %s", profile, row[5], want)
		}
	}
}
