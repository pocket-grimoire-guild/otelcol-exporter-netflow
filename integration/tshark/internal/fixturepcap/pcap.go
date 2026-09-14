// Package fixturepcap wraps immutable exporter goldens for independent decoding.
// It deliberately supports only the synthetic Ethernet/IPv4/UDP fixture format;
// it is not a live-capture reader or a NetFlow/IPFIX encoder/decoder.
package fixturepcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const maxPayload = 65507

// Wrap copies payload without interpreting or changing its flow headers, sets,
// records, or padding. The outer addresses describe the synthetic transport,
// including for goldens whose measured flows contain IPv6 addresses.
func Wrap(payload []byte, port uint16) ([]byte, error) {
	if len(payload) == 0 || len(payload) > maxPayload || port == 0 {
		return nil, fmt.Errorf("invalid UDP fixture payload length or port")
	}
	frame := make([]byte, 14+20+8+len(payload))
	copy(frame, []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0})
	ip := frame[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(frame)-14))
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // Don't fragment.
	copy(ip[12:20], []byte{192, 0, 2, 254, 192, 0, 2, 253})
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	udp := frame[34:]
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], port)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	sum := udpChecksum(ip, udp)
	if sum == 0 {
		sum = 0xffff // RFC 768: computed zero is transmitted as all ones.
	}
	binary.BigEndian.PutUint16(udp[6:8], sum)
	pcap := make([]byte, 24+16+len(frame))
	le := binary.LittleEndian
	le.PutUint32(pcap[0:4], 0xa1b2c3d4)
	le.PutUint16(pcap[4:6], 2)
	le.PutUint16(pcap[6:8], 4)
	le.PutUint32(pcap[16:20], 65549) // Complete maximum IPv4 Ethernet frame, no FCS.
	le.PutUint32(pcap[20:24], 1)     // LINKTYPE_ETHERNET.
	le.PutUint32(pcap[24:28], 1788220803)
	le.PutUint32(pcap[32:36], uint32(len(frame)))
	le.PutUint32(pcap[36:40], uint32(len(frame)))
	copy(pcap[40:], frame)
	return pcap, nil
}

// Extract verifies framing and checksums before returning the sole UDP payload.
// It parses the envelope independently of Wrap; byte identity with a named
// golden is checked separately by Verify. No decoded flow value is authority
// for the payload, and no unchecked/truncated/extra packet may disappear.
func Extract(pcap []byte, port uint16) ([]byte, error) {
	le, be := binary.LittleEndian, binary.BigEndian
	if len(pcap) < 82 || len(pcap) > 40+14+20+8+maxPayload {
		return nil, fmt.Errorf("PCAP size outside single-datagram bounds")
	}
	if le.Uint32(pcap[:4]) != 0xa1b2c3d4 || le.Uint16(pcap[4:6]) != 2 || le.Uint16(pcap[6:8]) != 4 ||
		le.Uint64(pcap[8:16]) != 0 || le.Uint32(pcap[16:20]) != 65549 || le.Uint32(pcap[20:24]) != 1 {
		return nil, fmt.Errorf("unsupported synthetic PCAP header")
	}
	if le.Uint32(pcap[24:28]) != 1788220803 || le.Uint32(pcap[28:32]) != 0 ||
		le.Uint32(pcap[32:36]) != uint32(len(pcap)-40) || le.Uint32(pcap[36:40]) != uint32(len(pcap)-40) {
		return nil, fmt.Errorf("PCAP must contain exactly one complete fixture packet")
	}
	frame := pcap[40:]
	if !bytes.Equal(frame[:14], []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0}) {
		return nil, fmt.Errorf("unexpected fixture Ethernet header")
	}
	ip := frame[14:34]
	if ip[0] != 0x45 || ip[1] != 0 || be.Uint16(ip[2:4]) != uint16(len(frame)-14) ||
		be.Uint16(ip[4:6]) != 0 || be.Uint16(ip[6:8]) != 0x4000 || ip[8] != 64 || ip[9] != 17 ||
		!bytes.Equal(ip[12:20], []byte{192, 0, 2, 254, 192, 0, 2, 253}) {
		return nil, fmt.Errorf("unexpected IPv4 length, fragmentation, or header fields")
	}
	if checksum(ip) != 0 {
		return nil, fmt.Errorf("invalid IPv4 checksum")
	}
	udp := frame[34:]
	if be.Uint16(udp[:2]) != 40000 || port == 0 || be.Uint16(udp[2:4]) != port ||
		int(be.Uint16(udp[4:6])) != len(udp) || len(udp) <= 8 {
		return nil, fmt.Errorf("unexpected UDP ports or length")
	}
	if be.Uint16(udp[6:8]) == 0 || udpChecksum(ip, udp) != 0 {
		return nil, fmt.Errorf("missing or invalid UDP checksum")
	}
	return udp[8:], nil
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksum(ip, udp []byte) uint16 {
	// A bounded, even-sized pseudoheader precedes the UDP bytes (RFC 768).
	data := make([]byte, 12+len(udp))
	copy(data[:8], ip[12:20])
	data[9] = 17
	binary.BigEndian.PutUint16(data[10:12], uint16(len(udp)))
	copy(data[12:], udp)
	return checksum(data)
}
