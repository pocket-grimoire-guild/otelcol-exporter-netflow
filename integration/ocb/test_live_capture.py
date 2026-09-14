import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import live_capture as live


def sum_bytes(data):
    total = 0
    for i, value in enumerate(data):
        total += value << (8 if i % 2 == 0 else 0)
    while total > 65535:
        total = (total & 65535) + (total >> 16)
    return struct.pack("!H", (~total) & 65535)


def frame(payload=b"odd"):
    ip = bytearray.fromhex("450000000000400040110000c6120002c6120001")
    ip[2:4] = struct.pack("!H", 28 + len(payload))
    ip[10:12] = sum_bytes(ip)
    udp = bytearray(struct.pack("!HHHH", 40000, 2055, 8 + len(payload), 0) + payload)
    udp[6:8] = sum_bytes(ip[12:20] + b"\0\x11" + udp[4:6] + udp)
    return bytes.fromhex("0200000000010200000000020800") + ip + udp


class LiveCaptureTests(unittest.TestCase):
    def test_independent_checksum_vector(self):
        self.assertTrue(live.checksum(bytes.fromhex("0001f203f4f5f6f7220d")))
        self.assertFalse(live.checksum(bytes.fromhex("0001f203f4f5f6f7220c")))

    def test_envelope_rejects_corruption(self):
        good = frame()
        self.assertEqual(live.envelope(good), ("198.18.0.2:40000", "198.18.0.1:2055", b"odd"))
        for cut in range(len(good)):
            with self.subTest(cut=cut), self.assertRaises(ValueError):
                live.envelope(good[:cut])
        for offset in range(12, len(good)):
            bad = bytearray(good)
            bad[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                live.envelope(bad)
        for bad in (good + b"\0", good[:40] + b"\0\0" + good[42:]):
            with self.assertRaises(ValueError):
                live.envelope(bad)

    def test_bijection_and_original_pcap_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            frames, outputs = [], []
            for i in range(21):
                payload = bytes([i])
                name = f"{i}.bin"
                (root / name).write_bytes(payload)
                outputs.append(dict(File=name, Length=1, SHA256=hashlib.sha256(payload).hexdigest(),
                                    Source="198.18.0.2:40000", Endpoint="198.18.0.1:2055"))
                frames.append((frame(payload), 100, i))
            self.assertEqual(live.bind_packets(frames[::-1], outputs, root), list(range(20, -1, -1)))
            for bad_frames in (frames[:-1], frames + frames[:1], frames[:-1] + frames[:1]):
                with self.assertRaises(ValueError):
                    live.bind_packets(bad_frames, outputs, root)
            bad = json.loads(json.dumps(outputs))
            bad[0]["Source"] = "198.18.0.2:40001"
            with self.assertRaises(ValueError):
                live.bind_packets(frames, bad, root)
            # A checksummed substituted payload cannot inherit a valid ledger.
            with self.assertRaises(ValueError):
                live.bind_packets([(frame(b"x"), 100, 0)] + frames[1:], outputs, root)
            pcap = root / "live.pcap"
            live.write_pcap(pcap, frames)
            data = pcap.read_bytes()
            self.assertEqual(struct.unpack("<I", data[:4])[0], 0xA1B23C4D)
            offset = 24
            for original, sec, ns in frames:
                self.assertEqual(struct.unpack("<IIII", data[offset:offset+16]), (sec, ns, len(original), len(original)))
                self.assertEqual(data[offset+16:offset+16+len(original)], original)
                offset += 16 + len(original)
            self.assertEqual(offset, len(data))
            with self.assertRaises(FileExistsError):
                live.write_pcap(pcap, frames)


if __name__ == "__main__":
    unittest.main()
