#!/usr/bin/env python3
"""Capture the OCB smoke on a disposable veth link; never repair packet bytes."""

import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import signal
import socket
import struct
import subprocess
import sys
import threading


def run(*args):
    return subprocess.check_output(args, timeout=5, stderr=subprocess.STDOUT).decode()


def offload(interface):
    # Linux UAPI ethtool_value / ifreq, GTXCSUM and STXCSUM. Veth exposes
    # mutable checksum features; lo does not. Verify the effective setting.
    if interface not in ("ocb0", "ocb1"):
        raise ValueError("only the disposable veth is supported")
    value = (ctypes.c_uint32 * 2)()
    request = struct.pack("16sP", interface.encode(), ctypes.addressof(value))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        values = []
        for command, data in ((0x16, 0), (0x17, 0), (0x16, 0)):
            value[0], value[1] = command, data
            fcntl.ioctl(sock, 0x8946, request)
            values.append(value[1])
        if values[-1] != 0:
            raise ValueError("transmit checksum offload remains enabled")
    return {"interface": interface, "tx_checksum_before": values[0], "tx_checksum_after": values[-1]}


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total == 65535


def envelope(frame):
    if len(frame) < 43 or len(frame) > 65549 or frame[12:14] != b"\x08\x00":
        raise ValueError("invalid Ethernet/IPv4 framing")
    ip, udp = frame[14:34], frame[34:]
    if (ip[0] != 0x45 or ip[9] != 17 or struct.unpack("!H", ip[2:4])[0] != len(frame) - 14
            or struct.unpack("!H", ip[6:8])[0] & 0x3FFF or not checksum(ip)):
        raise ValueError("invalid IPv4 header/length/fragment/checksum")
    if (struct.unpack("!H", udp[4:6])[0] != len(udp) or udp[6:8] == b"\0\0"
            or not checksum(ip[12:20] + b"\0\x11" + udp[4:6] + udp)):
        raise ValueError("invalid or unfinished UDP length/checksum")
    source, dest = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    if (source, dest) != ("198.18.0.2", "198.18.0.1"):
        raise ValueError("packet did not traverse the Collector veth")
    sport, dport = struct.unpack("!HH", udp[:4])
    return f"{source}:{sport}", f"{dest}:{dport}", udp[8:]


def bind_packets(frames, outputs, root):
    if len(frames) != 21 or len(outputs) != 21:
        raise ValueError("the complete smoke must emit exactly 21 output datagrams")
    unmatched = set(range(21))
    indexes = []
    for frame, _, _ in frames:
        source, endpoint, payload = envelope(frame)
        matches = [i for i in unmatched if outputs[i]["Source"] == source
                   and outputs[i]["Endpoint"] == endpoint
                   and outputs[i]["Length"] == len(payload)
                   and outputs[i]["SHA256"] == hashlib.sha256(payload).hexdigest()
                   and (root / outputs[i]["File"]).read_bytes() == payload]
        # Repeated bootstrap packets can be byte-identical. Preserve occurrence
        # order within their socket, consuming each application datagram once.
        if not matches:
            raise ValueError("captured packet has no application-datagram match")
        index = min(matches)
        unmatched.remove(index)
        indexes.append(index)
    if unmatched:
        raise ValueError("application datagrams missing from capture")
    return indexes


def write_pcap(path, frames):
    # Only capture framing is authored. Every Ethernet/IP/UDP/payload byte and
    # SO_TIMESTAMPNS timestamp comes directly from the receiving packet socket.
    with path.open("xb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65549, 1))
        for frame, seconds, nanos in frames:
            output.write(struct.pack("<IIII", seconds, nanos, len(frame), len(frame)))
            output.write(frame)


def main():
    resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))
    if os.getuid() != 0 or int(Path("/proc/self/uid_map").read_text().split()[1]) == 0:
        raise ValueError("requires root inside a rootless disposable container")
    if socket.if_nameindex() != [(1, "lo")]:
        raise ValueError("requires a fresh --network=none namespace")
    holder = subprocess.Popen(["unshare", "--net", sys.executable, __file__, "--hold"], stdout=subprocess.PIPE)
    process = None
    stop = threading.Event()
    try:
        if not select.select([holder.stdout], [], [], 5)[0] or holder.stdout.readline(16) != b"ready\n":
            raise ValueError("network namespace readiness failed")
        ns = f"/proc/{holder.pid}/ns/net"
        run("ip", "link", "add", "ocb0", "type", "veth", "peer", "name", "ocb1")
        run("ip", "link", "set", "ocb1", "netns", str(holder.pid))
        run("ip", "addr", "add", "198.18.0.1/30", "dev", "ocb0")
        run("ip", "link", "set", "ocb0", "up")
        enter = ("nsenter", "--net=" + ns, "--")
        run(*enter, "ip", "link", "set", "lo", "up")
        run(*enter, "ip", "addr", "add", "198.18.0.2/30", "dev", "ocb1")
        run(*enter, "ip", "link", "set", "ocb1", "up")
        settings = [offload("ocb0"), json.loads(run(*enter, sys.executable, __file__, "--offload", "ocb1"))]
        identity = {"kernel": os.uname().release, "driver_netns": os.readlink("/proc/self/ns/net"),
                    "collector_netns": os.readlink(ns), "offload": settings,
                    "driver_link": run("ip", "-details", "link", "show", "ocb0"),
                    "collector_link": run(*enter, "ip", "-details", "link", "show", "ocb1")}
        frames, errors = [], []
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw:
            raw.bind(("ocb0", 0))
            raw.setsockopt(socket.SOL_SOCKET, 35, 1)  # SO_TIMESTAMPNS (Linux/amd64)
            raw.settimeout(0.1)

            def capture():
                try:
                    while not stop.is_set():
                        try:
                            frame, ancillary, flags, address = raw.recvmsg(65549, 128)
                        except socket.timeout:
                            continue
                        if address[2] != 0:  # PACKET_HOST only, never outgoing copies
                            raise ValueError("unexpected packet direction")
                        if len(frame) < 34 or frame[23] != 17:
                            continue  # ICMP is not exporter UDP evidence
                        if flags or len(frames) >= 64:
                            raise ValueError("truncated/over-limit live capture")
                        stamps = [struct.unpack("@ll", data) for level, kind, data in ancillary
                                  if level == socket.SOL_SOCKET and kind == 35]
                        if len(stamps) != 1 or not 0 <= stamps[0][1] < 1_000_000_000:
                            raise ValueError("missing kernel packet timestamp")
                        frames.append((frame, *stamps[0]))
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=capture)
            thread.start()
            env = dict(os.environ, NETFLOW_OCB_NETNS=ns, NETFLOW_OCB_ARTIFACTS="/output",
                       NETFLOW_OCB_BINARY="/input/collector")
            with open("/output/smoke.log", "xb") as log:
                process = subprocess.Popen(["/input/driver", "-test.run=^TestCollectorSmoke$", "-test.v", "-test.timeout=60s"],
                                           cwd="/input/integration/ocb", env=env, stdout=log, stderr=subprocess.STDOUT)
                try:
                    code = process.wait(timeout=65)
                finally:
                    stop.set()
                    thread.join(timeout=2)
            if thread.is_alive() or errors or code != 0:
                raise ValueError(f"smoke/capture failed: exit={code}, errors={errors}; see smoke.log")
            packets, dropped = struct.unpack("II", raw.getsockopt(263, 6, 8))  # PACKET_STATISTICS
            if dropped or packets != len(frames):
                raise ValueError("packet socket dropped or excluded IPv4 packets")
        roots = list(Path("/output").glob("ocb-*"))
        if len(roots) != 1:
            raise ValueError("missing/extra fresh smoke directory")
        root = roots[0]
        manifest = json.loads((root / "capture.json").read_text())
        identity["application_indexes"] = bind_packets(frames, manifest["Outputs"], root)
        identity["packet_socket_packets"], identity["packet_socket_drops"] = packets, dropped
        write_pcap(root / "live.pcap", frames)
        identity["pcap_sha256"] = hashlib.sha256((root / "live.pcap").read_bytes()).hexdigest()
        (root / "network.json").write_text(json.dumps(identity, indent=2) + "\n")
        print(f"PASS: 21 live veth packets match the OCB smoke; original IPv4/UDP checksums valid: {root}")
    finally:
        stop.set()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        holder.kill()
        holder.wait(timeout=3)
        holder.stdout.close()


if __name__ == "__main__":
    if sys.argv[1:] == ["--hold"]:
        print("ready", flush=True)
        signal.pause()
    elif len(sys.argv) == 3 and sys.argv[1] == "--offload":
        print(json.dumps(offload(sys.argv[2])))
    else:
        main()
