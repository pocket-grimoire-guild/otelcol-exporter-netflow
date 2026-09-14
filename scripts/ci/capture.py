#!/usr/bin/env python3
"""Run one command while retaining a bounded combined stdout/stderr log."""
import argparse
import os
import signal
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-bytes", required=True, type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.max_bytes <= 0 or not args.command or args.command[0] != "--":
        parser.error("a positive --max-bytes and command after -- are required")
    command = args.command[1:]
    output = Path(args.output)
    child = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    def terminate_child():
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()

    def stop_child(signum, _frame):
        terminate_child()
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, stop_child)
    signal.signal(signal.SIGINT, stop_child)
    size = 0
    overflow = False
    with output.open("ab") as log:
        assert child.stdout is not None
        while True:
            try:
                chunk = os.read(child.stdout.fileno(), 65536)
            except InterruptedError:
                terminate_child()
                return 128 + signal.SIGTERM
            if not chunk:
                break
            if size + len(chunk) > args.max_bytes:
                remaining = args.max_bytes - size
                if remaining > 0:
                    log.write(chunk[:remaining])
                log.flush()
                overflow = True
                break
            log.write(chunk)
            size += len(chunk)
        if overflow:
            terminate_child()
            return 125
    return child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
