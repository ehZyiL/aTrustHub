#!/usr/bin/env python3
"""Measure an existing desktop path with a controlled, authorized HTTP fixture."""

import argparse
import concurrent.futures
import ctypes
import ipaddress
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit


def process_cpu(pid):
    """Return (creation identity, CPU seconds), or raise if unavailable."""
    if sys.platform == "win32":
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
        kernel.GetProcessTimes.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            fields = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(field) for field in fields)):
                raise ctypes.WinError(ctypes.get_last_error())
            started, exited, kernel_time, user_time = [
                (field.dwHighDateTime << 32) | field.dwLowDateTime for field in fields
            ]
            if exited:
                raise ProcessLookupError(pid)
            return started, (kernel_time + user_time) / 10_000_000
        finally:
            kernel.CloseHandle(handle)
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    if fields[0] in {"X", "Z"}:
        raise ProcessLookupError(pid)
    return int(fields[19]), (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def snapshot(pids):
    result = {}
    for label, pid in pids.items():
        try:
            result[label] = process_cpu(pid)
        except (OSError, ValueError):
            result[label] = None
    return result


def measure(command, timeout, expected, expected_bytes):
    try:
        p = subprocess.run(command, capture_output=True, timeout=timeout + 2, check=False)
    except subprocess.TimeoutExpired:
        return {"failure": "client_timeout"}
    if p.returncode:
        return {"failure": "curl", "exit_code": p.returncode}
    try:
        status, size, lookup, connect, tls, ready, first, total = p.stdout.split()
        status, size = int(status), int(size)
        lookup, connect, tls, ready, first, total = map(float, (lookup, connect, tls, ready, first, total))
    except ValueError:
        return {"failure": "invalid_timing_output"}
    if status != expected:
        return {"failure": "http_status", "status": status}
    if expected_bytes is not None and size != expected_bytes:
        return {"failure": "body_size", "status": status, "bytes": size}
    return {
        "status": status, "bytes": size, "client_lookup_ms": lookup * 1000,
        "client_tcp_ms": (connect - lookup) * 1000, "tls_ready_ms": tls * 1000 if tls else None,
        "transfer_ready_ms": ready * 1000, "first_byte_ms": first * 1000, "total_ms": total * 1000,
        "body_mib_per_s": size / ((total - first) * 1024**2) if total > first else None,
    }


def quantiles(values):
    ordered = sorted(v for v in values if v is not None)
    if not ordered:
        return None
    return {f"p{p}": ordered[math.ceil(len(ordered) * p / 100) - 1] for p in (50, 95)}


def log_stamp(path):
    try:
        state = path.stat()
        return (state.st_dev, state.st_ino), state.st_size
    except OSError:
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["proxy", "tun"], required=True)
    parser.add_argument("--url", required=True, help="fixed HTTP(S) resource returning a known status and body")
    parser.add_argument("--proxy-port", type=int, help="dedicated IPv4 loopback SOCKS5 port, required for proxy mode")
    parser.add_argument("--requests", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=15, help="per request, in seconds")
    parser.add_argument("--status", type=int, default=200, help="expected HTTP response status")
    parser.add_argument("--bytes", type=int, help="expected response body size in bytes")
    parser.add_argument("--pid", action="append", default=[], metavar="LABEL=PID", help="GUI, worker or helper to sample")
    parser.add_argument("--log", type=Path, help="optional file used only to measure aggregate byte growth")
    args = parser.parse_args()
    try:
        url = urlsplit(args.url)
        if (url.scheme not in {"http", "https"} or not url.hostname or url.username is not None
                or url.query or url.fragment or url.port == 0):
            raise ValueError()
        try:
            literal = ipaddress.ip_address(url.hostname)
        except ValueError:
            literal = None
        if literal and literal.version != 4:
            raise ValueError()
    except ValueError:
        parser.error("use an HTTP(S) IPv4 resource URL without credentials, query or fragment")
    if ((args.mode == "proxy") != (args.proxy_port is not None)
            or (args.proxy_port is not None and not 1 <= args.proxy_port <= 65535)):
        parser.error("supply a valid --proxy-port in proxy mode only")
    if not (1 <= args.concurrency <= min(args.requests, 32) and 1 <= args.requests <= 1000
            and 1 <= args.timeout <= 120 and 200 <= args.status <= 599):
        parser.error("requests: 1–1000; concurrency: 1–32 and <= requests; timeout: 1–120; status: 200–599")
    if args.bytes is not None and args.bytes < 0:
        parser.error("expected response body size must be nonnegative")
    pids = {}
    for pair in args.pid:
        label, _, pid = pair.partition("=")
        if not label or label in pids or not pid.isascii() or not pid.isdecimal() or not 0 < int(pid) <= 0xFFFF_FFFF:
            parser.error("supply each --pid as a distinct LABEL=PID")
        pids[label] = int(pid)
    curl = shutil.which("curl.exe" if sys.platform == "win32" else "curl")
    if curl is None:
        parser.error("curl is required")
    write_out = " ".join("%{" + name + "}" for name in (
        "http_code", "size_download", "time_namelookup", "time_connect",
        "time_appconnect", "time_pretransfer", "time_starttransfer", "time_total",
    ))
    # Ignore .curlrc and proxy environment settings. Do not follow redirects.
    proxy = f"socks5h://127.0.0.1:{args.proxy_port}" if args.mode == "proxy" else ""
    command = [curl, "-q", "--silent", "--ipv4", "--globoff", "--http1.1",
               "--proxy", proxy, "--noproxy", "", "--max-time", str(args.timeout),
               "--output", os.devnull, "--write-out", write_out, "--url", args.url]
    log_before = log_stamp(args.log) if args.log else None
    before = snapshot(pids)
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        samples = list(pool.map(lambda _: measure(command, args.timeout, args.status, args.bytes), range(args.requests)))
    elapsed = time.perf_counter() - started
    after = snapshot(pids)
    log_after = log_stamp(args.log) if args.log else None
    cpu = {}
    for label in pids:
        a, b = before[label], after[label]
        cpu[label] = b[1] - a[1] if a and b and a[0] == b[0] and b[1] >= a[1] else None
    successful = [sample for sample in samples if "failure" not in sample]
    metrics = ("client_lookup_ms", "client_tcp_ms", "tls_ready_ms", "transfer_ready_ms",
               "first_byte_ms", "total_ms", "body_mib_per_s")
    print(json.dumps({
        "mode": args.mode, "target_kind": "ipv4" if literal else "domain",
        "requests": args.requests, "expected_status": args.status, "expected_bytes": args.bytes,
        "concurrency": args.concurrency,
        "wall_seconds": elapsed, "failed": len(samples) - len(successful), "cpu_seconds": cpu,
        "log_bytes_added": log_after[1] - log_before[1] if (
            log_before and log_after and log_after[0] == log_before[0] and log_after[1] >= log_before[1]
        ) else None,
        "successful_mib_per_s": sum(s["bytes"] for s in successful) / (elapsed * 1024**2),
        "percentiles": {m: quantiles([s[m] for s in successful]) for m in metrics},
        "samples": samples,
    }, indent=2))
    return 0 if len(successful) == args.requests else 1


if __name__ == "__main__":
    sys.exit(main())
