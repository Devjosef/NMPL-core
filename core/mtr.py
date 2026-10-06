import subprocess
import shutil
import platform
import socket
import re
import logging
import struct
import time
from typing import List, Dict

logger = logging.getLogger("nmpl.diagnostics")


def is_mtr_available() -> bool:
    return shutil.which("mtr") is not None


def _parse_float_or_none(raw: str):
    if raw == "???":
        return None
    try:
        return float(raw)
    except (ValueError, TypeError):
        return None


def parse_mtr_output(output: str) -> List[Dict]:
    """
    Parses `mtr -r` report-mode output into hop dicts.

    Known accepted risk: field extraction is positional (parts[4:8] =
    Last/Avg/Best/Wrst). This is resilient to VALUE-level drift (this
    function logs a warning and returns None rather than crashing or
    fabricating a false 0.0 whenever a field fails to parse) but cannot
    detect COLUMN-REORDER drift -- if a future mtr version inserted a
    new column before Avg, every value would still parse successfully,
    just assigned to the wrong key, with no warning fired.

    Deliberately not fixed by dynamic header-name mapping: mtr -r's
    column layout is a decades-stable, widely-depended-upon interface
    that maintainers have strong backward-compatibility incentive never
    to break by insertion (any new fields go at the end of the row, per
    established convention). Also deliberately not fixed by apt-pinning
    mtr-tiny's exact version in the Dockerfile -- rigid version pins on
    packages Debian/Ubuntu rotate out of their mirrors on a security-
    patch cadence trade a near-zero-probability parsing risk for a
    near-certain future build failure. Risk accepted; revisit only if
    an actual mtr output-format change is ever observed in the wild.
    """
    hops = []
    lines = output.strip().split("\n")
    for line in lines:
        line_str = line.strip()
        if not line_str or line_str.startswith("Start:") or line_str.startswith("HOST:"):
            continue
        parts = re.split(r"\s+", line_str)
        if not parts:
            continue

        hop_raw = parts[0].rstrip(".|").split("|")[0].strip(".")
        if not hop_raw.isdigit():
            continue

        try:
            host = parts[1]
            if host == "???" or "Loss%" in line_str:
                loss_val = 100.0 if host == "???" else float(parts[2].rstrip("%"))
                hops.append({
                    "hop": int(hop_raw),
                    "host": host,
                    "loss": loss_val,
                    "sent": int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0,
                    "last": None, "avg": None, "best": None, "worst": None
                })
                continue

            last = _parse_float_or_none(parts[4])
            avg = _parse_float_or_none(parts[5])
            best = _parse_float_or_none(parts[6])
            worst = _parse_float_or_none(parts[7])

            if any(v is None for v in (last, avg, best, worst)) and "???" not in (parts[4], parts[5], parts[6], parts[7]):
                logger.warning(
                    f"mtr hop {hop_raw} ({host}) had unparseable timing field(s) despite "
                    f"non-placeholder output — possible mtr version/format drift. Raw: {parts[4:8]}"
                )

            hops.append({
                "hop": int(hop_raw),
                "host": host,
                "loss": float(parts[2].rstrip("%")),
                "sent": int(parts[3]),
                "last": last, "avg": avg, "best": best, "worst": worst
            })
        except (ValueError, IndexError) as e:
            logger.warning(f"Skipping malformed MTR hop line due to parsing error: {e}. Line: {line_str}")
            continue
    return hops


def run_mtr(target: str, count: int = 10) -> List[Dict]:
    if not is_mtr_available():
        system = platform.system()
        if system == "Windows":
            logger.error("MTR is not available on Windows. NMPL hop-by-hop tracing requires the POSIX version of MTR.")
        else:
            logger.error("The 'mtr' binary was not found on the system PATH.")
        return []
    cmd = ["mtr", "-r", "-c", str(count), "-w", "--no-dns", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            return parse_mtr_output(result.stdout)
        else:
            logger.error(f"MTR execution failed: {result.stderr}")
            return []
    except subprocess.TimeoutExpired:
        logger.error(f"MTR command timed out against target: {target}")
        return []
    except FileNotFoundError:
        logger.error("MTR binary disappeared during execution context.")
        return []


def _matching_icmp_response(packet: bytes, target_ip: str, source_port: int, dest_port: int):
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None

    outer_header_length = (packet[0] & 0x0F) * 4
    if outer_header_length < 20 or len(packet) < outer_header_length + 8 + 20:
        return None

    icmp_offset = outer_header_length
    icmp_type, icmp_code = struct.unpack_from("!BB", packet, icmp_offset)
    if icmp_type not in (3, 11):
        return None

    inner_offset = icmp_offset + 8
    inner_header_length = (packet[inner_offset] & 0x0F) * 4
    if (packet[inner_offset] >> 4 != 4 or inner_header_length < 20
            or packet[inner_offset + 9] != socket.IPPROTO_UDP
            or len(packet) < inner_offset + inner_header_length + 8):
        return None

    inner_destination = socket.inet_ntoa(packet[inner_offset + 16:inner_offset + 20])
    udp_offset = inner_offset + inner_header_length
    quoted_source_port, quoted_dest_port = struct.unpack_from("!HH", packet, udp_offset)
    if (inner_destination != target_ip or quoted_source_port != source_port
            or quoted_dest_port != dest_port):
        return None

    return icmp_type, icmp_code


def run_paris_trace(
    target: str,
    max_hops: int = 30,
    probes_per_hop: int = 3,
    timeout: float = 1.0,
) -> List[Dict]:
    """Trace an IPv4 path while keeping the UDP flow tuple constant across TTLs."""
    if max_hops < 1 or probes_per_hop < 1 or timeout <= 0:
        raise ValueError("max_hops, probes_per_hop, and timeout must be positive")

    try:
        target_ip = socket.gethostbyname(target)
    except OSError as error:
        logger.error(f"Unable to resolve Paris traceroute target {target}: {error}")
        return []

    dest_port = 33434
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    icmp_sock = None
    try:
        udp_sock.bind(("", 0))
        source_port = udp_sock.getsockname()[1]
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        hops = []

        for hop_ttl in range(1, max_hops + 1):
            responses = []
            reached_target = False
            for _ in range(probes_per_hop):
                udp_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, hop_ttl)
                icmp_sock.setblocking(False)
                while True:
                    try:
                        icmp_sock.recvfrom(512)
                    except BlockingIOError:
                        break
                started = time.monotonic()
                udp_sock.sendto(b"NMPL Paris traceroute", (target_ip, dest_port))
                deadline = started + timeout

                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    icmp_sock.settimeout(remaining)
                    try:
                        packet, (router_ip, _) = icmp_sock.recvfrom(512)
                    except socket.timeout:
                        break

                    response = _matching_icmp_response(
                        packet, target_ip, source_port, dest_port
                    )
                    if response is None:
                        continue

                    icmp_type, _ = response
                    responses.append((router_ip, (time.monotonic() - started) * 1000.0))
                    if router_ip == target_ip and icmp_type == 3:
                        reached_target = True
                    break

            if responses:
                latencies = [latency for _, latency in responses]
                hop = {
                    "hop": hop_ttl,
                    "host": responses[-1][0],
                    "loss": (probes_per_hop - len(responses)) * 100.0 / probes_per_hop,
                    "sent": probes_per_hop,
                    "last": latencies[-1],
                    "avg": sum(latencies) / len(latencies),
                    "best": min(latencies),
                    "worst": max(latencies),
                }
            else:
                hop = {
                    "hop": hop_ttl,
                    "host": "???",
                    "loss": 100.0,
                    "sent": probes_per_hop,
                    "last": None,
                    "avg": None,
                    "best": None,
                    "worst": None,
                }
            hops.append(hop)
            if reached_target:
                break

        return hops
    except OSError as error:
        logger.error(
            f"Paris traceroute failed for {target}; raw ICMP socket access may be required: {error}"
        )
        return []
    finally:
        udp_sock.close()
        if icmp_sock is not None:
            icmp_sock.close()