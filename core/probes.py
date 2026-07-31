import subprocess
import platform
import socket
import random
import re
import logging

logger = logging.getLogger("nmpl.diagnostics")

_SYSTEM = platform.system().lower()
_LATENCY_RE = re.compile(r"time[=:<]\s*([\d.]+)\s*(ms)?", re.IGNORECASE)


def icmp_probe(target, packet_size=64, timeout=1):
    payload = max(packet_size - 28, 0)

    if _SYSTEM == "windows":
        cmd = ["ping", "-n", "1", "-l", str(payload), "-w", str(int(timeout * 1000)), target]
    elif _SYSTEM == "darwin":
        cmd = ["ping", "-c", "1", "-s", str(payload), "-W", str(int(timeout * 1000)), target]
    else:
        cmd = ["ping", "-c", "1", "-s", str(payload), "-W", str(timeout), target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
    except subprocess.TimeoutExpired:
        return False, None
    except FileNotFoundError:
        logger.error("'ping' binary not found on this system.")
        return False, None

    success = (result.returncode == 0)
    if not success:
        return False, None

    match = _LATENCY_RE.search(result.stdout)
    if not match:
        logger.warning(
            f"ping succeeded (rc=0) but latency could not be parsed from output — "
            f"possible format drift. First 200 chars: {result.stdout[:200]!r}"
        )
        return True, None

    try:
        return True, float(match.group(1))
    except ValueError:
        logger.warning(f"Matched latency token but failed to parse as float: {match.group(1)!r}")
        return True, None


def udp_probe(target, timeout=1, jitter=True):
    payload_size = random.randint(32, 512)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        payload = b"A" * payload_size
        sock.sendto(payload, (target, 53))
        sock.recvfrom(1024)
        return True
    except socket.timeout:
        return False
    except Exception:
        return False
    finally:
        sock.close()