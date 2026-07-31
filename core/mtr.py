import subprocess
import shutil
import platform
import re
import logging
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