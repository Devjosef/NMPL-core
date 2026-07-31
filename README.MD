# NMPL Core (No More Packet Loss)

[![License: MIT / Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](#license)

**NMPL Core** is the standalone, lightweight packet loss detection and hop-localization engine powering the **No More Packet Loss** platform.

For the production-ready build featuring a web dashboard, ASN/RDAP network enrichment lookups, automated evidence exports, background monitoring, and pre-built Docker containers, visit **[getnmpl.com](https://www.getnmpl.com)**.

It provides real-time packet loss detection, per-target adaptive baseline analysis, and automated `mtr` hop-by-hop bottleneck tracing.

---

## Key Features

- **Adaptive Baseline Detection:** Learns a target's normal baseline over its first ~30 probes to prevent false alarms on naturally lossy or rate-limited links.
- **Hop Localization:** Automatically runs traceroutes (`mtr`) on detected loss events to isolate specific dropped segments and path bottlenecks.
- **Offline Resilient:** Core detection, latency tracking, and metric persistence run fully offline.
- **Zero External UI Dependencies:** Designed to be imported directly as a Python package or run via lightweight CLI scripts.

---

## Requirements & Platform Support

- **Python:** 3.9+
- **ICMP/UDP Probes:** Supported on Linux, macOS, and Windows.
- **Hop Tracing (`mtr`):** Requires the `mtr` system binary installed (`sudo apt install mtr` on Linux / `brew install mtr` on macOS).

---

## Quickstart

### Installation

```bash
git clone [https://github.com/Devjosef/NMPL-core.git](https://github.com/Devjosef/NMPL-core.git)
cd NMPL-core
```

## Usage
Run single-target or live monitoring probes directly using Python:

```bash
# Basic loss test
python3 -m core 8.8.8.8

# Live single-target monitoring
python3 -m core 8.8.8.8 --watch

# Traceroute + bottleneck analysis
python3 -m core 8.8.8.8 --mtr

# Export raw hop data to JSON/CSV
python3 -m core 8.8.8.8 --mtr --json=proof.json --csv=hops.csv
```

## Architecture & Detection Engine
Each monitored target receives a dedicated, persistent Detector instance. It establishes an initial baseline over a warm-up window (~30 probes) to account for targets that naturally throttle ICMP traffic, preventing false positive alerts while maintaining absolute loss thresholds for severe outages.

## License
Dual-licensed under either:

MIT License (LICENSE-MIT or http://opensource.org/licenses/MIT)

Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)

At your option.