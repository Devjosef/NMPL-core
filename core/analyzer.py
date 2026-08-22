import logging
from typing import Dict, List, Optional

logger = logging.getLogger("nmpl.diagnostics")

SUGGESTION_RATE_LIMITED = "Notice: Hop {hop} ({host}) is likely ICMP rate-limited. Destination is reachable with low loss."
SUGGESTION_CRITICAL = "Critical: Persistent packet loss at Hop {hop} ({host}) extending down the path."
SUGGESTION_UNSTABLE = "Warning: Unstable connection or intermittent loss detected at Hop {hop} ({host})."
SUGGESTION_ELEVATED = "Notice: Elevated loss ({loss:.1f}%) at Hop {hop} ({host}). Below critical, but worth monitoring."
SUGGESTION_HEALTHY = "Info: Path healthy."
SUGGESTION_UNCONFIRMED_ENDPOINT = "Notice: Final hop is unresponsive; endpoint loss is unconfirmed."
COSMETIC_LATENCY_NOTE = (
    "Note: Hop {hop} ({host}) shows an isolated latency spike that drops immediately "
    "at the next hop. This is a common router control-plane artifact, not real path congestion. "
    "See NANOG 47 'Practical Guide to Traceroute' for background; "
    "do not treat this hop's latency as evidence on its own."
)

CRITICAL_LOSS_THRESHOLD = 20.0
ELEVATED_LOSS_THRESHOLD = 5.0

LATENCY_SPIKE_RATIO = 3.0
LATENCY_RECOVERY_RATIO = 0.5
LATENCY_RECOVERY_CEILING = 1.5


def _detect_isolated_latency_spike(hops: List[Dict]) -> Optional[Dict]:
    """Detects single-hop RTT spikes that recover on the next hop (control-plane artifacts)."""
    valid = [h for h in hops if h.get("avg") is not None]
    for i in range(1, len(valid) - 1):
        prev_avg = valid[i - 1]["avg"]
        curr_avg = valid[i]["avg"]
        next_avg = valid[i + 1]["avg"]

        if prev_avg <= 0 or curr_avg <= 0:
            continue

        spike_ratio = curr_avg / prev_avg
        recovery_ratio = next_avg / curr_avg

        if (
            spike_ratio > LATENCY_SPIKE_RATIO
            and recovery_ratio < LATENCY_RECOVERY_RATIO
            and next_avg <= prev_avg * LATENCY_RECOVERY_CEILING
        ):
            return valid[i]
    return None


def analyze_path(hops: List[Dict]) -> Dict:
    if not hops:
        logger.warning("analyze_path called with no hops data.")
        return {
            "status": "error",
            "message": "No hops data to analyze",
            "bottleneck": None,
        }

    try:
        valid_avgs = [hop["avg"] for hop in hops if hop.get("avg") is not None]
        valid_worsts = [hop["worst"] for hop in hops if hop.get("worst") is not None]

        analysis = {
            "total_hops": len(hops),
            "total_loss": sum(hop["loss"] for hop in hops) / len(hops),
            "average_latency": sum(valid_avgs) / len(valid_avgs) if valid_avgs else 0.0,
            "worst_latency": max(valid_worsts) if valid_worsts else 0.0,
            "status": "healthy",
            "bottleneck": None,
            "unresponsive_hop": None,
            "forwardloss_inherited": False,
            "likely_rate_limited": False,
            "elevated": False,
            "latency_spike_isolated": None,
            "suggestion": "",
        }

        chosen_bottleneck = None
        unresponsive_hop = None
        total_hops = len(hops)

        for i, current_hop in enumerate(hops):
            current_loss = current_hop.get("loss", 0.0)
            current_host = current_hop.get("host", "???")

            if current_loss > ELEVATED_LOSS_THRESHOLD:
                sustained_loss = False
                lookahead_valid_hops = 0

                for next_idx in range(i + 1, min(i + 4, total_hops)):
                    next_hop = hops[next_idx]
                    if next_hop.get("host") == "???":
                        continue

                    lookahead_valid_hops += 1
                    if next_hop.get("loss", 0.0) >= (current_loss * 0.5):
                        sustained_loss = True
                        break

                if current_host == "???":
                    if sustained_loss:
                        chosen_bottleneck = current_hop
                        break
                    if i == total_hops - 1:
                        unresponsive_hop = current_hop
                    continue

                chosen_bottleneck = current_hop
                break

        if chosen_bottleneck is None:
            if unresponsive_hop is not None:
                analysis["status"] = "unconfirmed_endpoint_loss"
                analysis["unresponsive_hop"] = {
                    "hop": unresponsive_hop["hop"],
                    "host": unresponsive_hop["host"],
                    "loss": unresponsive_hop["loss"],
                    "avg_latency": unresponsive_hop.get("avg"),
                }
            else:
                max_loss_hop = max(hops, key=lambda x: x.get("loss", 0.0))
                if max_loss_hop.get("host") != "???" and max_loss_hop.get("loss", 0.0) > 0.0:
                    chosen_bottleneck = max_loss_hop
                else:
                    analysis["status"] = "unconfirmed_intermediate_loss"

        if chosen_bottleneck is not None:
            analysis["bottleneck"] = {
                "hop": chosen_bottleneck["hop"],
                "host": chosen_bottleneck["host"],
                "loss": chosen_bottleneck["loss"],
                "avg_latency": chosen_bottleneck.get("avg"),
            }

        if analysis["bottleneck"] is None:
            spike_hop = _detect_isolated_latency_spike(hops)
            if spike_hop:
                analysis["latency_spike_isolated"] = {
                    "hop": spike_hop["hop"],
                    "host": spike_hop["host"],
                    "avg_latency": spike_hop["avg"],
                }
                logger.info(
                    f"Isolated (non-persisting) latency spike detected at hop {spike_hop['hop']} "
                    f"({spike_hop['host']}) -- likely ICMP control-plane de-prioritization, not a real forwarding delay."
                )
            analysis["suggestion"] = SUGGESTION_UNCONFIRMED_ENDPOINT if analysis["status"] == "unconfirmed_endpoint_loss" else SUGGESTION_HEALTHY
            return analysis

    except KeyError as e:
        logger.error(f"Malformed hop data: missing key {e}")
        return {
            "status": "error",
            "message": f"Malformed hop data: missing key {e}",
            "bottleneck": None,
        }

    bottleneck_idx = None
    for i, hop in enumerate(hops):
        if hop["hop"] == analysis["bottleneck"]["hop"]:
            bottleneck_idx = i
            break

    if bottleneck_idx is not None and bottleneck_idx < len(hops) - 1:
        downstream = [
            hop for hop in hops[bottleneck_idx + 1 :]
            if hop.get("host") != "???" and hop.get("loss") is not None
        ]
        loss_after_bottleneck = sum(1 for hop in downstream if hop["loss"] > ELEVATED_LOSS_THRESHOLD)
        total_hops_after = len(downstream)

        if total_hops_after > 0 and (loss_after_bottleneck / total_hops_after) > 0.5:
            analysis["forwardloss_inherited"] = True
            logger.info(f"Forward-loss inheritance at hop {analysis['bottleneck']['hop']}")

    final_hop = hops[-1]
    if analysis["bottleneck"]["loss"] > CRITICAL_LOSS_THRESHOLD and final_hop["loss"] < ELEVATED_LOSS_THRESHOLD:
        analysis["likely_rate_limited"] = True

    analysis["elevated"] = ELEVATED_LOSS_THRESHOLD < analysis["bottleneck"]["loss"] <= CRITICAL_LOSS_THRESHOLD

    spike_hop = _detect_isolated_latency_spike(hops)
    if spike_hop:
        analysis["latency_spike_isolated"] = {
            "hop": spike_hop["hop"],
            "host": spike_hop["host"],
            "avg_latency": spike_hop["avg"],
        }
        logger.info(
            f"Isolated (non-persisting) latency spike detected at hop {spike_hop['hop']} "
            f"({spike_hop['host']}) -- likely ICMP control-plane de-prioritization, not a real forwarding delay."
        )

    b_data = analysis["bottleneck"]
    if analysis["likely_rate_limited"]:
        analysis["status"] = "likely_rate_limited"
        analysis["suggestion"] = SUGGESTION_RATE_LIMITED.format(hop=b_data["hop"], host=b_data["host"])
        logger.info(f"Hop {b_data['hop']} rate-limited")
    elif b_data["loss"] > CRITICAL_LOSS_THRESHOLD and analysis["forwardloss_inherited"]:
        analysis["status"] = "confirmed_persistent_loss"
        analysis["suggestion"] = SUGGESTION_CRITICAL.format(hop=b_data["hop"], host=b_data["host"])
        logger.warning(f"Critical fault at hop {b_data['hop']}")
    elif b_data["loss"] > CRITICAL_LOSS_THRESHOLD:
        analysis["status"] = "unconfirmed_intermediate_loss"
        analysis["suggestion"] = SUGGESTION_UNSTABLE.format(hop=b_data["hop"], host=b_data["host"])
        logger.warning(f"Unstable hop {b_data['hop']}")
    elif analysis["elevated"]:
        analysis["status"] = "unconfirmed_intermediate_loss"
        analysis["suggestion"] = SUGGESTION_ELEVATED.format(loss=b_data["loss"], hop=b_data["hop"], host=b_data["host"])
        logger.info(f"Elevated loss at hop {b_data['hop']}")
    else:
        analysis["status"] = "healthy"
        analysis["suggestion"] = SUGGESTION_HEALTHY

    if spike_hop and spike_hop["hop"] == b_data["hop"]:
        analysis["suggestion"] += COSMETIC_LATENCY_NOTE.format(hop=spike_hop["hop"], host=spike_hop["host"])

    return analysis