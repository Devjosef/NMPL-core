from collections import deque
from concurrent.futures import ThreadPoolExecutor
import json
import logging
from statistics import mean, stdev
import time
from urllib.error import URLError
from urllib.request import Request, urlopen
from .probes import icmp_probe, udp_probe

logger = logging.getLogger("nmpl.diagnostics")

DEVIATION_MULTIPLIER = 2.5
MIN_DEVIATION_FLOOR = 0.08
UDP_FILTERED_THRESHOLD = 0.5
ICMP_ABSOLUTE_CEILING = 0.5


class Detector:
    def __init__(self, baseline_window=30, recent_window=10, webhook_url=None):
        self.baseline_window = baseline_window
        self.recent_window = recent_window
        self.webhook_url = webhook_url
        self._webhook_executor = (
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="nmpl-webhook")
            if webhook_url else None
        )
        self._state = "OK"
        self._target = None

        self.start_time = time.time()
        self.icmp_successes = 0
        self.udp_successes = 0
        self.icmp_failures = 0
        self.udp_failures = 0

        self.icmp_loss_history = deque(maxlen=baseline_window)
        self.udp_loss_history = deque(maxlen=baseline_window)
        self.icmp_rate_limit_history = deque(maxlen=recent_window)
        self.latency_history = deque(maxlen=recent_window)  # ms, successful + parseable probes only

        self.currently_alerting = False
        self.udp_state = "normal"

        self.icmp_baseline = None
        self.udp_baseline = None
        self.icmp_std = None
        self.udp_std = None

    def probe(self, target):
        self._target = target
        icmp_small_ok, icmp_small_latency = icmp_probe(target, 64)
        icmp_large_ok, icmp_large_latency = icmp_probe(target, 512)

        icmp_success = int(icmp_small_ok and icmp_large_ok)
        self.icmp_successes += icmp_success
        self.icmp_failures += (1 - icmp_success)
        self.icmp_loss_history.append(1 - icmp_success)

        if icmp_success and icmp_small_latency is not None and icmp_large_latency is not None:
            self.latency_history.append((icmp_small_latency + icmp_large_latency) / 2.0)

        udp_ok = udp_probe(target)
        self.udp_successes += int(udp_ok)
        self.udp_failures += int(not udp_ok)
        self.udp_loss_history.append(int(not udp_ok))

        is_icmp_limited = 1 if (icmp_success == 0 and udp_ok) else 0
        self.icmp_rate_limit_history.append(is_icmp_limited)

        return ((1 - icmp_success) + int(not udp_ok)) / 2.0

    def status(self) -> str:
        total_probes = (self.icmp_successes + self.icmp_failures +
                        self.udp_successes + self.udp_failures)

        if len(self.icmp_loss_history) < self.baseline_window:
            return f"Learning... ICMP:{len(self.icmp_loss_history)}/{self.baseline_window}"

        if not self.currently_alerting:
            self.icmp_baseline = mean(self.icmp_loss_history)
            self.udp_baseline = mean(self.udp_loss_history)
            self.icmp_std = stdev(self.icmp_loss_history) if len(self.icmp_loss_history) > 1 else 0.0
            self.udp_std = stdev(self.udp_loss_history) if len(self.udp_loss_history) > 1 else 0.0

            if self.udp_baseline > UDP_FILTERED_THRESHOLD:
                self.udp_state = "unreachable" if self.icmp_baseline > UDP_FILTERED_THRESHOLD else "filtered"
            else:
                self.udp_state = "normal"

        icmp_recent = mean(list(self.icmp_loss_history)[-self.recent_window:])
        udp_recent = mean(list(self.udp_loss_history)[-self.recent_window:])

        icmp_rate_limited_now = (len(self.icmp_rate_limit_history) >= 5 and
                                 mean(self.icmp_rate_limit_history) > 0.6)

        icmp_threshold = self.icmp_baseline + max(DEVIATION_MULTIPLIER * self.icmp_std, MIN_DEVIATION_FLOOR)
        icmp_deviation_alert = icmp_recent > icmp_threshold and not icmp_rate_limited_now

        icmp_ceiling_alert = icmp_recent > ICMP_ABSOLUTE_CEILING and not icmp_rate_limited_now

        icmp_alert = icmp_deviation_alert or icmp_ceiling_alert

        udp_threshold = self.udp_baseline + max(DEVIATION_MULTIPLIER * self.udp_std, MIN_DEVIATION_FLOOR)
        udp_alert = (self.udp_state == "normal") and (udp_recent > udp_threshold)

        if icmp_alert and udp_alert:
            confidence = "confirmed"
        elif icmp_alert:
            confidence = "suspected"
        else:
            confidence = None

        self.currently_alerting = (confidence is not None)
        state = "CRITICAL" if confidence == "confirmed" else (
            "DEGRADED" if confidence == "suspected" else "OK"
        )
        if state != self._state:
            self._state = state
            if state != "OK":
                self._dispatch_webhook(state, confidence, icmp_recent, udp_recent)

        udp_note = ""
        if self.udp_state == "filtered":
            udp_note = " [UDP filtered]"
        elif self.udp_state == "unreachable":
            udp_note = " [target unreachable]"

        if self.currently_alerting:
            reason = " (absolute ceiling)" if icmp_ceiling_alert and not icmp_deviation_alert else ""
            return (f"ALERT [{confidence.upper()}]{reason} "
                    f"ICMP: {icmp_recent*100:.1f}% (base {self.icmp_baseline*100:.1f}%) "
                    f"UDP: {udp_recent*100:.1f}% (base {self.udp_baseline*100:.1f}%){udp_note} "
                    f"S:{self.icmp_successes+self.udp_successes}/{total_probes}")

        rate_limit_note = " [ICMP rate-limited]" if icmp_rate_limited_now else ""
        return (f"OK ICMP: {icmp_recent*100:.1f}% (base {self.icmp_baseline*100:.1f}%){rate_limit_note} "
                f"UDP: {udp_recent*100:.1f}% (base {self.udp_baseline*100:.1f}%){udp_note}")

    def _dispatch_webhook(self, state, confidence, icmp_loss, udp_loss):
        if self._webhook_executor is None:
            return
        payload = {
            "target": self._target,
            "state": state,
            "confidence": confidence,
            "timestamp": time.time(),
            "metrics": {
                "icmp_loss_pct": icmp_loss * 100.0,
                "udp_loss_pct": udp_loss * 100.0,
            },
        }
        self._webhook_executor.submit(self._deliver_webhook, payload)

    def _deliver_webhook(self, payload):
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            self.webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        for attempt in range(3):
            error_message = None
            try:
                with urlopen(request, timeout=5) as response:
                    if 200 <= response.status < 300:
                        return
                    error_message = f"HTTP {response.status}"
            except (URLError, TimeoutError, OSError, ValueError) as error:
                error_message = str(error)

            if attempt < 2:
                time.sleep(0.5 * (2 ** attempt))
            else:
                logger.error(
                    "Webhook delivery failed after 3 attempts for target %s: %s",
                    payload["target"],
                    error_message,
                )

    @property
    def is_alert(self) -> bool:
        return self.currently_alerting

    @property
    def baseline_established(self) -> bool:
        return self.icmp_baseline is not None

    def current_loss_pct(self) -> float:
        if not self.baseline_established:
            if not self.icmp_loss_history:
                return 0.0
            return mean(self.icmp_loss_history) * 100.0
        return mean(list(self.icmp_loss_history)[-self.recent_window:]) * 100.0

    def current_latency_ms(self) -> float:
        return mean(self.latency_history) if self.latency_history else 0.0

    def current_jitter_ms(self) -> float:
        return stdev(self.latency_history) if len(self.latency_history) > 1 else 0.0

    def get_stats(self) -> dict:
        return {
            "is_alerting": self.currently_alerting,
            "icmp": {
                "successes": self.icmp_successes,
                "failures": self.icmp_failures,
                "baseline": self.icmp_baseline,
                "std_dev": self.icmp_std
            },
            "udp": {
                "successes": self.udp_successes,
                "failures": self.udp_failures,
                "baseline": self.udp_baseline,
                "std_dev": self.udp_std,
                "state": self.udp_state
            }
        }