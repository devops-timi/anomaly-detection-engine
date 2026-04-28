"""
baseline.py - Learns normal traffic patterns over time.
Uses a 30-minute rolling window of per-second request counts.
Spike guard prevents attack traffic from corrupting the baseline.
"""

import time
import math
import datetime
from collections import deque, defaultdict


class BaselineEngine:
    def __init__(self, config):
        # 30 minutes x 60 seconds = 1800 samples max
        self.window_seconds = config["baseline_window_minutes"] * 60
        self.recalc_interval = config["baseline_recalc_interval"]
        self.min_samples = config["baseline_min_samples"]
        self.floor_mean = config["baseline_floor_mean"]
        self.floor_stddev = config["baseline_floor_stddev"]

        # Rolling window of (timestamp, count) per second
        self.global_samples = deque(maxlen=self.window_seconds)
        self.error_samples = deque(maxlen=self.window_seconds)

        # Per-hour slots for preferred current-hour baseline
        self.hourly_slots = defaultdict(list)

        # Current baseline values - start at floor
        self.effective_mean = self.floor_mean
        self.effective_stddev = self.floor_stddev
        self.effective_error_mean = 0.1
        self.effective_error_stddev = 0.1

        # Per-second counters
        self.current_second_count = 0
        self.current_second_errors = 0
        self.last_second_time = time.time()

        # Recalculation timer
        self.last_recalc_time = time.time()

        # History for dashboard
        self.recalc_history = []

    def record_request(self, ip, status):
        """Record one request into the current-second bucket."""
        now = time.time()

        # If we moved into a new second, flush the old second
        if now - self.last_second_time >= 1.0:
            self._flush_second()
            self.last_second_time = now

        self.current_second_count += 1
        if status >= 400:
            self.current_second_errors += 1

    def _flush_second(self):
        """
        Save current second's count into rolling window.
        Spike guard: if count is more than 10x current mean,
        discard it — it is almost certainly attack traffic.
        """
        count = self.current_second_count
        errors = self.current_second_errors
        now = time.time()

        # Spike guard — only active after enough samples
        if len(self.global_samples) >= self.min_samples:
            if count > 10 * self.effective_mean:
                print(
                    f"[Baseline] Spike guard: {count} req/s > "
                    f"10x mean {self.effective_mean:.2f} — discarded"
                )
                self.current_second_count = 0
                self.current_second_errors = 0
                return

        # Save to rolling window
        self.global_samples.append((now, count))
        self.error_samples.append((now, errors))

        # Save to hourly slot
        hour_key = datetime.datetime.now().strftime("%Y-%m-%d-%H")
        self.hourly_slots[hour_key].append(count)

        # Keep only last 25 hours
        if len(self.hourly_slots) > 25:
            oldest = sorted(self.hourly_slots.keys())[0]
            del self.hourly_slots[oldest]

        # Reset counters
        self.current_second_count = 0
        self.current_second_errors = 0

    def maybe_recalculate(self):
        """Recalculate baseline if enough time has passed."""
        now = time.time()
        if now - self.last_recalc_time < self.recalc_interval:
            return False
        self.last_recalc_time = now
        self._recalculate()
        return True

    def _recalculate(self):
        """Compute mean and stddev from rolling window."""
        hour_key = datetime.datetime.now().strftime("%Y-%m-%d-%H")
        current_hour = self.hourly_slots.get(hour_key, [])

        # Prefer current hour if enough data
        if len(current_hour) >= self.min_samples:
            samples = current_hour
        elif len(self.global_samples) >= self.min_samples:
            samples = [c for (_, c) in self.global_samples]
        else:
            return  # not enough data yet

        mean = sum(samples) / len(samples)
        variance = sum((x - mean) ** 2 for x in samples) / len(samples)
        stddev = math.sqrt(variance)

        self.effective_mean = max(mean, self.floor_mean)
        self.effective_stddev = max(stddev, self.floor_stddev)

        # Error baseline
        error_vals = [c for (_, c) in self.error_samples]
        if error_vals:
            e_mean = sum(error_vals) / len(error_vals)
            e_var = sum((x - e_mean) ** 2 for x in error_vals) / len(error_vals)
            self.effective_error_mean = max(e_mean, 0.1)
            self.effective_error_stddev = max(math.sqrt(e_var), 0.1)

        # Save history for dashboard
        self.recalc_history.append({
            "timestamp": time.time(),
            "mean": self.effective_mean,
            "stddev": self.effective_stddev,
            "samples": len(samples)
        })
        if len(self.recalc_history) > 100:
            self.recalc_history.pop(0)

    def get_baseline(self):
        return {
            "mean": self.effective_mean,
            "stddev": self.effective_stddev,
            "error_mean": self.effective_error_mean,
            "error_stddev": self.effective_error_stddev,
        }