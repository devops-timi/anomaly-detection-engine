import time
import math
from collections import deque, defaultdict

class BaselineEngine:
    """
    Tracks traffic rates over time and computes a rolling baseline.
    
    How it works:
    - Every second, we record how many requests came in (a "sample")
    - We keep the last 30 minutes of these per-second samples
    - Every 60 seconds, we recalculate mean and stddev from those samples
    - We also track per-hour slots so current-hour data gets priority
    
    The baseline tells the detector: "this is what normal looks like right now"
    """

    def __init__(self, config):
        # How many seconds of history to keep (30 min × 60 sec = 1800 samples)
        self.window_seconds = config["baseline_window_minutes"] * 60

        # How often to recalculate (in seconds)
        self.recalc_interval = config["baseline_recalc_interval"]

        # Minimum number of samples before we trust the baseline
        self.min_samples = config["baseline_min_samples"]

        # Floor values prevent division by zero and false positives at very low traffic
        self.floor_mean = config["baseline_floor_mean"]
        self.floor_stddev = config["baseline_floor_stddev"]

        # ── Per-second global request count samples ──────────────────────
        # deque with maxlen automatically drops oldest entries when full
        # Each entry is (timestamp, count) — one per second
        self.global_samples = deque(maxlen=self.window_seconds)

        # ── Per-IP per-second samples ─────────────────────────────────────
        # { ip: deque([(timestamp, count), ...]) }
        self.ip_samples = defaultdict(lambda: deque(maxlen=self.window_seconds))

        # ── Per-hour slots ────────────────────────────────────────────────
        # { hour_key: [list of per-second counts] }
        # hour_key is like "2024-01-15-14" (YYYY-MM-DD-HH)
        self.hourly_slots = defaultdict(list)

        # Current computed baseline values
        self.effective_mean = self.floor_mean
        self.effective_stddev = self.floor_stddev
        self.effective_error_mean = 0.0     # baseline error rate
        self.effective_error_stddev = 0.0

        # Timestamps for periodic recalculation
        self.last_recalc_time = time.time()
        self.last_second_time = time.time()
        self.current_second_count = 0        # requests counted in current second
        self.current_second_errors = 0       # error responses in current second

        # Error rate samples (same structure as global_samples)
        self.error_samples = deque(maxlen=self.window_seconds)

        # For the dashboard: track recalculation history
        self.recalc_history = []   # list of (timestamp, mean, stddev)

    def record_request(self, ip, status):
        """
        Called for every incoming request.
        We count it into the current-second bucket.
        """
        now = time.time()

        # If we've moved into a new second, flush the old second's count
        if now - self.last_second_time >= 1.0:
            self._flush_second()
            self.last_second_time = now

        self.current_second_count += 1

        # Track errors separately (4xx and 5xx status codes)
        if status >= 400:
            self.current_second_errors += 1

    def _flush_second(self):
        """
        Save the completed second's request count to our samples deque.
        Also store in the current hour's slot.
        """
        now = time.time()
        count = self.current_second_count
        errors = self.current_second_errors

        # Save to rolling window (deque auto-drops oldest when full)
        self.global_samples.append((now, count))
        self.error_samples.append((now, errors))

        # Save to hourly slot
        # Build a string key for the current hour: "YYYY-MM-DD-HH"
        import datetime
        hour_key = datetime.datetime.now().strftime("%Y-%m-%d-%H")
        self.hourly_slots[hour_key].append(count)

        # Keep only last 25 hours of hourly slots (to avoid unbounded memory)
        if len(self.hourly_slots) > 25:
            oldest_key = sorted(self.hourly_slots.keys())[0]
            del self.hourly_slots[oldest_key]

        # Reset counters for next second
        self.current_second_count = 0
        self.current_second_errors = 0

    def maybe_recalculate(self):
        """
        Called periodically. Recalculates mean/stddev if enough time has passed.
        Returns True if a recalculation happened (so caller can log it).
        """
        now = time.time()
        if now - self.last_recalc_time < self.recalc_interval:
            return False   # not time yet

        self.last_recalc_time = now
        self._recalculate()
        return True

    def _recalculate(self):
        """
        The core baseline computation.
        
        Strategy:
        1. Try using current hour's data if it has enough samples (preferred)
        2. Fall back to the full 30-minute rolling window
        3. Apply floor values so we never go below safe minimums
        """
        import datetime
        current_hour_key = datetime.datetime.now().strftime("%Y-%m-%d-%H")
        current_hour_data = self.hourly_slots.get(current_hour_key, [])

        # Prefer current hour's data if it has at least min_samples
        if len(current_hour_data) >= self.min_samples:
            samples = current_hour_data
        elif len(self.global_samples) >= self.min_samples:
            # Fall back to all rolling window data
            samples = [count for (_, count) in self.global_samples]
        else:
            # Not enough data yet — keep defaults
            return

        # ── Compute mean ─────────────────────────────────────────
        mean = sum(samples) / len(samples)

        # ── Compute standard deviation ────────────────────────────
        # stddev = sqrt( average of squared differences from the mean )
        variance = sum((x - mean) ** 2 for x in samples) / len(samples)
        stddev = math.sqrt(variance)

        # Apply floor values (never go below minimum)
        self.effective_mean = max(mean, self.floor_mean)
        self.effective_stddev = max(stddev, self.floor_stddev)

        # ── Error rate baseline ───────────────────────────────────
        error_vals = [count for (_, count) in self.error_samples]
        if error_vals:
            e_mean = sum(error_vals) / len(error_vals)
            e_var = sum((x - e_mean) ** 2 for x in error_vals) / len(error_vals)
            self.effective_error_mean = max(e_mean, 0.1)
            self.effective_error_stddev = max(math.sqrt(e_var), 0.1)

        # Record this recalculation for dashboard history
        self.recalc_history.append({
            "timestamp": time.time(),
            "mean": self.effective_mean,
            "stddev": self.effective_stddev,
            "samples": len(samples)
        })
        # Keep only last 100 recalculations
        if len(self.recalc_history) > 100:
            self.recalc_history.pop(0)

    def get_baseline(self):
        """Returns the current effective baseline values."""
        return {
            "mean": self.effective_mean,
            "stddev": self.effective_stddev,
            "error_mean": self.effective_error_mean,
            "error_stddev": self.effective_error_stddev,
        }