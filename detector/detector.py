import time
import math
from collections import deque, defaultdict


class SlidingWindowDetector:
    """
    Detects anomalies using two deque-based sliding windows:
    
    1. Per-IP window: tracks requests from each individual IP in the last 60s
    2. Global window: tracks ALL requests combined in the last 60s
    
    How deque eviction works:
    - Each entry in the deque is a timestamp (float)
    - When we want the "rate", we remove all timestamps older than 60 seconds
    - Whatever is left in the deque = requests in the last 60 seconds
    - Dividing by 60 gives requests-per-second
    
    This is O(1) amortized — very efficient.
    """

    def __init__(self, config):
        self.window_seconds = config["window_seconds"]        # 60 seconds
        self.zscore_threshold = config["zscore_threshold"]    # 3.0
        self.rate_multiplier = config["rate_multiplier"]      # 5.0
        self.error_rate_multiplier = config["error_rate_multiplier"]  # 3.0

        # ── Per-IP windows ────────────────────────────────────────────────
        # { ip: deque([timestamp1, timestamp2, ...]) }
        # Each timestamp = one request from that IP
        self.ip_windows = defaultdict(deque)

        # Per-IP error tracking (4xx/5xx)
        # { ip: deque([timestamp1, ...]) }
        self.ip_error_windows = defaultdict(deque)

        # ── Global window ─────────────────────────────────────────────────
        # One big deque with a timestamp for every request from any IP
        self.global_window = deque()

        # Track which IPs are currently banned (so we don't double-ban)
        # { ip: True }
        self.banned_ips = set()

    def record(self, ip, status):
        """
        Record an incoming request. Called for every log line.
        Adds a timestamp to both the per-IP and global deques.
        """
        now = time.time()
        self.ip_windows[ip].append(now)
        self.global_window.append(now)

        # Also track if this was an error response
        if status >= 400:
            self.ip_error_windows[ip].append(now)

    def _evict_old(self, dq, now, window):
        """
        Remove timestamps older than `window` seconds from the left of the deque.
        
        Deques are ordered (oldest on left, newest on right).
        We pop from the left until the leftmost entry is within our window.
        This is the eviction logic — it's what makes it a "sliding" window.
        """
        cutoff = now - window   # anything before this timestamp is too old
        while dq and dq[0] < cutoff:
            dq.popleft()   # pop from left = remove oldest entry

    def get_ip_rate(self, ip):
        """
        Returns the current request rate for an IP (requests per second).
        First evicts old timestamps, then counts what remains.
        """
        now = time.time()
        dq = self.ip_windows[ip]
        self._evict_old(dq, now, self.window_seconds)
        # len(dq) = number of requests in the last 60 seconds
        return len(dq) / self.window_seconds

    def get_global_rate(self):
        """Returns the current global request rate (requests per second)."""
        now = time.time()
        self._evict_old(self.global_window, now, self.window_seconds)
        return len(self.global_window) / self.window_seconds

    def get_ip_error_rate(self, ip):
        """Returns the error rate (errors per second) for an IP."""
        now = time.time()
        dq = self.ip_error_windows[ip]
        self._evict_old(dq, now, self.window_seconds)
        return len(dq) / self.window_seconds

    def check_ip_anomaly(self, ip, baseline):
        """
        Check if a specific IP is behaving anomalously.
        
        Two conditions (whichever fires first):
        1. Z-score > 3.0 — statistically unusual compared to baseline
        2. Rate > 5x baseline mean — absolute multiplier check
        
        Also: if IP has high error rate, tighten the thresholds.
        
        Returns (is_anomaly: bool, reason: str, rate: float)
        """
        if ip in self.banned_ips:
            return False, "", 0   # already banned, don't re-trigger

        rate = self.get_ip_rate(ip)
        mean = baseline["mean"]
        stddev = baseline["stddev"]

        # ── Check for error surge (tighten thresholds) ────────────────────
        error_rate = self.get_ip_error_rate(ip)
        error_mean = baseline["error_mean"]
        
        # If this IP's error rate is 3x the baseline error rate,
        # we use tighter thresholds (zscore 2.0 instead of 3.0, multiplier 3x instead of 5x)
        if error_mean > 0 and error_rate >= self.error_rate_multiplier * error_mean:
            effective_zscore_threshold = self.zscore_threshold * 0.67   # ~2.0
            effective_rate_multiplier = self.rate_multiplier * 0.6       # 3.0
            tightened = True
        else:
            effective_zscore_threshold = self.zscore_threshold
            effective_rate_multiplier = self.rate_multiplier
            tightened = False

        # ── Z-score check ─────────────────────────────────────────────────
        # Z-score = how many standard deviations above the mean is this rate?
        # If stddev is 0 (perfectly flat baseline), z-score is 0
        if stddev > 0:
            zscore = (rate - mean) / stddev
        else:
            zscore = 0

        if zscore > effective_zscore_threshold:
            suffix = " [tightened thresholds]" if tightened else ""
            reason = f"z-score {zscore:.2f} > {effective_zscore_threshold:.2f}{suffix}"
            return True, reason, rate

        # ── Rate multiplier check ─────────────────────────────────────────
        if rate > effective_rate_multiplier * mean:
            suffix = " [tightened thresholds]" if tightened else ""
            reason = f"rate {rate:.2f} > {effective_rate_multiplier}x mean {mean:.2f}{suffix}"
            return True, reason, rate

        return False, "", rate

    def check_global_anomaly(self, baseline):
        """
        Check if TOTAL traffic (all IPs combined) is anomalous.
        Same logic but uses the global window.
        
        Returns (is_anomaly: bool, reason: str, rate: float)
        """
        rate = self.get_global_rate()
        mean = baseline["mean"]
        stddev = baseline["stddev"]

        if stddev > 0:
            zscore = (rate - mean) / stddev
        else:
            zscore = 0

        if zscore > self.zscore_threshold:
            reason = f"GLOBAL z-score {zscore:.2f} > {self.zscore_threshold}"
            return True, reason, rate

        if rate > self.rate_multiplier * mean:
            reason = f"GLOBAL rate {rate:.2f} > {self.rate_multiplier}x mean {mean:.2f}"
            return True, reason, rate

        return False, "", rate

    def get_top_ips(self, n=10):
        """
        Return the top N IPs by current request rate.
        Used by the dashboard.
        """
        now = time.time()
        ip_rates = []
        for ip, dq in self.ip_windows.items():
            self._evict_old(dq, now, self.window_seconds)
            rate = len(dq) / self.window_seconds
            ip_rates.append((ip, rate))
        # Sort by rate descending, return top N
        ip_rates.sort(key=lambda x: x[1], reverse=True)
        return ip_rates[:n]