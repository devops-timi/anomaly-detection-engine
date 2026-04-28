"""
main.py - Entry point for the HNG anomaly detection daemon.
Wires all components together and runs the main detection loop.
"""

import yaml
import time
import sys
from datetime import datetime

from monitor import tail_log
from baseline import BaselineEngine
from detector import SlidingWindowDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import set_state, start_dashboard


class AuditLogger:
    def __init__(self, config):
        self.log_path = config["audit_log_path"]

    def _write(self, line):
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            with open(self.log_path, "a") as f:
                f.write(f"[{timestamp}] {line}\n")
                f.flush()
        except IOError as e:
            print(f"[AuditLogger] Cannot write: {e}")

    def log_ban(self, ip, condition, rate, baseline, duration):
        d = str(duration) if duration != -1 else "permanent"
        self._write(
            f"BAN {ip} | {condition} | rate={rate:.2f} | "
            f"baseline_mean={baseline['mean']:.2f} "
            f"stddev={baseline['stddev']:.2f} | duration={d}s"
        )

    def log_unban(self, ip, offense, duration):
        self._write(f"UNBAN {ip} | offense={offense} | ban_was={duration}s")

    def log_baseline_recalc(self, mean, stddev, samples):
        self._write(
            f"BASELINE_RECALC | effective_mean={mean:.4f} | "
            f"effective_stddev={stddev:.4f} | samples={samples}"
        )


class SharedState:
    def __init__(self, baseline_engine, detector, blocker):
        self.baseline_engine = baseline_engine
        self.detector = detector
        self.blocker = blocker
        self.start_time = time.time()
        self.total_requests = 0
        self.total_bans = 0


def load_config(path="config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main():
    print("=" * 60)
    print("  HNG Cloud.ng — Anomaly Detection Daemon Starting...")
    print("=" * 60)

    # Load config
    config = load_config()
    print(f"[Main] Log path: {config['log_path']}")

    # Create all components
    audit_logger = AuditLogger(config)
    baseline = BaselineEngine(config)
    detector = SlidingWindowDetector(config)
    blocker = Blocker(config)
    notifier = Notifier(config)

    # Pass detector into unbanner so it can clear banned_ips on unban
    unbanner = Unbanner(blocker, notifier, audit_logger, detector)

    # Set up shared state for dashboard
    state = SharedState(baseline, detector, blocker)
    set_state(state)

    # Start background threads
    unbanner.start()
    start_dashboard(
        host=config["dashboard_host"],
        port=config["dashboard_port"]
    )

    # Grace period - collect baseline before detecting
    startup_grace_period = 60
    startup_time = time.time()
    print(f"[Main] Grace period: {startup_grace_period}s")

    # Cooldown trackers - prevent Slack spam
    # { ip: last_alert_time }
    recent_alerts = {}
    alert_cooldown = 30         # seconds between alerts for same IP
    last_global_alert = 0
    global_alert_cooldown = 120  # seconds between global alerts

    # IPs that should never be banned
    WHITELISTED_IPS = {
        "127.0.0.1",
    }

    print("[Main] Starting main detection loop...")

    # Main loop - processes every nginx log line
    for log_entry in tail_log(config["log_path"]):

        ip = log_entry["source_ip"]
        status = log_entry["status"]
        path = log_entry["path"]

        # Count every request for dashboard
        state.total_requests += 1

        # Always record in sliding window for rate detection
        detector.record(ip, status)

        # Only feed into baseline if:
        # 1. IP is not currently banned (not attack traffic)
        # 2. Not a whitelisted internal IP
        if not blocker.is_banned(ip) and ip not in WHITELISTED_IPS:
            baseline.record_request(ip, status)

        # Maybe recalculate baseline every 60 seconds
        if baseline.maybe_recalculate():
            b = baseline.get_baseline()
            samples = len(baseline.global_samples)
            audit_logger.log_baseline_recalc(
                b["mean"], b["stddev"], samples
            )
            print(
                f"[Main] Baseline recalculated: "
                f"mean={b['mean']:.4f} "
                f"stddev={b['stddev']:.4f} "
                f"samples={samples}"
            )

        # Skip anomaly detection during grace period
        if time.time() - startup_time < startup_grace_period:
            continue

        # Get current baseline
        b = baseline.get_baseline()

        # ── Per-IP anomaly check ──────────────────────────────────
        is_anomaly, reason, rate = detector.check_ip_anomaly(ip, b)

        if is_anomaly and not blocker.is_banned(ip) and ip not in WHITELISTED_IPS:
            last_alert = recent_alerts.get(ip, 0)
            if time.time() - last_alert > alert_cooldown:
                recent_alerts[ip] = time.time()

                # Ban via iptables
                duration = blocker.ban_ip(ip)

                if duration is not None:
                    state.total_bans += 1

                    # Mark as banned in detector
                    detector.banned_ips.add(ip)

                    # Send Slack ban alert
                    notifier.send_ban(ip, reason, rate, b, duration)

                    # Write audit log
                    audit_logger.log_ban(ip, reason, rate, b, duration)

                    print(
                        f"[Main] ANOMALY DETECTED — IP {ip} | "
                        f"{reason} | rate={rate:.2f} | "
                        f"BANNED for {duration}s"
                    )

        # ── Global anomaly check ──────────────────────────────────
        global_anomaly, global_reason, global_rate = \
            detector.check_global_anomaly(b)

        if global_anomaly:
            if time.time() - last_global_alert > global_alert_cooldown:
                last_global_alert = time.time()
                notifier.send_global_alert(global_reason, global_rate, b)
                print(
                    f"[Main] GLOBAL ANOMALY — "
                    f"{global_reason} | rate={global_rate:.2f}"
                )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[Main] Shutting down.")
        sys.exit(0)