"""
main.py — Entry point for the HNG anomaly detection daemon.

This file:
1. Loads config
2. Creates all components (monitor, baseline, detector, blocker, unbanner, notifier, logger)
3. Starts background threads (unbanner, dashboard)
4. Runs the main loop: read log → record → check anomalies → respond
"""

import yaml
import time
import sys
import os

# Import all our modules
from monitor import tail_log
from baseline import BaselineEngine
from detector import SlidingWindowDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import set_state, start_dashboard

# We need the audit logger — import it
sys.path.insert(0, os.path.dirname(__file__))
# Create audit_logger.py in same folder (we include it here inline for clarity)


class AuditLogger:
    """Write structured audit log entries."""
    def __init__(self, config):
        self.log_path = config["audit_log_path"]

    def _write(self, line):
        from datetime import datetime
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = f"[{timestamp}] {line}\n"
        try:
            with open(self.log_path, "a") as f:
                f.write(entry)
                f.flush()
        except IOError as e:
            print(f"[AuditLogger] Cannot write: {e}")

    def log_ban(self, ip, condition, rate, baseline, duration):
        d = str(duration) if duration != -1 else "permanent"
        self._write(f"BAN {ip} | {condition} | rate={rate:.2f} | "
                    f"baseline_mean={baseline['mean']:.2f} stddev={baseline['stddev']:.2f} | duration={d}s")

    def log_unban(self, ip, offense, duration):
        self._write(f"UNBAN {ip} | offense={offense} | ban_was={duration}s")

    def log_baseline_recalc(self, mean, stddev, samples):
        self._write(f"BASELINE_RECALC | effective_mean={mean:.4f} | "
                    f"effective_stddev={stddev:.4f} | samples={samples}")


class SharedState:
    """
    A simple container that holds all shared state.
    The dashboard reads from this; the main loop writes to it.
    """
    def __init__(self, baseline_engine, detector, blocker):
        self.baseline_engine = baseline_engine
        self.detector = detector
        self.blocker = blocker
        self.start_time = time.time()
        self.total_requests = 0
        self.total_bans = 0


def load_config(path="config.yaml"):
    """Load YAML config file."""
    with open(path, "r") as f:
        return yaml.safe_load(f)


def main():
    print("=" * 60)
    print("  HNG Cloud.ng — Anomaly Detection Daemon")
    print("  Starting up...")
    print("=" * 60)

    # ── Load config ───────────────────────────────────────────────
    config = load_config()
    print(f"[Main] Config loaded. Log path: {config['log_path']}")

    # ── Create components ─────────────────────────────────────────
    audit_logger = AuditLogger(config)
    baseline = BaselineEngine(config)
    detector = SlidingWindowDetector(config)
    blocker = Blocker(config)
    notifier = Notifier(config)
    unbanner = Unbanner(blocker, notifier, audit_logger)

    # ── Shared state for dashboard ────────────────────────────────
    state = SharedState(baseline, detector, blocker)
    set_state(state)

    # ── Start background threads ──────────────────────────────────
    unbanner.start()
    start_dashboard(
        host=config["dashboard_host"],
        port=config["dashboard_port"]
    )

    # Cooldown: don't trigger anomaly alerts for first 60 seconds
    # (let baseline gather some data first)
    startup_grace_period = 60
    startup_time = time.time()
    print(f"[Main] Grace period: {startup_grace_period}s before anomaly detection begins.")

    # Track which IPs we've recently alerted on (to avoid Slack spam)
    # { ip: last_alert_timestamp }
    recent_alerts = {}
    alert_cooldown = 30   # seconds between repeat alerts for the same IP
    global_alert_cooldown = 60
    last_global_alert = 0

    print("[Main] Starting log monitoring loop...")

    # ── MAIN LOOP ─────────────────────────────────────────────────
    # tail_log is a generator — it yields one parsed log entry at a time
    for log_entry in tail_log(config["log_path"]):

        ip = log_entry["source_ip"]
        status = log_entry["status"]

        # ── Count this request ────────────────────────────────────
        baseline.record_request(ip, status)
        detector.record(ip, status)
        state.total_requests += 1

        # ── Maybe recalculate baseline ────────────────────────────
        if baseline.maybe_recalculate():
            b = baseline.get_baseline()
            samples = len(baseline.global_samples)
            audit_logger.log_baseline_recalc(b["mean"], b["stddev"], samples)
            print(f"[Main] Baseline recalculated: mean={b['mean']:.4f} stddev={b['stddev']:.4f} samples={samples}")

        # ── Skip anomaly checks during grace period ───────────────
        if time.time() - startup_time < startup_grace_period:
            continue

        # Get current baseline
        b = baseline.get_baseline()

        # ── Check per-IP anomaly ──────────────────────────────────
        is_anomaly, reason, rate = detector.check_ip_anomaly(ip, b)

        if is_anomaly and not blocker.is_banned(ip):
            # Check alert cooldown (don't spam Slack)
            last_alert = recent_alerts.get(ip, 0)
            if time.time() - last_alert > alert_cooldown:
                recent_alerts[ip] = time.time()

                # Ban the IP via iptables
                duration = blocker.ban_ip(ip)

                if duration is not None:
                    state.total_bans += 1
                    detector.banned_ips.add(ip)   # tell detector to skip this IP

                    # Send Slack ban alert
                    notifier.send_ban(ip, reason, rate, b, duration)

                    # Write audit log
                    audit_logger.log_ban(ip, reason, rate, b, duration)

                    print(f"[Main] ANOMALY DETECTED — IP {ip} | {reason} | rate={rate:.2f} | BANNED for {duration}s")

        # ── Check global anomaly ──────────────────────────────────
        global_anomaly, global_reason, global_rate = detector.check_global_anomaly(b)

        if global_anomaly:
            # Global anomaly: Slack alert only, no IP ban
            if time.time() - last_global_alert > global_alert_cooldown:
                last_global_alert = time.time()
                notifier.send_global_alert(global_reason, global_rate, b)
                print(f"[Main] GLOBAL ANOMALY — {global_reason} | rate={global_rate:.2f}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[Main] Shutting down.")
        sys.exit(0)