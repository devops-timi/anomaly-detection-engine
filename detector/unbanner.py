"""
unbanner.py - Automatically lifts bans on a backoff schedule.
Runs as a background thread checking every 30 seconds.
"""

import time
import threading


class Unbanner:
    def __init__(self, blocker, notifier, audit_logger, detector):
        self.blocker = blocker
        self.notifier = notifier
        self.audit_logger = audit_logger
        self.detector = detector  # needed to clear banned_ips set
        self.running = False
        self._thread = None

    def start(self):
        self.running = True
        self._thread = threading.Thread(
            target=self._run, daemon=True
        )
        self._thread.start()
        print("[Unbanner] Started.")

    def stop(self):
        self.running = False

    def _run(self):
        while self.running:
            self._check_bans()
            time.sleep(30)

    def _check_bans(self):
        now = time.time()
        # Get copy of active bans to iterate safely
        bans = self.blocker.get_active_bans()

        for ip, ban_info in bans.items():
            duration = ban_info["duration"]
            banned_at = ban_info["banned_at"]
            offense = ban_info["offense"]

            # Never auto-unban permanent bans
            if duration == -1:
                continue

            # Check if ban has expired
            if now >= banned_at + duration:
                # Remove iptables rule
                self.blocker.unban_ip(ip)

                # Remove from detector's banned set
                # So the IP can be detected again if it reoffends
                self.detector.banned_ips.discard(ip)

                # Send Slack unban notification
                self.notifier.send_unban(
                    ip=ip,
                    offense=offense,
                    ban_duration=duration
                )

                # Write audit log
                self.audit_logger.log_unban(
                    ip=ip,
                    offense=offense,
                    duration=duration
                )

                print(f"[Unbanner] Auto-unbanned {ip} after {duration}s")