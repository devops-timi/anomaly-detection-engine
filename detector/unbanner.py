import time
import threading


class Unbanner:
    """
    Runs as a background thread.
    Every 30 seconds, checks all active bans.
    If a ban has exceeded its duration, it lifts the ban.
    
    The backoff schedule: 10min → 30min → 2hr → permanent
    Each new ban for the same IP uses the next duration in the list.
    """

    def __init__(self, blocker, notifier, audit_logger):
        self.blocker = blocker           # the Blocker that manages iptables
        self.notifier = notifier         # the Notifier for Slack messages
        self.audit_logger = audit_logger # the AuditLogger for structured logs
        self.running = False
        self._thread = None

    def start(self):
        """Start the unbanner as a background daemon thread."""
        self.running = True
        # daemon=True means this thread dies when the main program exits
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        print("[Unbanner] Started background unban thread.")

    def stop(self):
        """Signal the thread to stop."""
        self.running = False

    def _run(self):
        """Main loop — checks bans every 30 seconds."""
        while self.running:
            self._check_bans()
            time.sleep(30)   # check every 30 seconds

    def _check_bans(self):
        """
        Look at every active ban. If it has expired, unban the IP.
        'Expired' means: current time > banned_at + duration
        Permanent bans (duration == -1) are never auto-unbanned.
        """
        now = time.time()
        bans = self.blocker.get_active_bans()

        for ip, ban_info in bans.items():
            duration = ban_info["duration"]
            banned_at = ban_info["banned_at"]
            offense = ban_info["offense"]

            # Skip permanent bans
            if duration == -1:
                continue

            # Check if this ban has expired
            if now >= banned_at + duration:
                # Unban!
                self.blocker.unban_ip(ip)

                # Send Slack notification
                self.notifier.send_unban(
                    ip=ip,
                    offense=offense,
                    ban_duration=duration
                )

                # Write audit log entry
                self.audit_logger.log_unban(
                    ip=ip,
                    offense=offense,
                    duration=duration
                )

                print(f"[Unbanner] Auto-unbanned {ip} after {duration}s ban.")