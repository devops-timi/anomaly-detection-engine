import subprocess
import time
import threading
from collections import defaultdict


class Blocker:
    """
    Manages iptables bans.
    
    When an IP is flagged as anomalous:
    1. Add an iptables DROP rule for that IP
    2. Record the ban time and offense count
    3. A separate unbanner thread will lift the ban later
    
    iptables DROP rule means: silently discard all packets from this IP.
    The IP gets no response — the connection just times out on their end.
    """

    def __init__(self, config):
        # Ban duration schedule in seconds: 10min, 30min, 2hr, permanent
        self.ban_durations = config["ban_durations"]

        # Track current bans: { ip: { "banned_at": float, "offense": int, "duration": int } }
        self.active_bans = {}

        # Track how many times each IP has been banned (for backoff schedule)
        # { ip: offense_count }
        self.offense_counts = defaultdict(int)

        # Thread lock — because multiple threads might call ban/unban simultaneously
        self.lock = threading.Lock()

    def ban_ip(self, ip):
        """
        Add an iptables DROP rule for this IP.
        Returns the ban duration in seconds, or -1 if permanent.
        """
        with self.lock:
            if ip in self.active_bans:
                return None   # already banned

            # Determine duration based on how many times this IP has been banned
            offense = self.offense_counts[ip]
            if offense < len(self.ban_durations):
                duration = self.ban_durations[offense]
            else:
                # More offenses than schedule entries → permanent
                duration = -1

            # Increment offense count for next time
            self.offense_counts[ip] += 1

            # ── Add iptables rule ─────────────────────────────────────────
            # iptables -I INPUT 1 = INSERT at position 1 (top of INPUT chain)
            # -s {ip}           = source IP to match
            # -j DROP           = action: drop the packet
            # We use -I (insert) not -A (append) so it takes priority over other rules
            try:
                result = subprocess.run(
                    ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                    capture_output=True,
                    text=True,
                    timeout=5   # don't hang if iptables is slow
                )
                if result.returncode != 0:
                    print(f"[Blocker] iptables ERROR: {result.stderr}")
                    return None
            except subprocess.TimeoutExpired:
                print(f"[Blocker] iptables timed out for IP {ip}")
                return None
            except FileNotFoundError:
                # iptables not installed — log and continue (for testing)
                print(f"[Blocker] WARNING: iptables not found. Simulating ban for {ip}")

            # Record the ban
            self.active_bans[ip] = {
                "banned_at": time.time(),
                "offense": offense + 1,
                "duration": duration
            }

            duration_str = f"{duration}s" if duration != -1 else "permanent"
            print(f"[Blocker] BANNED {ip} for {duration_str} (offense #{offense + 1})")
            return duration

    def unban_ip(self, ip):
        """
        Remove the iptables DROP rule for this IP.
        Returns the ban record for logging/notification.
        """
        with self.lock:
            if ip not in self.active_bans:
                return None

            ban_record = self.active_bans.pop(ip)

            # ── Remove iptables rule ──────────────────────────────────────
            # iptables -D = DELETE a rule matching these parameters
            try:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                print(f"[Blocker] WARNING: Could not remove iptables rule for {ip}")

            print(f"[Blocker] UNBANNED {ip}")
            return ban_record

    def get_active_bans(self):
        """Return a copy of all active bans (for the dashboard)."""
        with self.lock:
            return dict(self.active_bans)

    def is_banned(self, ip):
        """Check if an IP is currently banned."""
        with self.lock:
            return ip in self.active_bans