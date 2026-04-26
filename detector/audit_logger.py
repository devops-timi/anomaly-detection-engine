import time
from datetime import datetime


class AuditLogger:
    """
    Writes structured log entries to a file for every significant event.
    
    Format required by the task spec:
    [timestamp] ACTION ip | condition | rate | baseline | duration
    
    Events logged:
    - BAN: when an IP is banned
    - UNBAN: when an IP is unbanned
    - BASELINE_RECALC: when baseline is recalculated
    """

    def __init__(self, config):
        self.log_path = config["audit_log_path"]

    def _write(self, line):
        """Append a line to the audit log file."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = f"[{timestamp}] {line}\n"
        
        try:
            # 'a' = append mode — never overwrites existing logs
            with open(self.log_path, "a") as f:
                f.write(entry)
                f.flush()   # ensure it's written to disk immediately
        except IOError as e:
            print(f"[AuditLogger] Could not write to {self.log_path}: {e}")

    def log_ban(self, ip, condition, rate, baseline, duration):
        """Log a ban event."""
        duration_str = str(duration) if duration != -1 else "permanent"
        line = (
            f"BAN {ip} | {condition} | "
            f"rate={rate:.2f} | "
            f"baseline_mean={baseline['mean']:.2f} stddev={baseline['stddev']:.2f} | "
            f"duration={duration_str}s"
        )
        self._write(line)

    def log_unban(self, ip, offense, duration):
        """Log an unban event."""
        line = f"UNBAN {ip} | offense={offense} | ban_was={duration}s"
        self._write(line)

    def log_baseline_recalc(self, mean, stddev, samples):
        """Log a baseline recalculation."""
        line = (
            f"BASELINE_RECALC | "
            f"effective_mean={mean:.4f} | "
            f"effective_stddev={stddev:.4f} | "
            f"samples={samples}"
        )
        self._write(line)