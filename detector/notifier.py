import requests
import json
import time
from datetime import datetime


class Notifier:
    """
    Sends formatted messages to Slack via Incoming Webhooks.
    
    Each alert includes:
    - What condition fired (z-score, multiplier, etc.)
    - Current rate vs baseline
    - Timestamp
    - Ban duration (if applicable)
    """

    def __init__(self, config):
        # The Slack webhook URL from config.yaml
        self.webhook_url = config["slack_webhook_url"]

    def _send(self, text):
        """
        Send a message to Slack.
        Slack webhooks accept a simple JSON payload with a "text" field.
        """
        if "YOUR/WEBHOOK" in self.webhook_url:
            # Webhook not configured — just print to console
            print(f"[Notifier] SLACK (not configured): {text}")
            return

        try:
            payload = {"text": text}
            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=10   # don't hang on Slack API issues
            )
            if response.status_code != 200:
                print(f"[Notifier] Slack error: {response.status_code} {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"[Notifier] Slack request failed: {e}")

    def send_ban(self, ip, reason, rate, baseline, duration):
        """
        Send a Slack alert when an IP is banned.
        
        duration: seconds (int) or -1 for permanent
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        if duration == -1:
            duration_str = "PERMANENT"
        else:
            # Convert seconds to human-readable
            if duration >= 3600:
                duration_str = f"{duration // 3600}h"
            elif duration >= 60:
                duration_str = f"{duration // 60}m"
            else:
                duration_str = f"{duration}s"

        message = (
            f"🚨 *IP BANNED* — `{ip}`\n"
            f"*Condition:* {reason}\n"
            f"*Current Rate:* {rate:.2f} req/s\n"
            f"*Baseline Mean:* {baseline['mean']:.2f} req/s\n"
            f"*Baseline Stddev:* {baseline['stddev']:.2f}\n"
            f"*Ban Duration:* {duration_str}\n"
            f"*Time:* {timestamp}"
        )
        self._send(message)

    def send_unban(self, ip, offense, ban_duration):
        """Send a Slack alert when an IP is automatically unbanned."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        message = (
            f"✅ *IP UNBANNED* — `{ip}`\n"
            f"*Offense #:* {offense}\n"
            f"*Ban was:* {ban_duration}s\n"
            f"*Time:* {timestamp}"
        )
        self._send(message)

    def send_global_alert(self, reason, rate, baseline):
        """Send a Slack alert for a global traffic anomaly (no ban, just alert)."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        message = (
            f"⚠️ *GLOBAL TRAFFIC ANOMALY*\n"
            f"*Condition:* {reason}\n"
            f"*Current Global Rate:* {rate:.2f} req/s\n"
            f"*Baseline Mean:* {baseline['mean']:.2f} req/s\n"
            f"*Baseline Stddev:* {baseline['stddev']:.2f}\n"
            f"*Time:* {timestamp}"
        )
        self._send(message)