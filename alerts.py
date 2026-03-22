"""
Alert System Module
Sends alerts when suspicious transfers are detected
"""

import logging
import os
from datetime import datetime

LOG_FILE = "logs/alerts.log"

# Setup alert logger
os.makedirs("logs", exist_ok=True)
alert_logger = logging.getLogger("AlertSystem")
alert_logger.setLevel(logging.WARNING)
handler = logging.FileHandler(LOG_FILE)
handler.setFormatter(logging.Formatter("%(asctime)s - ALERT - %(message)s"))
alert_logger.addHandler(handler)


def send_console_alert(reason, src_ip="Unknown", filename="Unknown"):
    """Print a visible alert to the console and log it"""
    border = "!" * 55
    msg = f"""
{border}
  ⚠️  SECURITY ALERT DETECTED
{border}
  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Source IP: {src_ip}
  File     : {filename}
  Reason   : {reason}
{border}
"""
    print(msg)
    alert_logger.warning(f"src={src_ip} | file={filename} | reason={reason}")


def send_email_alert(reason, src_ip="Unknown", filename="Unknown",
                     sender_email=None, receiver_email=None, password=None):
    """
    Send email alert (configure your Gmail credentials to use this)
    NOTE: Enable 'Less secure app access' or use App Password in Gmail
    """
    import smtplib

    if not all([sender_email, receiver_email, password]):
        print("[!] Email credentials not configured. Skipping email alert.")
        return

    subject = "⚠️ Secure Transfer System - Security Alert"
    body = f"""
Security Alert Triggered!

Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Source IP: {src_ip}
File     : {filename}
Reason   : {reason}

Please review the transfer logs immediately.
    """

    message = f"Subject: {subject}\n\n{body}"

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message)
        print(f"[✔] Email alert sent to {receiver_email}")
    except Exception as e:
        print(f"[✘] Failed to send email: {e}")


def view_alerts():
    """Display all logged alerts"""
    if not os.path.exists(LOG_FILE):
        print("\n[i] No alerts logged yet.")
        return

    print(f"\n{'='*60}")
    print("  🚨 ALERT HISTORY")
    print(f"{'='*60}")
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
        if not lines:
            print("  No alerts found.")
        for line in lines[-20:]:  # Show last 20 alerts
            print(" ", line.strip())
    print(f"{'='*60}\n")
