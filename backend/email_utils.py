"""
email_utils.py — PacketPulse email sending utility.

Reads SMTP config from environment variables:
    SMTP_HOST      e.g. smtp.gmail.com
    SMTP_PORT      e.g. 587
    SMTP_USER      sender address
    SMTP_PASSWORD  app password / SMTP password
    SMTP_FROM      display from address (optional, defaults to SMTP_USER)
    APP_BASE_URL   e.g. http://localhost:3000 (used in link generation)

If SMTP_HOST is not set, emails are printed to the console (dev mode).
"""

import os
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText

log = logging.getLogger("email_utils")

SMTP_HOST    = os.getenv("SMTP_HOST",    "")
SMTP_PORT    = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER    = os.getenv("SMTP_USER",    "")
SMTP_PASS    = os.getenv("SMTP_PASSWORD","")
SMTP_FROM    = os.getenv("SMTP_FROM",    SMTP_USER) or "noreply@packetpulse.local"
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:3000")


def _send(to_addr: str, subject: str, html_body: str, text_body: str):
    """
    Send an email. Falls back to console logging if SMTP is not configured.
    """
    if not SMTP_HOST:
        # Dev mode — print to console so dev can test without real SMTP
        log.info("──── [DEV EMAIL] ────────────────────────────────")
        log.info("To:      %s", to_addr)
        log.info("Subject: %s", subject)
        log.info("Body:\n%s", text_body)
        log.info("─────────────────────────────────────────────────")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"PacketPulse <{SMTP_FROM}>"
    msg["To"]      = to_addr

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, to_addr, msg.as_string())
        log.info("Email sent to %s: %s", to_addr, subject)
    except Exception as e:
        log.error("Failed to send email to %s: %s", to_addr, e)
        raise


def send_verification_email(to_addr: str, display_name: str, token: str):
    link = f"{APP_BASE_URL}/verify-email.html?token={token}"

    text = f"""Hi {display_name},

Welcome to PacketPulse! Please verify your email address by visiting:

{link}

This link expires in 24 hours.

If you did not create an account, you can ignore this email.

— PacketPulse
"""

    html = f"""<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;max-width:480px;margin:40px auto;color:#1e293b">
  <h2 style="color:#2563eb">Verify your email</h2>
  <p>Hi <strong>{display_name}</strong>,</p>
  <p>Welcome to PacketPulse! Click the button below to verify your email address.</p>
  <p style="margin:28px 0">
    <a href="{link}"
       style="background:#2563eb;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">
      Verify Email
    </a>
  </p>
  <p style="color:#64748b;font-size:0.875rem">This link expires in 24 hours.<br>
  If you didn't create an account, you can safely ignore this email.</p>
  <hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
  <p style="color:#94a3b8;font-size:0.75rem">PacketPulse Network Scanner</p>
</body>
</html>"""

    _send(to_addr, "Verify your PacketPulse email", html, text)


def send_password_reset_email(to_addr: str, display_name: str, token: str):
    link = f"{APP_BASE_URL}/reset-password.html?token={token}"

    text = f"""Hi {display_name},

We received a request to reset your PacketPulse password.

Click the link below to set a new password:

{link}

This link expires in 1 hour. If you did not request a password reset, you can ignore this email — your password has not been changed.

— PacketPulse
"""

    html = f"""<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;max-width:480px;margin:40px auto;color:#1e293b">
  <h2 style="color:#2563eb">Reset your password</h2>
  <p>Hi <strong>{display_name}</strong>,</p>
  <p>We received a request to reset your PacketPulse password. Click the button below to choose a new one.</p>
  <p style="margin:28px 0">
    <a href="{link}"
       style="background:#2563eb;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">
      Reset Password
    </a>
  </p>
  <p style="color:#64748b;font-size:0.875rem">This link expires in 1 hour.<br>
  If you didn't request this, your account is safe — just ignore this email.</p>
  <hr style="border:none;border-top:1px solid #e2e8f0;margin:24px 0">
  <p style="color:#94a3b8;font-size:0.75rem">PacketPulse Network Scanner</p>
</body>
</html>"""

    _send(to_addr, "Reset your PacketPulse password", html, text)