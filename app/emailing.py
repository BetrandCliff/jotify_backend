import asyncio
import logging
import smtplib
from email.message import EmailMessage

from fastapi import HTTPException

from .config import settings

logger = logging.getLogger(__name__)


def _send_email(to: str, subject: str, body: str) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = f"{settings.smtp_from_name} <{settings.smtp_from_email}>"
    message["To"] = to
    message.set_content(body)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
        if settings.smtp_use_tls:
            server.starttls()
        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password.get_secret_value())
        server.send_message(message)


async def send_code(to: str, code: str, purpose: str) -> bool:
    subject = "Verify your Planner email" if purpose == "verify" else "Reset your Planner password"
    body = (
        f"Your Planner {purpose} code is {code}.\n"
        "It expires in 30 minutes. If you did not request this, you can ignore this email."
    )
    if not settings.smtp_host or not settings.smtp_from_email:
        if not settings.is_production:
            logger.warning("SMTP is not configured; %s code for %s: %s", purpose, to, code)
            return True
        raise HTTPException(status_code=503, detail="Email delivery is not configured.")
    try:
        await asyncio.to_thread(_send_email, to, subject, body)
    except (OSError, smtplib.SMTPException) as exc:
        logger.exception("Could not send %s email", purpose)
        raise HTTPException(status_code=503, detail="Could not send email. Try again later.") from exc
    return False