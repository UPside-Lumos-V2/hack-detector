"""
Telegram Bot 알림 발송 — httpx로 Telegram Bot API 직접 호출.

hack-detector 서버에서 직접 발송 (Vercel serverless 안 거침).
"""
import os
import logging

import httpx

logger = logging.getLogger(__name__)

_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
_CHAT_ID = os.getenv("TELEGRAM_ALERT_CHAT_ID")
_API_BASE = "https://api.telegram.org"
_TIMEOUT = 10
_MAX_MESSAGE_LENGTH = 4096


async def send_alert(text: str, chat_id: str | None = None) -> bool:
    """
    Telegram Bot API로 메시지 발송.

    Args:
        text: 보낼 메시지 (plain text, 최대 4096자)
        chat_id: 대상 채팅 ID (기본: TELEGRAM_ALERT_CHAT_ID)

    Returns:
        True if sent successfully
    """
    token = _BOT_TOKEN
    target = chat_id or _CHAT_ID

    if not token or not target:
        logger.warning("Telegram notifier disabled: missing BOT_TOKEN or CHAT_ID")
        return False

    if len(text) > _MAX_MESSAGE_LENGTH:
        logger.warning(
            "Telegram alert truncated: "
            f"original_length={len(text)} max_length={_MAX_MESSAGE_LENGTH} "
            f"truncated_chars={len(text) - _MAX_MESSAGE_LENGTH}"
        )

    url = f"{_API_BASE}/bot{token}/sendMessage"
    payload = {
        "chat_id": target,
        "text": text[:_MAX_MESSAGE_LENGTH],
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(url, json=payload)

        if resp.status_code == 200:
            logger.info(f"Telegram alert sent to {target}")
            return True
        else:
            logger.warning(f"Telegram send failed: {resp.status_code} {resp.text[:200]}")
            return False

    except Exception as e:
        logger.warning(f"Telegram send error: {e}")
        return False


async def send_hack_alert(
    protocol: str,
    loss: str,
    chain: str | None,
    source_count: int,
    confidence: int,
    group_id: str,
    tx_hash: str | None = None,
) -> bool:
    """포맷된 해킹 알림 발송."""
    lines = [
        f"<b>HACK {protocol} — {loss} lost</b>",
        "",
    ]
    if chain:
        lines.append(f"Chain: {chain}")
    if tx_hash:
        lines.append(f"Tx: <code>{tx_hash[:20]}...</code>")
    lines.append(f"Sources: {source_count}")
    lines.append(f"Confidence: {confidence}")
    lines.append(f"Group: <code>{group_id[:8]}</code>")

    return await send_alert("\n".join(lines))
