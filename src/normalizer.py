"""
Normalizer — 메시지 관련성 판단 + Field Extractor 적용.

- should_skip(): 명백한 비관련 메시지만 제거 (보수적)
- process_message(): 필터링 → 필드 추출 → HackSignal 반환
- skip된 메시지는 logs/skipped.log에 누적 (유저 피드백용)
"""
import re
import logging
from pathlib import Path

from src.models import HackSignal
from src.config import ChannelConfig
from src.extractors.field_extractor import extract_all

# ── Skip 로거 설정 (파일 누적) ──
_LOG_DIR = Path(__file__).parent.parent / "logs"
_LOG_DIR.mkdir(exist_ok=True)

_skip_logger = logging.getLogger("skip_log")
_skip_logger.setLevel(logging.INFO)

if not _skip_logger.handlers:
    _handler = logging.FileHandler(
        _LOG_DIR / "skipped.log",
        mode="a",  # append — 하나의 파일에 누적
        encoding="utf-8",
    )
    _handler.setFormatter(
        logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    _skip_logger.addHandler(_handler)


# ── 해킹 관련 키워드 (confidence 부스트용) ──
HACK_KEYWORDS = [
    "hack", "hacked", "exploit", "exploited", "drained",
    "compromised", "vulnerability", "attack", "attacked",
    "stolen", "flash loan", "reentrancy", "rugpull", "rug pull",
    "suspicious", "malicious", "phishing",
    "security incident", "security breach", "security alert",
    "funds at risk", "emergency", "incident",
    "front-run", "frontrun", "sandwich",
    "oracle manipulation", "price manipulation",
]


def has_hack_keyword(text: str) -> bool:
    """해킹 관련 키워드가 포함되어 있는지"""
    text_lower = text.lower()
    return any(kw in text_lower for kw in HACK_KEYWORDS)


def should_skip(text: str) -> tuple[bool, str]:
    """
    이 메시지를 무시해야 하는지 판단.

    보수적 필터링: 놓치는 것보다 오탐이 낫다.
    보안 전문 채널이므로 기본적으로 "관련"으로 간주하고,
    명백한 비관련만 제거.

    Returns: (should_skip, reason)
    """
    if not text or not text.strip():
        return True, "empty"

    stripped = text.strip()

    # 너무 짧은 메시지 (10자 미만)
    if len(stripped) < 10:
        return True, f"too_short({len(stripped)})"

    # 봇 명령어
    if stripped.startswith("/"):
        return True, "bot_command"

    # 순수 이모지/특수문자만 (알파벳/숫자 없음)
    if not re.search(r"[a-zA-Z0-9]", stripped):
        return True, "no_alphanumeric"

    # 나머지는 전부 통과 (보안 채널이므로)
    return False, ""


def process_message(
    message,
    channel: ChannelConfig,
    store=None,
) -> HackSignal | None:
    """
    메시지 → 필터링 → 필드 추출 → HackSignal 반환.

    skip된 경우 None 반환 + skipped.log + Supabase 기록.
    store가 주어지면 lumos_skipped_messages에도 저장.
    """
    text = message.text or ""

    # 1. 관련성 필터링
    skip, reason = should_skip(text)
    if skip:
        _skip_logger.info(
            f"SKIP [{reason}] | {channel.name} | "
            f"msg_id={message.id} | {text[:80]!r}"
        )
        if store:
            store.log_skip(
                reason=reason,
                source="telegram",
                channel_name=channel.name,
                channel_id=channel.chat_id,
                message_id=message.id,
                raw_text=text,
            )
        return None

    # 2. HackSignal 생성 (메타데이터 수집)
    signal = HackSignal.from_telegram(
        message=message,
        channel_name=channel.name,
        channel_tier=channel.tier,
        chat_id=channel.chat_id,
    )

    # 3. Field Extractor로 optional 필드 채우기
    extracted = extract_all(signal.raw_text)
    signal.protocol_name = extracted["protocol_name"]
    signal.chain = extracted["chain"]
    signal.loss_usd = extracted["loss_usd"]
    signal.tx_hash = extracted["tx_hash"]
    signal.attacker_address = extracted["attacker_address"]

    return signal
