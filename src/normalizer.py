"""
Normalizer — 메시지 관련성 판단 + Field Extractor 적용 + LLM 보강.

파이프라인: should_skip() → tweet URL resolve → regex 추출 → LLM 분류 → merge
- should_skip(): 명백한 비관련 메시지만 제거 (보수적)
- process_message(): 필터링 → URL resolve → 정규식 → LLM → HackSignal 반환
- skip된 메시지는 logs/skipped.log에 누적 (유저 피드백용)
"""
import re
import logging
from pathlib import Path

from src.models import HackSignal
from src.config import ChannelConfig
from src.extractors.field_extractor import extract_all
from src.extractors.tweet_resolver import resolve_tweet_urls, append_resolved_to_text
from src.classifiers.gemini_classifier import (
    GeminiClassifier,
    merge_results,
    should_veto_signal,
)

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

# ── Gemini 분류기 (싱글톤) ──
_classifier: GeminiClassifier | None = None


def _get_classifier() -> GeminiClassifier:
    """GeminiClassifier 싱글톤."""
    global _classifier
    if _classifier is None:
        _classifier = GeminiClassifier()
    return _classifier


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


async def process_message(
    message,
    channel: ChannelConfig,
    store=None,
) -> HackSignal | None:
    """
    메시지 → 필터링 → URL resolve → 정규식 → LLM → HackSignal 반환.

    파이프라인:
    1. should_skip: 명백한 비관련 제거
    2. tweet URL resolve: fxtwitter로 참조 트윗 내용 가져와서 raw_text에 append
    3. extract_all (regex): 빠르고 무료 — 기본 메타데이터 추출
    4. GeminiClassifier: LLM으로 is_hack 판정 + 놓친 필드 보강
    5. merge: regex 결과 + LLM 결과 합치기

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

    # 2. Tweet URL resolve — 참조 트윗 내용을 raw_text에 append
    try:
        resolved = await resolve_tweet_urls(text)
        text = append_resolved_to_text(text, resolved)
    except Exception as e:
        logging.getLogger(__name__).warning(f"Tweet resolve failed: {e}")

    # 3. HackSignal 생성 (기본 메타데이터)
    signal = HackSignal.from_telegram(
        message=message,
        channel_name=channel.name,
        channel_tier=channel.tier,
        chat_id=channel.chat_id,
    )
    # resolve된 텍스트로 raw_text 업데이트
    signal.raw_text = text

    # 4. 정규식 추출 (1차 — 빠르고 무료)
    regex_fields = extract_all(text)

    # 5. LLM 분류 (2차 — 보강)
    classifier = _get_classifier()
    llm_result = None
    if classifier.available:
        try:
            llm_result = await classifier.classify(text)
        except Exception as e:
            logging.getLogger(__name__).warning(f"LLM classify failed: {e}")

    veto, veto_reason = should_veto_signal(llm_result, regex_fields, text)
    if veto:
        _skip_logger.info(
            f"SKIP [{veto_reason}] | {channel.name} | "
            f"msg_id={message.id} | {text[:80]!r}"
        )
        if store:
            store.log_skip(
                reason=veto_reason,
                source="telegram",
                channel_name=channel.name,
                channel_id=channel.chat_id,
                message_id=message.id,
                raw_text=text,
            )
        return None

    # 6. Merge: regex + LLM
    merged = merge_results(regex_fields, llm_result)

    # 결과 적용 (regex)
    signal.protocol_name = merged.get("protocol_name")
    signal.chain = merged.get("chain")
    signal.loss_usd = merged.get("loss_usd")
    signal.tx_hash = merged.get("tx_hash")
    signal.attacker_address = merged.get("attacker_address")

    # LLM 분류 결과 적용
    signal.llm_is_hack = merged.get("llm_is_hack")
    signal.llm_confidence = merged.get("llm_confidence")
    signal.llm_category = merged.get("llm_category")
    signal.llm_summary = merged.get("llm_summary")

    return signal
