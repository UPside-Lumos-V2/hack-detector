"""
Gemini LLM Classifier — DeFi 해킹 신호 분류 + 메타데이터 추출.

정규식이 1차로 처리한 후, Gemini가 2차로 보강:
- is_hack 판정 (해킹/보안 사건 여부)
- 정규식이 놓친 메타데이터 추출
- 카테고리 분류 + 한줄 요약

API 실패 시 정규식 결과만으로 동작 (graceful degradation).
"""
import os
import json
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ClassificationResult:
    """Gemini 분류 결과"""
    is_hack: bool = False
    is_new_incident: bool = False     # 새로 발생한 사건인지 (과거 회고 vs 신규)
    confidence: float = 0.0
    category: str = "unknown"       # hack, exploit, rugpull, phishing, scam, other
    protocol_name: str | None = None
    chain: str | None = None
    loss_usd: float | None = None
    tx_hash: str | None = None
    attacker_address: str | None = None
    summary: str = ""
    raw_response: dict | None = None


_SYSTEM_PROMPT = """You are a DeFi security analyst. Classify the following message and extract metadata.

Rules:
- is_hack: true ONLY for actual security incidents (hacks, exploits, rugpulls, phishing attacks, fund drains)
- is_hack: false for general news, educational content, tool announcements, job postings, market commentary
- is_new_incident: Determine if this is a NEWLY OCCURRING incident or a retrospective/historical analysis.
  - true: The post is reporting or alerting about a hack that is happening NOW or very recently (breaking news, real-time alerts, "just happened", urgent warnings).
  - false: The post is analyzing, reviewing, or educating about a PAST incident (case studies, post-mortems, "what happened in [date]", lessons learned).
  - IMPORTANT: The same protocol CAN be hacked multiple times. Do NOT assume a known protocol's incident is always old. Check the TONE and CONTEXT — is it breaking news or retrospective analysis?
- confidence: 0.0 to 1.0 indicating how certain you are
- Extract metadata ONLY if explicitly mentioned in the text
- For loss_usd, return the numeric value only (e.g., 5000000 for $5M)
- For tx_hash, return only valid 0x-prefixed hex strings (66 chars)
- For attacker_address, return only valid 0x-prefixed hex strings (42 chars)

Respond with JSON only, no explanation."""

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "is_hack": {"type": "boolean"},
        "is_new_incident": {"type": "boolean"},
        "confidence": {"type": "number"},
        "category": {
            "type": "string",
            "enum": ["hack", "exploit", "rugpull", "phishing", "scam", "vulnerability", "other"],
        },
        "protocol_name": {"type": "string"},
        "chain": {"type": "string"},
        "loss_usd": {"type": "number"},
        "tx_hash": {"type": "string"},
        "attacker_address": {"type": "string"},
        "summary": {"type": "string"},
    },
    "required": ["is_hack", "is_new_incident", "confidence", "category", "summary"],
}


class GeminiClassifier:
    """Gemini 3 Flash 기반 DeFi 해킹 분류기"""

    MODEL = "gemini-3-flash-preview"
    FALLBACK_MODEL = "gemini-2.5-flash"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self._client = None
        self._available = False

        if not self.api_key:
            logger.warning("GEMINI_API_KEY not set — LLM classification disabled")
            return

        try:
            from google import genai
            self._client = genai.Client(api_key=self.api_key)
            self._available = True
            logger.info(f"Gemini classifier initialized (model={self.MODEL})")
        except ImportError:
            logger.warning("google-genai not installed — LLM classification disabled")
        except Exception as e:
            logger.warning(f"Gemini init failed: {e}")

    @property
    def available(self) -> bool:
        return self._available

    async def classify(self, raw_text: str) -> ClassificationResult | None:
        """
        메시지를 분류하고 메타데이터를 추출.
        실패 시 None 반환 (caller는 regex fallback 사용).
        """
        if not self._available:
            return None

        try:
            from google.genai import types

            response = self._client.models.generate_content(
                model=self.MODEL,
                contents=raw_text[:4000],  # 토큰 절약
                config=types.GenerateContentConfig(
                    system_instruction=_SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    response_schema=_RESPONSE_SCHEMA,
                    temperature=0.1,  # 일관된 분류
                    max_output_tokens=512,
                ),
            )

            text = response.text.strip()
            data = json.loads(text)

            return ClassificationResult(
                is_hack=data.get("is_hack", False),
                is_new_incident=data.get("is_new_incident", False),
                confidence=data.get("confidence", 0.0),
                category=data.get("category", "unknown"),
                protocol_name=data.get("protocol_name") or None,
                chain=data.get("chain") or None,
                loss_usd=data.get("loss_usd") or None,
                tx_hash=data.get("tx_hash") or None,
                attacker_address=data.get("attacker_address") or None,
                summary=data.get("summary", ""),
                raw_response=data,
            )

        except json.JSONDecodeError as e:
            logger.warning(f"Gemini JSON parse error: {e}")
            return None
        except Exception as e:
            logger.warning(f"Gemini classify failed: {e}")
            return None


def merge_results(
    regex_fields: dict,
    llm_result: ClassificationResult | None,
) -> dict:
    """
    정규식 결과와 LLM 결과를 merge.

    전략:
    - tx_hash, loss_usd, attacker_address: regex 우선 (정확한 패턴 매칭)
    - protocol_name, chain: regex가 있으면 유지, 없으면 LLM
    - is_hack, category, summary: LLM 우선 (판단이 필요한 필드)
    - LLM 결과가 없으면 regex만 사용 (현재와 동일)
    """
    merged = dict(regex_fields)

    if llm_result is None:
        # LLM 실패 — regex만 사용 (기존과 동일)
        merged["llm_is_hack"] = None
        merged["llm_confidence"] = None
        merged["llm_category"] = None
        merged["llm_summary"] = None
        return merged

    # regex 결과가 없는 필드를 LLM으로 보충
    if not merged.get("protocol_name") and llm_result.protocol_name:
        merged["protocol_name"] = llm_result.protocol_name
    if not merged.get("chain") and llm_result.chain:
        merged["chain"] = llm_result.chain
    if not merged.get("loss_usd") and llm_result.loss_usd:
        merged["loss_usd"] = llm_result.loss_usd
    if not merged.get("tx_hash") and llm_result.tx_hash:
        merged["tx_hash"] = llm_result.tx_hash
    if not merged.get("attacker_address") and llm_result.attacker_address:
        merged["attacker_address"] = llm_result.attacker_address

    # LLM 전용 필드
    merged["llm_is_hack"] = llm_result.is_hack
    merged["llm_is_new_incident"] = llm_result.is_new_incident
    merged["llm_confidence"] = llm_result.confidence
    merged["llm_category"] = llm_result.category
    merged["llm_summary"] = llm_result.summary

    return merged
