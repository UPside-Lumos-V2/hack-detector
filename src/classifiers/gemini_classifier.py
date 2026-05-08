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
import re
from dataclasses import dataclass

from src.extractors.field_extractor import normalize_chain_name, normalize_protocol_name

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
- is_hack: false for:
  - General news, educational content, tool announcements, job postings, market commentary
  - Post-incident communications: bounty negotiations, threat messages, fund return requests, white-hat offers
  - Onchain messages between parties (attacker <-> project team communications)
  - Fund recovery/tracking updates ("funds moved to mixer", "attacker bridged to X")
  - Security tool advertisements or monitoring service promotions
- is_new_incident: Determine if this is a NEWLY OCCURRING incident or a retrospective/historical analysis.
  - true: The post is reporting or alerting about a hack that is happening NOW or very recently (breaking news, real-time alerts, "just happened", urgent warnings).
  - false: The post is analyzing, reviewing, or educating about a PAST incident (case studies, post-mortems, "what happened in [date]", lessons learned).
  - IMPORTANT: The same protocol CAN be hacked multiple times. Do NOT assume a known protocol's incident is always old. Check the TONE and CONTEXT — is it breaking news or retrospective analysis?
- confidence: 0.0 to 1.0 indicating how certain you are
- Extract metadata ONLY if explicitly mentioned in the text
- For loss_usd, return the numeric value only (e.g., 5000000 for $5M)
- For tx_hash, return only valid 0x-prefixed hex strings (66 chars)
- For attacker_address, return only valid 0x-prefixed hex strings (42 chars)
- For summary, keep it under 160 characters. Be concise.

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

# 필수 필드 (repair된 JSON 검증용)
_REQUIRED_FIELDS = {"is_hack", "is_new_incident", "confidence", "category", "summary"}
_CATEGORIES = {"hack", "exploit", "rugpull", "phishing", "scam", "vulnerability", "other"}
_TX_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")
_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_MODEL_INPUT_LIMIT = 12000
_LLM_ENTITY_CONFIDENCE = 0.75
_LLM_UNKNOWN_PROTOCOL_CONFIDENCE = 0.85
_GENERIC_PROTOCOL_VALUES = {
    "unknown", "n/a", "na", "none", "null", "defi", "protocol", "project",
    "victim", "target", "attacker", "exploiter", "ethereum", "bsc", "bnb chain",
}


def build_classification_input(raw_text: str) -> str:
    text = raw_text.strip()
    if len(text) <= _MODEL_INPUT_LIMIT:
        return text

    head = text[:8000]
    tail = text[-3500:]
    omitted = len(text) - len(head) - len(tail)
    return f"{head}\n\n[... omitted {omitted} chars from middle ...]\n\n{tail}"


def has_deterministic_incident_evidence(regex_fields: dict, raw_text: str) -> bool:
    if regex_fields.get("tx_hash") or regex_fields.get("attacker_address") or regex_fields.get("loss_usd"):
        return True

    text_lower = raw_text.lower()
    strong_terms = (
        "exploited", "exploit", "hack", "hacked", "drained", "stolen",
        "security incident", "compromised", "vulnerability", "attack",
    )
    return any(term in text_lower for term in strong_terms)


def should_veto_signal(
    llm_result: ClassificationResult | None,
    regex_fields: dict,
    raw_text: str,
) -> tuple[bool, str]:
    if llm_result is None:
        return False, ""

    has_evidence = has_deterministic_incident_evidence(regex_fields, raw_text)
    high_confidence = llm_result.confidence >= 0.85

    if not llm_result.is_hack and high_confidence and not has_evidence:
        return True, f"llm_not_hack({llm_result.category})"
    if llm_result.is_hack and not llm_result.is_new_incident and high_confidence and not has_evidence:
        return True, "llm_retrospective"
    return False, ""


def _validated_optional_string(data: dict, key: str) -> str | None:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def _clean_llm_protocol_name(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = re.sub(r"\s+", " ", value.strip().strip("#@$:;,.()[]{}<>\"'"))
    if not cleaned or cleaned.lower() in _GENERIC_PROTOCOL_VALUES:
        return None
    if len(cleaned) > 80:
        return None
    if not re.search(r"[A-Za-z0-9]", cleaned):
        return None
    return cleaned


def _validate_model_output(data: dict) -> dict | None:
    if not isinstance(data.get("is_hack"), bool):
        return None
    if not isinstance(data.get("is_new_incident"), bool):
        return None

    confidence = data.get("confidence")
    if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        return None

    category = data.get("category")
    if category not in _CATEGORIES:
        return None

    summary = data.get("summary")
    if not isinstance(summary, str):
        return None

    cleaned = dict(data)
    cleaned["summary"] = summary.strip()[:240]

    tx_hash = _validated_optional_string(data, "tx_hash")
    cleaned["tx_hash"] = tx_hash if tx_hash and _TX_HASH_RE.match(tx_hash) else None

    attacker = _validated_optional_string(data, "attacker_address")
    cleaned["attacker_address"] = attacker if attacker and _ADDRESS_RE.match(attacker) else None

    loss = data.get("loss_usd")
    cleaned["loss_usd"] = loss if isinstance(loss, (int, float)) and loss > 0 else None
    cleaned["protocol_name"] = _validated_optional_string(data, "protocol_name")
    cleaned["chain"] = _validated_optional_string(data, "chain")

    return cleaned


class GeminiClassifier:
    """Gemini Flash 기반 DeFi 해킹 분류기"""

    MODEL = "gemini-3-flash-preview"

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

    @staticmethod
    def _repair_json(raw: str) -> dict | None:
        """잘린 JSON 복구 시도 → 필수 필드 검증까지 통과해야 반환."""
        # 1차: 그대로 파싱
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # 2차: 닫히지 않은 문자열/객체 보정
            repaired = raw.rstrip()
            if repaired.count('"') % 2 != 0:
                repaired += '"'
            open_braces = repaired.count('{') - repaired.count('}')
            repaired += '}' * max(open_braces, 0)
            try:
                data = json.loads(repaired)
            except json.JSONDecodeError:
                return None

        # 필수 필드 검증: 하나라도 빠지면 repair 실패로 처리
        if not isinstance(data, dict):
            return None
        missing = _REQUIRED_FIELDS - set(data.keys())
        if missing:
            logger.warning(f"Gemini JSON missing required fields: {missing}")
            return None

        return _validate_model_output(data)

    def _call_model(self, raw_text: str) -> dict:
        """모델 호출 + JSON 파싱 + 검증. 실패 시 예외 발생."""
        from google.genai import types

        response = self._client.models.generate_content(
            model=self.MODEL,
            contents=build_classification_input(raw_text),
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT,
                response_mime_type="application/json",
                response_schema=_RESPONSE_SCHEMA,
                temperature=0.1,
                max_output_tokens=1024,
            ),
        )

        # response.text 비어있는 경우
        if not response.text:
            logger.warning(f"Gemini empty response (finish_reason={getattr(response, 'finish_reason', 'unknown')})")
            raise ValueError("empty response")

        raw = response.text.strip()

        # JSON repair + 필수 필드 검증
        data = self._repair_json(raw)
        if data is not None:
            return data

        # repair/검증 실패 → 원본 로깅
        logger.warning(f"Gemini raw response (unparseable): {raw[:300]}")
        raise json.JSONDecodeError("repair failed", raw, 0)

    async def classify(self, raw_text: str) -> ClassificationResult | None:
        """
        메시지를 분류하고 메타데이터를 추출.
        JSON 파싱 실패 시 1회 재시도. 최종 실패 시 None 반환.
        """
        if not self._available:
            return None

        max_attempts = 2
        for attempt in range(max_attempts):
            try:
                data = self._call_model(raw_text)

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
                if attempt < max_attempts - 1:
                    logger.warning(f"Gemini JSON parse error (retry {attempt+1}): {e}")
                    continue
                logger.warning(f"Gemini JSON parse error (final): {e}")
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

    # regex 결과가 없는 필드를 검증된 LLM 값으로 보충
    llm_confident = llm_result.confidence >= _LLM_ENTITY_CONFIDENCE and llm_result.is_hack
    if not merged.get("protocol_name") and llm_result.protocol_name and llm_confident:
        known_protocol = normalize_protocol_name(llm_result.protocol_name)
        if known_protocol:
            merged["protocol_name"] = known_protocol
        elif llm_result.confidence >= _LLM_UNKNOWN_PROTOCOL_CONFIDENCE:
            cleaned_protocol = _clean_llm_protocol_name(llm_result.protocol_name)
            if cleaned_protocol:
                merged["protocol_name"] = cleaned_protocol
    if not merged.get("chain") and llm_result.chain and llm_confident:
        merged["chain"] = normalize_chain_name(llm_result.chain)
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
