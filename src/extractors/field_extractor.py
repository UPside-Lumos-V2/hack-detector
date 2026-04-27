"""
raw_text에서 해킹 관련 필드를 추출하는 정규식 기반 추출기.

역할: HackSignal의 optional 필드(protocol_name, chain, tx_hash 등)를 채운다.
Normalizer가 "관련 있음"으로 판단한 메시지에만 적용.
"""
import re
from pathlib import Path

import yaml

# ── 프로토콜 사전 로딩 (protocols.yaml) ──
_PROTOCOLS_FILE = Path(__file__).parent.parent.parent / "config" / "protocols.yaml"
_protocols_cache: list[dict] | None = None

_TOKEN_BEFORE = r"(?<![a-zA-Z0-9])"
_TOKEN_AFTER = r"(?![a-zA-Z0-9])"
_EVM_ADDRESS_RE = r"0x[a-fA-F0-9]{40}"

# 한 단어 alias 중 일반 문장에서도 자주 나오는 값은 단독 매칭하지 않는다.
_AMBIGUOUS_PROTOCOL_ALIASES = {
    "arb",
    "base",
    "curve",
    "dai",
    "level",
    "maker",
    "one",
    "op",
    "sentiment",
    "sol",
    "transit",
    "uni",
}

_ATTACKER_LABEL_RE = re.compile(
    rf"""
    (?:
        attacker(?:\s+address|\s+wallet)?|
        exploiter(?:\s+address|\s+wallet)?|
        hacker(?:\s+address|\s+wallet)?|
        drainer(?:\s+address|\s+wallet)?|
        malicious\s+(?:address|wallet)
    )
    [^\n\r]{{0,40}}?
    ({_EVM_ADDRESS_RE})
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _contains_token(text_lower: str, keyword: str) -> bool:
    """키워드를 토큰 경계 기준으로 매칭한다."""
    keyword_lower = keyword.lower()
    if keyword_lower.startswith(("#", "$")):
        return keyword_lower in text_lower
    pattern = _TOKEN_BEFORE + re.escape(keyword_lower) + _TOKEN_AFTER
    return re.search(pattern, text_lower) is not None


def _has_crypto_marker(text_lower: str, alias: str) -> bool:
    """짧고 모호한 alias가 실제 토큰/프로토콜 문맥인지 확인한다."""
    alias_lower = alias.lower()
    marked = (f"#{alias_lower}" in text_lower) or (f"${alias_lower}" in text_lower)
    contextual = re.search(
        _TOKEN_BEFORE + re.escape(alias_lower) + _TOKEN_AFTER
        + r".{0,24}\b(protocol|finance|network|dao|bridge|chain)\b",
        text_lower,
    )
    return marked or contextual is not None


def _load_protocols() -> list[dict]:
    """protocols.yaml에서 프로토콜 사전 로딩 (1회 캐싱)"""
    global _protocols_cache
    if _protocols_cache is not None:
        return _protocols_cache

    if not _PROTOCOLS_FILE.exists():
        _protocols_cache = []
        return _protocols_cache

    with open(_PROTOCOLS_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    _protocols_cache = data.get("protocols", [])
    return _protocols_cache


# ── 체인 사전 ──
CHAIN_KEYWORDS: dict[str, list[str]] = {
    "ethereum": ["ethereum", "eth mainnet", "on eth", "#ethereum"],
    "bsc": ["bsc", "binance smart chain", "bnb chain", "#bsc"],
    "arbitrum": ["arbitrum", "#arbitrum", "arb"],
    "polygon": ["polygon", "#polygon", "matic"],
    "optimism": ["optimism", "#optimism", "op mainnet"],
    "avalanche": ["avalanche", "avax", "#avalanche"],
    "base": ["base chain", "on base", "#base"],
    "solana": ["solana", "#solana", "sol"],
    "fantom": ["fantom", "#fantom", "ftm"],
    "zksync": ["zksync", "#zksync"],
}


def extract_tx_hash(text: str) -> str | None:
    """트랜잭션 해시 추출 (0x + 64자 hex)"""
    match = re.search(r"0x[a-fA-F0-9]{64}", text)
    return match.group(0) if match else None


def extract_addresses(text: str) -> list[str]:
    """이더리움 주소 추출 (0x + 40자 hex), tx_hash와 구분"""
    matches = re.findall(rf"{_EVM_ADDRESS_RE}(?![a-fA-F0-9])", text)
    return list(dict.fromkeys(matches))


def extract_attacker_address(text: str) -> str | None:
    """공격자 주소 추출 — attacker/exploiter 등 명시 라벨이 있을 때만 반환"""
    match = _ATTACKER_LABEL_RE.search(text)
    return match.group(1) if match else None


def extract_loss_usd(text: str) -> float | None:
    """피해액(USD) 추출"""
    patterns = [
        (r"\$\s*~?\s*([\d,.]+)\s*[Bb](?:illion)?", 1_000_000_000),
        (r"\$\s*~?\s*([\d,.]+)\s*[Mm](?:illion)?", 1_000_000),
        (r"\$\s*~?\s*([\d,.]+)\s*[Kk]", 1_000),
        (r"\$\s*~?\s*([\d,.]+)", 1),
        (r"([\d,.]+)\s*[Bb](?:illion)?\s*(?:USD|USDT|USDC)", 1_000_000_000),
        (r"([\d,.]+)\s*[Mm](?:illion)?\s*(?:USD|USDT|USDC)", 1_000_000),
        (r"([\d,.]+)\s*[Kk]\s*(?:USD|USDT|USDC)", 1_000),
        (r"([\d,.]+)\s*(?:million)\s*(?:USD|USDT|USDC)", 1_000_000),
    ]

    for pattern, multiplier in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            raw = match.group(1).replace(",", "")
            try:
                return float(raw) * multiplier
            except ValueError:
                continue
    return None


def extract_protocol_name(text: str) -> str | None:
    """protocols.yaml 사전 기반 프로토콜명 매칭 (aliases 포함)"""
    text_lower = text.lower()
    protocols = _load_protocols()

    for proto in protocols:
        for alias in proto.get("aliases", []):
            alias_lower = alias.lower()
            if alias_lower in _AMBIGUOUS_PROTOCOL_ALIASES:
                if _has_crypto_marker(text_lower, alias_lower):
                    return proto["name"]
                continue
            if _contains_token(text_lower, alias_lower):
                return proto["name"]
    return None


def extract_chain(text: str) -> str | None:
    """체인 키워드 매칭"""
    text_lower = text.lower()
    for chain, keywords in CHAIN_KEYWORDS.items():
        for kw in keywords:
            if _contains_token(text_lower, kw):
                return chain
    return None


def extract_all(text: str) -> dict:
    """모든 필드를 한번에 추출 — HackSignal에 적용할 dict 반환"""
    return {
        "tx_hash": extract_tx_hash(text),
        "attacker_address": extract_attacker_address(text),
        "loss_usd": extract_loss_usd(text),
        "protocol_name": extract_protocol_name(text),
        "chain": extract_chain(text),
    }
