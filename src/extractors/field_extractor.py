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
    all_hex = re.findall(r"0x[a-fA-F0-9]+", text)
    addresses = []
    for h in all_hex:
        clean = h[:42]  # 0x + 40자만
        if len(clean) == 42 and len(h) != 66:  # 66자(tx_hash) 제외
            addresses.append(clean)
    return addresses


def extract_attacker_address(text: str) -> str | None:
    """공격자 주소 추출 — 첫 번째 매칭 주소 반환"""
    addrs = extract_addresses(text)
    return addrs[0] if addrs else None


def extract_loss_usd(text: str) -> float | None:
    """피해액(USD) 추출"""
    patterns = [
        (r"\$\s*([\d,.]+)\s*[Bb](?:illion)?", 1_000_000_000),
        (r"\$\s*([\d,.]+)\s*[Mm](?:illion)?", 1_000_000),
        (r"\$\s*([\d,.]+)\s*[Kk]", 1_000),
        (r"\$\s*([\d,.]+)", 1),
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
            if alias.lower() in text_lower:
                return proto["name"]
    return None


def extract_chain(text: str) -> str | None:
    """체인 키워드 매칭"""
    text_lower = text.lower()
    for chain, keywords in CHAIN_KEYWORDS.items():
        for kw in keywords:
            if kw in text_lower:
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
