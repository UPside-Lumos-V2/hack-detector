"""
raw_text에서 해킹 관련 필드를 추출하는 정규식 기반 추출기.

역할: HackSignal의 optional 필드(protocol_name, chain, tx_hash 등)를 채운다.
Normalizer가 "관련 있음"으로 판단한 메시지에만 적용.
"""
import re
from pathlib import Path
from typing import TypeAlias, cast

import yaml

# ── 프로토콜 사전 로딩 (protocols.yaml) ──
_PROTOCOLS_FILE = Path(__file__).parent.parent.parent / "config" / "protocols.yaml"
ProtocolEntry: TypeAlias = dict[str, object]
ExtractedFields: TypeAlias = dict[str, str | float | None]
_protocols_cache: list[ProtocolEntry] | None = None

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


def _load_protocols() -> list[ProtocolEntry]:
    """protocols.yaml에서 프로토콜 사전 로딩 (1회 캐싱)"""
    global _protocols_cache
    if _protocols_cache is not None:
        return _protocols_cache

    if not _PROTOCOLS_FILE.exists():
        _protocols_cache = []
        return _protocols_cache

    with open(_PROTOCOLS_FILE, "r", encoding="utf-8") as f:
        data = cast(object, yaml.safe_load(f))

    protocols: list[ProtocolEntry] = []
    if isinstance(data, dict):
        data_dict = cast(dict[object, object], data)
        raw_protocols = data_dict.get("protocols")
        if isinstance(raw_protocols, list):
            raw_items = cast(list[object], raw_protocols)
            protocols = [cast(ProtocolEntry, item) for item in raw_items if isinstance(item, dict)]

    _protocols_cache = protocols
    return _protocols_cache


# ── 모호한 체인 키워드 (일반 영어와 충돌) ──
# 이 키워드들은 단독으로 나오면 매칭하지 않고, 해시태그/문맥 마커가 있을 때만 매칭
_AMBIGUOUS_CHAIN_KEYWORDS = {
    "bitcoin", "btc",      # "Bitcoin Inheritance", "BTC rally"
    "near",                # "near the bridge"
    "ton",                 # "a ton of money"
    "icon",                # "icon of the project"
    "waves",               # "waves of attacks"
    "flow",                # "cash flow"
    "mina",                # 이름
    "ergo",                # 라틴어
    "core",                # "core team"
    "oasis",               # 일반명사
    "flare",               # "flare up"
    "theta",               # 그리스 문자
    "canto",               # 음악 용어
    "bob",                 # 이름
    "mode",                # 일반명사
    "lisk",                # 유사: "risk"
    "neo",                 # 접두사
    "wax",                 # 일반명사
    "stacks",              # "tech stacks"
    "fuse",                # 일반명사
    "boba",                # 음료
    "zora",                # 이름
    "terra",               # 라틴어
    "luna",                # 이름/천문
    "rune",                # 게임 용어
    "atom",                # 과학 용어
    "dot",                 # 일반명사
    "ada",                 # 이름
}

# ── 체인 사전 ──
# 카테고리: EVM L1 / EVM L2 / Non-EVM L1 / 앱체인·RWA
# 각 키워드는 보안 봇 메시지, 트윗 본문, 해시태그 형식 모두 커버
CHAIN_KEYWORDS: dict[str, list[str]] = {
    # ── EVM Layer 1 ──
    "ethereum": ["ethereum", "eth mainnet", "on eth", "#ethereum", "erc-20", "erc20"],
    "bsc": ["bsc", "binance smart chain", "bnb chain", "#bsc", "#bnbchain"],
    "avalanche": ["avalanche", "avax", "#avalanche", "c-chain"],
    "polygon": ["polygon", "#polygon", "matic", "polygon pos"],
    "fantom": ["fantom", "#fantom", "ftm", "sonic"],
    "cronos": ["cronos", "#cronos", "cro chain"],
    "gnosis": ["gnosis", "gnosis chain", "#gnosis", "xdai"],
    "celo": ["celo", "#celo"],
    "moonbeam": ["moonbeam", "#moonbeam", "glmr"],
    "moonriver": ["moonriver", "#moonriver", "movr"],
    "aurora": ["aurora chain", "#aurora", "aurora network"],
    "kava": ["kava", "#kava", "kava evm"],
    "harmony": ["harmony", "#harmony", "harmony one"],
    "klaytn": ["klaytn", "#klaytn", "klay", "kaia"],
    "metis": ["metis", "#metis", "metis andromeda"],
    "fuse": ["fuse network", "#fuse"],
    "boba": ["boba network", "#boba", "boba"],
    "evmos": ["evmos", "#evmos"],
    "canto": ["canto", "#canto"],
    "core": ["core chain", "core dao", "#coredao"],
    "pulsechain": ["pulsechain", "#pulsechain", "pls"],
    "flare": ["flare network", "#flare", "flare"],
    "telos": ["telos", "#telos", "telos evm"],
    "velas": ["velas", "#velas"],
    "oasis": ["oasis", "#oasis", "oasis sapphire", "oasis emerald"],
    "theta": ["theta", "#theta", "theta network"],
    "iotex": ["iotex", "#iotex"],
    "heco": ["heco", "#heco", "huobi eco"],
    "okc": ["okc", "okx chain", "okexchain", "#okc"],
    "berachain": ["berachain", "#berachain", "bera"],
    "monad": ["monad", "#monad"],

    # ── EVM Layer 2 / Rollup ──
    "arbitrum": ["arbitrum", "#arbitrum", "arbitrum one"],
    "optimism": ["optimism", "#optimism", "op mainnet"],
    "base": ["base chain", "on base", "#base"],
    "zksync": ["zksync", "#zksync", "zksync era"],
    "blast": ["blast", "#blast", "blast l2"],
    "linea": ["linea", "#linea"],
    "scroll": ["scroll", "#scroll"],
    "mantle": ["mantle", "#mantle"],
    "starknet": ["starknet", "#starknet"],
    "polygon_zkevm": ["polygon zkevm", "#polygonzkevm", "polygon hermez"],
    "manta": ["manta pacific", "#manta", "manta network"],
    "mode": ["mode network", "#mode"],
    "zora": ["zora", "#zora", "zora network"],
    "taiko": ["taiko", "#taiko"],
    "fraxtal": ["fraxtal", "#fraxtal"],
    "bob": ["bob chain", "#bob", "build on bitcoin"],
    "immutable_x": ["immutable x", "#immutablex", "imx"],
    "loopring": ["loopring", "#loopring", "lrc"],
    "world_chain": ["world chain", "#worldchain"],

    # ── Non-EVM Layer 1 ──
    "solana": ["solana", "#solana"],
    "tron": ["tron", "#tron", "trx", "trc-20", "trc20"],
    "ton": ["ton", "#ton", "the open network", "toncoin"],
    "bitcoin": ["bitcoin", "#bitcoin", "btc"],
    "near": ["near protocol", "#near"],
    "cosmos": ["cosmos", "#cosmos", "atom", "cosmos hub"],
    "cardano": ["cardano", "#cardano", "ada"],
    "algorand": ["algorand", "#algorand", "algo"],
    "sui": ["sui", "#sui", "sui network"],
    "aptos": ["aptos", "#aptos"],
    "sei": ["sei", "#sei", "sei network"],
    "injective": ["injective", "#injective", "inj"],
    "osmosis": ["osmosis", "#osmosis", "osmo"],
    "polkadot": ["polkadot", "#polkadot", "dot"],
    "kusama": ["kusama", "#kusama", "ksm"],
    "hedera": ["hedera", "#hedera", "hbar"],
    "stellar": ["stellar", "#stellar", "xlm"],
    "xrpl": ["xrpl", "#xrpl", "xrp ledger", "ripple"],
    "icp": ["internet computer", "#icp", "icp"],
    "flow": ["flow blockchain", "#flow"],
    "multiversx": ["multiversx", "#multiversx", "elrond", "egld"],
    "zilliqa": ["zilliqa", "#zilliqa", "zil"],
    "mina": ["mina protocol", "#mina", "mina"],
    "kaspa": ["kaspa", "#kaspa", "kas"],
    "eos": ["eos", "#eos"],
    "wax": ["wax blockchain", "#wax"],
    "stacks": ["stacks", "#stacks", "stx"],
    "filecoin": ["filecoin", "#filecoin", "fil"],
    "nervos": ["nervos", "#nervos", "ckb"],
    "ergo": ["ergo", "#ergo"],
    "radix": ["radix", "#radix", "xrd"],
    "tezos": ["tezos", "#tezos", "xtz"],
    "waves": ["waves", "#waves"],
    "neo": ["neo", "#neo"],
    "icon": ["icon", "#icon", "icx"],
    "astar": ["astar", "#astar"],
    "acala": ["acala", "#acala"],
    "bifrost": ["bifrost", "#bifrost"],
    "terra": ["terra", "#terra", "luna"],
    "thorchain": ["thorchain", "#thorchain", "rune"],
    "dymension": ["dymension", "#dymension", "dym"],
    "celestia": ["celestia", "#celestia", "tia"],

    # ── 앱체인 / Gaming / RWA ──
    "ronin": ["ronin", "#ronin", "ronin network"],
    "wemix": ["wemix", "#wemix"],
    "skale": ["skale", "#skale"],
    "lisk": ["lisk", "#lisk"],
    "shardeum": ["shardeum", "#shardeum"],
    "zetachain": ["zetachain", "#zetachain", "zeta"],
    "layerzero": ["layerzero", "#layerzero"],
    "wormhole": ["wormhole bridge", "#wormhole"],
    "axelar": ["axelar", "#axelar"],
    "hyperliquid": ["hyperliquid", "#hyperliquid"],
}

# ── "Network: X" 라벨 매핑 (보안 봇 알림 형식) ──
# 예: "🌎 Network: mainnet", "Network: BSC", "Chain: Arbitrum"
_NETWORK_LABEL_RE = re.compile(
    r"(?:network|chain)\s*:\s*([a-zA-Z][a-zA-Z0-9 ]*)",
    re.IGNORECASE,
)

# CHAIN_KEYWORDS에서 자동 생성 + 수동 alias 보강
_NETWORK_LABEL_MAP: dict[str, str] = {
    # 특수 alias (CHAIN_KEYWORDS에 없는 변형)
    "mainnet": "ethereum",
    "ethereum mainnet": "ethereum",
    "eth": "ethereum",
    "bnb": "bsc",
    "bnb chain": "bsc",
    "binance": "bsc",
    "arbitrum one": "arbitrum",
    "arb": "arbitrum",
    "matic": "polygon",
    "op mainnet": "optimism",
    "avax": "avalanche",
    "ftm": "fantom",
    "zksync era": "zksync",
    "sol": "solana",
    "trx": "tron",
    "hbar": "hedera",
    "xlm": "stellar",
    "ada": "cardano",
    "atom": "cosmos",
    "dot": "polkadot",
    "algo": "algorand",
    "inj": "injective",
    "luna": "terra",
    "rune": "thorchain",
    "xrp": "xrpl",
}
# CHAIN_KEYWORDS의 키를 자동으로 label map에 등록 (중복 무시)
for _chain_key in CHAIN_KEYWORDS:
    _label = _chain_key.replace("_", " ")
    if _label not in _NETWORK_LABEL_MAP:
        _NETWORK_LABEL_MAP[_label] = _chain_key


def _clean_entity_label(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().strip("#@$:;,.()[]{}<>\"'"))


def normalize_protocol_name(value: str | None) -> str | None:
    """LLM/외부 입력 프로토콜명을 protocols.yaml 기준 canonical name으로 정규화한다."""
    if not value:
        return None

    cleaned = _clean_entity_label(value)
    if not cleaned:
        return None

    cleaned_lower = cleaned.lower()
    protocols = _load_protocols()

    for proto in protocols:
        name = proto.get("name")
        if not isinstance(name, str):
            continue
        if cleaned_lower == name.lower():
            return name

        aliases = proto.get("aliases")
        if not isinstance(aliases, list):
            continue
        for alias in cast(list[object], aliases):
            if not isinstance(alias, str):
                continue
            alias_lower = alias.lower()
            if cleaned_lower == alias_lower and alias_lower not in _AMBIGUOUS_PROTOCOL_ALIASES:
                return name

    return None


def normalize_chain_name(value: str | None) -> str | None:
    """체인명을 내부 canonical key(ethereum, bsc 등)로 정규화한다."""
    if not value:
        return None

    cleaned = _clean_entity_label(value).lower()
    if not cleaned:
        return None

    for suffix in (" network", " chain", " mainnet"):
        if cleaned.endswith(suffix):
            trimmed = cleaned[: -len(suffix)].strip()
            if trimmed in _NETWORK_LABEL_MAP:
                return _NETWORK_LABEL_MAP[trimmed]

    mapped = _NETWORK_LABEL_MAP.get(cleaned)
    if mapped:
        return mapped

    for chain, keywords in CHAIN_KEYWORDS.items():
        if cleaned == chain.replace("_", " "):
            return chain
        for keyword in keywords:
            if cleaned == keyword.lower().lstrip("#"):
                return chain

    return None


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
    contextual_patterns = [
        (r"(?:actual\s+loss|loss|lost|stolen|drained|damage|피해액)[^\n\r$]{0,40}\$\s*~?\s*([\d,.]+)\s*[Bb](?:illion)?", 1_000_000_000),
        (r"(?:actual\s+loss|loss|lost|stolen|drained|damage|피해액)[^\n\r$]{0,40}\$\s*~?\s*([\d,.]+)\s*[Mm](?:illion)?", 1_000_000),
        (r"(?:actual\s+loss|loss|lost|stolen|drained|damage|피해액)[^\n\r$]{0,40}\$\s*~?\s*([\d,.]+)\s*[Kk]", 1_000),
        (r"(?:actual\s+loss|loss|lost|stolen|drained|damage|피해액)[^\n\r$]{0,40}\$\s*~?\s*([\d,.]+)", 1),
    ]
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

    for pattern, multiplier in [*contextual_patterns, *patterns]:
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
        aliases = proto.get("aliases")
        if not isinstance(aliases, list):
            continue
        name = proto.get("name")
        if not isinstance(name, str):
            continue
        for alias in cast(list[object], aliases):
            if not isinstance(alias, str):
                continue
            alias_lower = alias.lower()
            if alias_lower in _AMBIGUOUS_PROTOCOL_ALIASES:
                if _has_crypto_marker(text_lower, alias_lower):
                    return name
                continue
            if _contains_token(text_lower, alias_lower):
                return name
    return None


def extract_chain(text: str) -> str | None:
    """체인 추출 — 'Network: X' 라벨 우선, 이후 키워드 매칭.

    모호한 키워드(bitcoin, near, flow 등)는 해시태그(#bitcoin) 또는
    체인 문맥("on bitcoin", "bitcoin network")이 있을 때만 매칭.
    """
    text_lower = text.lower()

    # 1차: "Network: X" / "Chain: X" 라벨 매칭 (보안 봇 형식)
    label_match = _NETWORK_LABEL_RE.search(text)
    if label_match:
        label_value = label_match.group(1).strip().lower()
        mapped = _NETWORK_LABEL_MAP.get(label_value)
        if mapped:
            return mapped

    active_chain_match = re.search(
        r"(?:happened|exploited|drained|attack(?:ed)?|incident)\s+on\s+([a-zA-Z][a-zA-Z0-9 ]{1,24})",
        text,
        re.IGNORECASE,
    )
    if active_chain_match:
        candidate = re.sub(r"\s+only$", "", active_chain_match.group(1).strip(), flags=re.IGNORECASE)
        mapped = normalize_chain_name(candidate)
        if mapped:
            return mapped

    # 2차: 일반 키워드 매칭 (모호한 키워드는 문맥 체크)
    for chain, keywords in CHAIN_KEYWORDS.items():
        for kw in keywords:
            kw_lower = kw.lower()
            # 모호한 키워드 → 해시태그 또는 체인 문맥 필요
            if kw_lower in _AMBIGUOUS_CHAIN_KEYWORDS:
                if _has_crypto_marker(text_lower, kw_lower):
                    return chain
                continue
            if _contains_token(text_lower, kw):
                return chain
    return None


def extract_all(text: str) -> ExtractedFields:
    """모든 필드를 한번에 추출 — HackSignal에 적용할 dict 반환"""
    return {
        "tx_hash": extract_tx_hash(text),
        "attacker_address": extract_attacker_address(text),
        "loss_usd": extract_loss_usd(text),
        "protocol_name": extract_protocol_name(text),
        "chain": extract_chain(text),
    }
