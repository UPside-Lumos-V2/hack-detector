"""Confidence scoring contracts for hack detection.

This module keeps the existing confidence score behavior intact while also
defining the future-facing score fields and a deterministic severity rubric.
"""

from typing import Final

from postgrest.types import JSON

TIER_SCORES: Final[dict[int, int]] = {1: 40, 2: 25, 3: 10}
MAX_SCORE: Final[int] = 140

CONFIDENCE_SCORE_FIELD: Final[str] = "confidence_score"
CORROBORATION_SCORE_FIELD: Final[str] = "corroboration_score"
SEVERITY_SCORE_FIELD: Final[str] = "severity_score"
SEVERITY_LABEL_FIELD: Final[str] = "severity_label"

SCORER_OUTPUT_FIELDS: Final[tuple[str, ...]] = (
    CONFIDENCE_SCORE_FIELD,
    CORROBORATION_SCORE_FIELD,
    SEVERITY_SCORE_FIELD,
    SEVERITY_LABEL_FIELD,
)

CONFIDENCE_INPUT_FIELDS: Final[tuple[str, ...]] = (
    "source_types",
    "best_tier",
    "signal_count",
    "tx_hash",
    "loss_usd",
    "protocol_name",
    "attacker_address",
)

# ── Same-platform corroboration bonus constants ────────────────────────────────

TWO_AUTHOR_BONUS: Final[int] = 10
THREE_PLUS_AUTHOR_BONUS: Final[int] = 15
TIER1_AUTHOR_BONUS: Final[int] = 5
MAX_PLATFORM_AUTHOR_BONUS: Final[int] = 20

# Identity anchors that allow same-platform corroboration to approach
# cross-platform confirmation strength (cross-platform gives +30 via
# calculate_confidence; same-platform is capped at +20 without anchors).
IDENTITY_ANCHOR_FIELDS: Final[tuple[str, ...]] = (
    "tx_hash",
    "attacker_address",
    "loss_usd",
    "protocol_name",
)

METADATA_COMPLETENESS_FIELDS: Final[tuple[str, ...]] = (
    "protocol_name",
    "chain",
    "tx_hash",
    "loss_usd",
    "attacker_address",
)

CORROBORATION_INPUT_FIELDS: Final[tuple[str, ...]] = (
    "source_authors",
    "source_author_count",
    "tier1_author_count",
    "tier2_author_count",
)

SEVERITY_LABEL_RANGES: Final[tuple[tuple[str, int, int], ...]] = (
    ("low", 0, 44),
    ("medium", 45, 69),
    ("high", 70, 84),
    ("critical", 85, 100),
)

# ── Severity scoring constants ─────────────────────────────────────────────────

SEVERITY_INPUT_FIELDS: Final[tuple[str, ...]] = (
    "llm_is_new_incident",
    "loss_usd",
    "tx_hash",
    "attacker_address",
    "protocol_name",
    "chain",
    "best_tier",
    "corroboration_score",
)

RETROSPECTIVE_SEVERITY_CAP: Final[int] = 30
ACTIVE_INCIDENT_BONUS: Final[int] = 40
UNCERTAIN_INCIDENT_BONUS: Final[int] = 15
MAX_CORROBORATION_SEVERITY_BONUS: Final[int] = 10
METADATA_COMPLETENESS_SEVERITY_BONUS: Final[int] = 5


def _parse_platform_author_stats(
    source_authors: list[str],
) -> dict[str, tuple[int, int]]:
    # Entry format from grouper: "{platform}:{author}:{tier}"
    # rfind(":") isolates the trailing tier so colons inside author names are safe.
    platform_keys: dict[str, set[str]] = {}
    platform_t1: dict[str, int] = {}

    for entry in source_authors:
        colon_pos = entry.rfind(":")
        if colon_pos == -1:
            continue
        key = entry[:colon_pos]
        tier_str = entry[colon_pos + 1:]

        first_colon = key.find(":")
        if first_colon == -1:
            continue
        platform = key[:first_colon]

        if platform not in platform_keys:
            platform_keys[platform] = set()
            platform_t1[platform] = 0

        is_new_key = key not in platform_keys[platform]
        platform_keys[platform].add(key)
        if is_new_key and tier_str.isdigit() and int(tier_str) == 1:
            platform_t1[platform] += 1

    return {
        platform: (len(keys), platform_t1[platform])
        for platform, keys in platform_keys.items()
    }


def _string_list(value: JSON | None) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _int_value(value: JSON | None, default: int) -> int:
    if isinstance(value, bool):
        return default
    return int(value) if isinstance(value, int | float) else default


def _bool_value(value: JSON | None) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def calculate_confidence(group: dict[str, JSON]) -> int:
    """
    Incident 그룹 데이터로 confidence score 계산.

    Args:
        group: lumos_incident_groups row (dict)
            - source_types: ['twitter', 'telegram']
            - signal_count: int
            - tx_hash, loss_usd, protocol_name, attacker_address
    """
    score = 0

    # 소스 타입 수 → 교차 소스 보너스
    source_types = _string_list(group.get("source_types"))
    unique_sources = set(source_types)

    # 기본 Tier 점수 (그룹의 best_tier 사용)
    best_tier = _int_value(group.get("best_tier"), 3)
    score += TIER_SCORES.get(best_tier, 10)

    # 교차 소스 보너스 (+30)
    if len(unique_sources) >= 2:
        score += 30

    # 필드 보너스
    if group.get("tx_hash"):
        score += 20
    if group.get("loss_usd"):
        score += 10
    if group.get("protocol_name"):
        score += 10
    if group.get("attacker_address"):
        score += 10

    # 다중 소스 보너스 (signal_count >= 3)
    signal_count = _int_value(group.get("signal_count"), 1)
    if signal_count >= 3:
        score += 20

    return min(score, MAX_SCORE)


def calculate_corroboration(group: dict[str, JSON]) -> int:
    source_authors = _string_list(group.get("source_authors"))
    if not source_authors:
        return 0

    stats = _parse_platform_author_stats(source_authors)
    if not stats:
        return 0

    best_bonus = 0
    for unique_count, tier1_count in stats.values():
        bonus = 0
        if unique_count >= 3:
            bonus += THREE_PLUS_AUTHOR_BONUS
        elif unique_count >= 2:
            bonus += TWO_AUTHOR_BONUS
        if tier1_count >= 2:
            bonus += TIER1_AUTHOR_BONUS
        best_bonus = max(best_bonus, bonus)

    return min(best_bonus, MAX_PLATFORM_AUTHOR_BONUS)


def severity_label_for_score(score: int | float) -> str:
    """Map a numeric severity score onto the contract labels.

    Scores are clamped to 0..100 before banding.
    """

    value = max(0.0, min(float(score), 100.0))
    for label, lower, upper in SEVERITY_LABEL_RANGES:
        if lower <= value <= upper:
            return label
    return "critical"


def calculate_severity(group: dict[str, JSON]) -> tuple[int, str]:
    """Compute (severity_score, severity_label) from impact/urgency evidence.

    Severity is independent of confidence.  Retrospective reports
    (llm_is_new_incident=False) are capped at RETROSPECTIVE_SEVERITY_CAP
    regardless of loss size or source tier.

    Score components:
        activeness       : +40 (confirmed active) | +15 (unknown) | cap 30 (retrospective)
        loss_usd         : +30 (>=10M) | +20 (>=1M) | +10 (>=100K) | +5 (>0)
        tx_hash          : +15
        attacker_address : +10
        protocol_name    : +5
        best_tier=1      : +10 | tier=2: +5
        corroboration    : +10 (score>=15) | +5 (score>=10) | +0 otherwise
        metadata         : +5 when at least 4/5 key metadata fields are present
    """
    is_new = _bool_value(group.get("llm_is_new_incident"))

    if is_new is False:
        return RETROSPECTIVE_SEVERITY_CAP, severity_label_for_score(RETROSPECTIVE_SEVERITY_CAP)

    active_bonus = ACTIVE_INCIDENT_BONUS if is_new is True else UNCERTAIN_INCIDENT_BONUS

    raw_loss = group.get("loss_usd")
    loss_usd: float | None = (
        float(raw_loss)
        if isinstance(raw_loss, (int, float)) and not isinstance(raw_loss, bool)
        else None
    )
    if loss_usd is not None and loss_usd >= 10_000_000:
        loss_pts = 30
    elif loss_usd is not None and loss_usd >= 1_000_000:
        loss_pts = 20
    elif loss_usd is not None and loss_usd >= 100_000:
        loss_pts = 10
    elif loss_usd is not None and loss_usd > 0:
        loss_pts = 5
    else:
        loss_pts = 0

    anchor_pts = 0
    if group.get("tx_hash"):
        anchor_pts += 15
    if group.get("attacker_address"):
        anchor_pts += 10
    if group.get("protocol_name"):
        anchor_pts += 5

    best_tier = _int_value(group.get("best_tier"), 3)
    tier_pts = {1: 10, 2: 5}.get(best_tier, 0)

    corr = _int_value(group.get("corroboration_score"), 0)
    corr_pts = MAX_CORROBORATION_SEVERITY_BONUS if corr >= 15 else (5 if corr >= 10 else 0)

    metadata_count = sum(1 for field in METADATA_COMPLETENESS_FIELDS if group.get(field))
    metadata_pts = METADATA_COMPLETENESS_SEVERITY_BONUS if metadata_count >= 4 else 0

    raw = active_bonus + loss_pts + anchor_pts + tier_pts + corr_pts + metadata_pts
    score = max(0, min(raw, 100))
    return score, severity_label_for_score(score)
