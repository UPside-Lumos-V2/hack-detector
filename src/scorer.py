"""Confidence Scorer — Incident 그룹의 신뢰도 점수 산출

점수 체계 (최대 140점):
  - Source Tier:  T1=40, T2=25, T3=10 (최고 Tier 기준)
  - 교차 소스:    +30  (Twitter + Telegram 양쪽 감지)
  - tx_hash 존재: +20
  - loss_usd 명시: +10
  - protocol_name: +10
  - attacker_addr: +10
  - 다중 소스 (3+): +20
"""

TIER_SCORES = {1: 40, 2: 25, 3: 10}
MAX_SCORE = 140


def calculate_confidence(group: dict) -> int:
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
    source_types = group.get("source_types") or []
    unique_sources = set(source_types)

    # 기본 Tier 점수 (그룹의 best_tier 사용)
    best_tier = group.get("best_tier") or 3
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
    signal_count = group.get("signal_count") or 1
    if signal_count >= 3:
        score += 20

    return min(score, MAX_SCORE)
