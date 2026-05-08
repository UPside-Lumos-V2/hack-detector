"""Authoritative binary hack-incident classifier.

The pipeline only needs one operational split:
- actionable hack incident: new/active incident worth grouping and alerting
- other: everything else, including reports, fund-tracking, negotiations, and market news
"""
from src.models import HackSignal


ACTIVE_INCIDENT_TERMS = (
    "exploited", "was exploited", "has been exploited", "reportedly exploited",
    "was attacked", "being attacked", "suspicious attack", "critical exploit",
    "reentrancy hack", "compromised admin key", "missing access control",
    "drained", "drain all funds", "stolen funds", "attacker exploited",
    "funds at risk", "security breach",
)

OTHER_CONTEXT_TERMS = (
    "onchain message", "bounty", "returned", "whitehat", "funds are safu",
    "fund return", "refund", "negotiation", "laundered", "tornado cash",
    "monthly", "weekly", "security news", "web2 security", "newsletter", "report", "post-mortem",
    "retrospective", "case study", "educational", "partnered", "staking",
    "staked", "etf", "whale", "deposited", "withdrew", "airdrop",
)


def normalize_confidence(value: float | int | None) -> float | None:
    """Return a 0..1 confidence value when possible."""
    if value is None:
        return None
    if value <= 1:
        return max(0.0, float(value))
    return min(float(value) / 100, 1.0)


def _text(signal: HackSignal) -> str:
    return f"{signal.source_author or ''}\n{signal.raw_text or ''}\n{signal.llm_summary or ''}".lower()


def has_other_context(signal: HackSignal) -> bool:
    text = _text(signal)
    return any(term in text for term in OTHER_CONTEXT_TERMS)


def has_active_incident_language(signal: HackSignal) -> bool:
    text = _text(signal)
    return any(term in text for term in ACTIVE_INCIDENT_TERMS)


def has_incident_evidence(signal: HackSignal) -> bool:
    return bool(
        signal.protocol_name
        or signal.tx_hash
        or signal.attacker_address
        or signal.loss_usd
    )


def is_actionable_hack_incident(signal: HackSignal) -> bool:
    """True only for active hack incidents; false means route to other/review."""
    if signal.llm_is_hack is False:
        return False
    if has_other_context(signal):
        return False
    if signal.llm_is_hack is True and has_active_incident_language(signal):
        return has_incident_evidence(signal)
    if has_active_incident_language(signal) and has_incident_evidence(signal):
        return True
    return False
