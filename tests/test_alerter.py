"""Alert Rule Engine + Deduplicator + Formatter 단위 테스트"""
import unittest
from datetime import datetime, timezone
from typing import override

from postgrest.types import JSON

from src.alerter import AlertRuleEngine, evaluate_alert_gate, evaluate_signal_quarantine
from src.formatter import AlertFormatter
from src.models import HackSignal, SourceType


class AlertRuleEngineTest(unittest.TestCase):
    engine: AlertRuleEngine = AlertRuleEngine()

    @override
    def setUp(self) -> None:
        self.engine = AlertRuleEngine()

    def test_cross_source_always_critical(self):
        """교차 채널 (telegram + twitter) → 무조건 critical"""
        group: dict[str, JSON] = {
            "source_types": ["telegram", "twitter"],
            "confidence_score": 50,
            "best_tier": 3,
            "severity_score": 92,
            "severity_label": "critical",
        }
        decision = self.engine.evaluate(group)
        self.assertTrue(decision.should_alert)
        self.assertEqual(decision.alert_level, "critical")
        self.assertIn("cross_source", decision.reason)
        self.assertEqual(decision.severity_label, "critical")
        self.assertGreaterEqual(decision.severity_score or 0, 85)

    def test_tier1_high_confidence_critical(self):
        """Tier 1 + confidence >= 70 → critical"""
        group: dict[str, JSON] = {
            "source_types": ["telegram"],
            "confidence_score": 80,
            "best_tier": 1,
        }
        decision = self.engine.evaluate(group)
        self.assertTrue(decision.should_alert)
        self.assertEqual(decision.alert_level, "critical")

    def test_tier1_low_confidence_silent(self):
        """Tier 1 + confidence < 70 → silent"""
        group: dict[str, JSON] = {
            "source_types": ["telegram"],
            "confidence_score": 50,
            "best_tier": 1,
        }
        decision = self.engine.evaluate(group)
        self.assertFalse(decision.should_alert)
        self.assertEqual(decision.alert_level, "silent")

    def test_tier3_single_source_silent(self):
        """Tier 3 단일 소스 → silent"""
        group: dict[str, JSON] = {
            "source_types": ["twitter"],
            "confidence_score": 30,
            "best_tier": 3,
        }
        decision = self.engine.evaluate(group)
        self.assertFalse(decision.should_alert)
        self.assertEqual(decision.alert_level, "silent")

    def test_missing_fields_defaults_silent(self):
        """필드 누락 시 기본 silent"""
        decision = self.engine.evaluate({})
        self.assertFalse(decision.should_alert)

    def test_offensive_malformed_source_types_do_not_amplify(self):
        group: dict[str, JSON] = {
            "source_types": "telegram,twitter,chainalysis_official_verified_gold",
            "confidence_score": 99,
            "best_tier": 3,
        }

        decision = self.engine.evaluate(group)

        self.assertFalse(decision.should_alert)


class AlertGateTest(unittest.TestCase):
    def _signal(
        self,
        *,
        raw_text: str = "Possible exploit reported",
        protocol_name: str | None = None,
        loss_usd: float | None = None,
        llm_is_hack: bool | None = None,
        llm_confidence: float | None = None,
    ) -> HackSignal:
        return HackSignal(
            raw_text=raw_text,
            source=SourceType.TELEGRAM,
            source_id="tg_1_1",
            source_url="https://t.me/c/1/1",
            source_author="test",
            source_author_tier=1,
            published_at=datetime.now(timezone.utc),
            protocol_name=protocol_name,
            loss_usd=loss_usd,
            llm_is_hack=llm_is_hack,
            llm_confidence=llm_confidence,
        )

    def test_high_confidence_llm_not_hack_is_quarantined(self):
        signal = self._signal(llm_is_hack=False, llm_confidence=0.91)

        gate = evaluate_signal_quarantine(signal)

        self.assertTrue(gate.should_block_alert)
        self.assertEqual(gate.status, "quarantined")

    def test_group_without_identity_anchor_is_ambiguous(self):
        signal = self._signal()
        group: dict[str, JSON] = {"source_types": ["telegram", "twitter"], "confidence_score": 80, "best_tier": 1}

        gate = evaluate_alert_gate(signal, group)

        self.assertTrue(gate.should_block_alert)
        self.assertEqual(gate.status, "ambiguous")

    def test_group_with_protocol_anchor_can_alert(self):
        signal = self._signal(protocol_name="Radiant Capital")
        group: dict[str, JSON] = {"protocol_name": "Radiant Capital", "source_types": ["telegram"], "confidence_score": 80, "best_tier": 1}

        gate = evaluate_alert_gate(signal, group)

        self.assertFalse(gate.should_block_alert)

    def test_offensive_large_loss_without_identity_anchor_is_ambiguous(self):
        signal = self._signal(raw_text="Protocol drained for $40M. Details soon.", loss_usd=40_000_000)
        group: dict[str, JSON] = {"loss_usd": 40_000_000, "source_types": ["telegram", "twitter"], "confidence_score": 140, "best_tier": 1}

        gate = evaluate_alert_gate(signal, group)

        self.assertTrue(gate.should_block_alert)
        self.assertEqual(gate.status, "ambiguous")

    def test_offensive_llm_non_hack_veto_blocks_anchored_signal(self):
        signal = self._signal(
            raw_text="Withdrawals paused for maintenance. No user funds lost.",
            protocol_name="Aave",
            llm_is_hack=False,
            llm_confidence=0.96,
        )
        group: dict[str, JSON] = {"protocol_name": "Aave", "source_types": ["telegram", "twitter"], "confidence_score": 100, "best_tier": 1}

        gate = evaluate_alert_gate(signal, group)

        self.assertTrue(gate.should_block_alert)
        self.assertEqual(gate.status, "quarantined")

    def test_high_confidence_non_new_suppresses_without_fresh_anchor(self):
        signal = self._signal(protocol_name="Uniswap", llm_confidence=0.96)
        signal.llm_is_new_incident = False
        group: dict[str, JSON] = {
            "protocol_name": "Uniswap",
            "tx_hash": "0x" + "1" * 64,
            "attacker_address": "0x" + "2" * 40,
            "loss_usd": 2_000_000,
            "first_seen_at": "2026-05-08T00:00:00+00:00",
            "source_authors": ["telegram:test:1"],
        }
        signal.tx_hash = "0x" + "1" * 64
        signal.attacker_address = "0x" + "2" * 40
        signal.loss_usd = 2_000_000
        signal.published_at = datetime(2026, 5, 8, 0, 15, tzinfo=timezone.utc)

        gate = evaluate_alert_gate(signal, group)

        self.assertTrue(gate.should_block_alert)
        self.assertEqual(gate.status, "suppressed")
        self.assertEqual(gate.reason, "llm_non_new_no_fresh_anchor")

    def test_known_group_source_url_can_identify_fresh_url(self):
        signal = self._signal(protocol_name="Uniswap", llm_confidence=0.96)
        signal.llm_is_new_incident = False
        signal.tx_hash = "0x" + "1" * 64
        signal.source_url = "https://x.com/security/status/222"
        group: dict[str, JSON] = {
            "protocol_name": "Uniswap",
            "tx_hash": "0x" + "1" * 64,
            "source_url": "https://x.com/security/status/111",
            "source_authors": ["telegram:test:1"],
        }

        gate = evaluate_alert_gate(signal, group)

        self.assertFalse(gate.should_block_alert)
        self.assertEqual(gate.status, "allow")

    def test_none_new_incident_fails_open(self):
        signal = self._signal(protocol_name="Aave", llm_confidence=0.99)
        signal.llm_is_new_incident = None
        group: dict[str, JSON] = {"protocol_name": "Aave"}

        gate = evaluate_alert_gate(signal, group)

        self.assertFalse(gate.should_block_alert)
        self.assertEqual(gate.status, "allow")

    def test_low_confidence_non_new_fails_open(self):
        signal = self._signal(protocol_name="Aave", llm_confidence=0.60)
        signal.llm_is_new_incident = False
        group: dict[str, JSON] = {"protocol_name": "Aave"}

        gate = evaluate_alert_gate(signal, group)

        self.assertFalse(gate.should_block_alert)
        self.assertEqual(gate.status, "allow")

    def test_fresh_anchor_overrides_non_new_suppression(self):
        signal = self._signal(protocol_name="Uniswap", llm_confidence=0.95)
        signal.llm_is_new_incident = False
        signal.tx_hash = "0x" + "f" * 64
        group: dict[str, JSON] = {
            "protocol_name": "Uniswap",
            "tx_hash": "0x" + "e" * 64,
            "source_authors": ["telegram:test:1"],
        }

        gate = evaluate_alert_gate(signal, group)

        self.assertFalse(gate.should_block_alert)
        self.assertEqual(gate.status, "allow")

    def test_already_alerted_group_is_not_retroactively_suppressed(self):
        signal = self._signal(protocol_name="Aave", llm_confidence=0.97)
        signal.llm_is_new_incident = False
        group: dict[str, JSON] = {
            "protocol_name": "Aave",
            "alert_status": "alerted",
            "tx_hash": "0x" + "1" * 64,
        }
        signal.tx_hash = "0x" + "1" * 64

        gate = evaluate_alert_gate(signal, group)

        self.assertFalse(gate.should_block_alert)
        self.assertEqual(gate.status, "allow")

    def test_repeat_protocol_with_fresh_anchor_and_authors_is_allowed(self):
        signal = self._signal(
            protocol_name="Uniswap",
            llm_confidence=0.99,
            raw_text="New Uniswap exploit with fresh tx details",
        )
        signal.llm_is_new_incident = False
        signal.tx_hash = "0x" + "a" * 64
        signal.source = SourceType.TWITTER
        signal.source_author = "new_reporter"
        signal.source_url = "https://x.com/new_reporter/status/222"
        signal.published_at = datetime(2026, 5, 8, 12, 0, tzinfo=timezone.utc)
        group: dict[str, JSON] = {
            "protocol_name": "Uniswap",
            "tx_hash": "0x" + "b" * 64,
            "first_seen_at": "2026-05-08T00:00:00+00:00",
            "source_authors": ["telegram:oldreporter:1"],
            "source_url": "https://t.me/c/1/100",
        }

        gate = evaluate_alert_gate(signal, group)

        self.assertFalse(gate.should_block_alert)
        self.assertEqual(gate.status, "allow")


class AlertFormatterTest(unittest.TestCase):
    formatter: AlertFormatter = AlertFormatter()

    @override
    def setUp(self) -> None:
        self.formatter = AlertFormatter()

    def test_first_alert_contains_meta_summary(self):
        """첫 알림에 메타데이터 식별 현황 (N/5) 포함"""
        group: dict[str, JSON] = {
            "protocol_name": "Radiant Capital",
            "chain": "arbitrum",
            "tx_hash": "0x" + "a" * 64,
            "loss_usd": 1200000,
            "attacker_address": None,
            "source_types": ["telegram", "twitter"],
            "confidence_score": 110,
        }
        msg = self.formatter.format_first_alert("test-group-id", group)
        self.assertIn("4/5 식별", msg.body)
        self.assertIn("protocol ✓", msg.body)
        self.assertIn("attacker ✗", msg.body)
        self.assertIn("Radiant Capital", msg.title)
        self.assertEqual(msg.alert_action, "first_alert")
        self.assertEqual(len(msg.metadata), 4)  # 4개 필드 있음

    def test_follow_up_shows_new_info(self):
        """Follow-up 알림에 새 정보 표시"""
        group: dict[str, JSON] = {
            "protocol_name": "Radiant Capital",
            "chain": "arbitrum",
            "tx_hash": "0x" + "a" * 64,
            "loss_usd": 1200000,
            "attacker_address": "0x" + "1" * 40,
            "source_types": ["telegram", "twitter"],
            "confidence_score": 120,
        }
        msg = self.formatter.format_follow_up(
            "test-group-id", group, ["attacker_address"]
        )
        self.assertIn("5/5 식별", msg.body)
        self.assertIn("업데이트", msg.title)
        self.assertEqual(msg.alert_action, "follow_up")

    def test_all_none_metadata(self):
        """모든 메타데이터 None → 0/5"""
        group: dict[str, JSON] = {"source_types": ["telegram"]}
        msg = self.formatter.format_first_alert("test-id", group)
        self.assertIn("0/5 식별", msg.body)

    def test_offensive_malformed_db_row_formats_without_fake_metadata(self):
        group: dict[str, JSON] = {
            "protocol_name": "BadRowProtocol",
            "chain": "ethereum",
            "loss_usd": "not-a-number",
            "tx_hash": 12345,
            "source_types": "telegram,twitter",
            "confidence_score": 91,
        }

        msg = self.formatter.format_first_alert("bad-row-id", group)

        self.assertIn("unknown lost", msg.title)
        self.assertNotIn("Tx:", msg.body)
        self.assertEqual(msg.source_count, 0)


if __name__ == "__main__":
    _ = unittest.main()
