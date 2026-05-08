"""Alert Rule Engine + Deduplicator + Formatter 단위 테스트"""
import unittest
from datetime import datetime, timezone

from src.alerter import AlertRuleEngine, evaluate_alert_gate, evaluate_signal_quarantine
from src.formatter import AlertFormatter
from src.models import HackSignal, SourceType


class AlertRuleEngineTest(unittest.TestCase):
    def setUp(self):
        self.engine = AlertRuleEngine()

    def test_cross_source_always_critical(self):
        """교차 채널 (telegram + twitter) → 무조건 critical"""
        group = {
            "source_types": ["telegram", "twitter"],
            "confidence_score": 50,
            "best_tier": 3,
        }
        decision = self.engine.evaluate(group)
        self.assertTrue(decision.should_alert)
        self.assertEqual(decision.alert_level, "critical")
        self.assertIn("cross_source", decision.reason)

    def test_tier1_high_confidence_critical(self):
        """Tier 1 + confidence >= 70 → critical"""
        group = {
            "source_types": ["telegram"],
            "confidence_score": 80,
            "best_tier": 1,
        }
        decision = self.engine.evaluate(group)
        self.assertTrue(decision.should_alert)
        self.assertEqual(decision.alert_level, "critical")

    def test_tier1_low_confidence_silent(self):
        """Tier 1 + confidence < 70 → silent"""
        group = {
            "source_types": ["telegram"],
            "confidence_score": 50,
            "best_tier": 1,
        }
        decision = self.engine.evaluate(group)
        self.assertFalse(decision.should_alert)
        self.assertEqual(decision.alert_level, "silent")

    def test_tier3_single_source_silent(self):
        """Tier 3 단일 소스 → silent"""
        group = {
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


class AlertGateTest(unittest.TestCase):
    def _signal(self, **overrides):
        data = {
            "raw_text": "Possible exploit reported",
            "source": SourceType.TELEGRAM,
            "source_id": "tg_1_1",
            "source_url": "https://t.me/c/1/1",
            "source_author": "test",
            "source_author_tier": 1,
            "published_at": datetime.now(timezone.utc),
        }
        data.update(overrides)
        return HackSignal(**data)

    def test_high_confidence_llm_not_hack_is_quarantined(self):
        signal = self._signal(llm_is_hack=False, llm_confidence=0.91)

        gate = evaluate_signal_quarantine(signal)

        self.assertTrue(gate.should_block_alert)
        self.assertEqual(gate.status, "quarantined")

    def test_group_without_identity_anchor_is_ambiguous(self):
        signal = self._signal()
        group = {"source_types": ["telegram", "twitter"], "confidence_score": 80, "best_tier": 1}

        gate = evaluate_alert_gate(signal, group)

        self.assertTrue(gate.should_block_alert)
        self.assertEqual(gate.status, "ambiguous")

    def test_group_with_protocol_anchor_can_alert(self):
        signal = self._signal(protocol_name="Radiant Capital")
        group = {"protocol_name": "Radiant Capital", "source_types": ["telegram"], "confidence_score": 80, "best_tier": 1}

        gate = evaluate_alert_gate(signal, group)

        self.assertFalse(gate.should_block_alert)


class AlertFormatterTest(unittest.TestCase):
    def setUp(self):
        self.formatter = AlertFormatter()

    def test_first_alert_contains_meta_summary(self):
        """첫 알림에 메타데이터 식별 현황 (N/5) 포함"""
        group = {
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
        group = {
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
        group = {"source_types": ["telegram"]}
        msg = self.formatter.format_first_alert("test-id", group)
        self.assertIn("0/5 식별", msg.body)


if __name__ == "__main__":
    unittest.main()
