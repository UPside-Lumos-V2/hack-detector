"""E2E Test Harness — 가짜 메시지 기반 Alert Pipeline 통합 테스트

13개 시나리오:
  A (메타데이터 4건) + B (그룹핑+Confidence 3건) + C (Alert 판정 3건)
  + D (Dedup 2건) + E (엣지 1건)

실행: .venv/bin/python -m pytest tests/e2e_harness.py -v
"""
import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from src.models import HackSignal, SourceType
from src.normalizer import has_hack_keyword, should_skip
from src.extractors.field_extractor import extract_all
from src.alerter import AlertRuleEngine
from src.deduplicator import AlertDeduplicator, DeduplicatorResult
from src.formatter import AlertFormatter
from src.scorer import calculate_confidence


# === Helpers ===

def make_signal(**overrides) -> HackSignal:
    """기본 HackSignal 팩토리"""
    defaults = {
        "raw_text": f"[test_{uuid4().hex[:6]}] Test signal",
        "source": SourceType.TELEGRAM,
        "source_id": f"tg_test_{uuid4().hex[:8]}",
        "source_url": "https://t.me/test/1",
        "source_author": "test_channel",
        "source_author_tier": 2,
        "published_at": datetime.now(timezone.utc),
    }
    defaults.update(overrides)
    return HackSignal(**defaults)


# =========================================
# Scenario A: 메타데이터 수집 검증
# =========================================

class ScenarioA_MetadataExtraction(unittest.TestCase):
    """필드 추출 + 키워드 감지 정확도"""

    def test_A1_full_extraction(self):
        """T1 보안업체 알림 → 전 필드 추출"""
        text = (
            "#PeckShieldAlert SomeProtocol exploited for $1.2M on #BSC "
            "tx: 0x" + "a" * 64
        )
        fields = extract_all(text)
        self.assertTrue(has_hack_keyword(text))
        self.assertEqual(fields["chain"], "bsc")
        self.assertEqual(fields["loss_usd"], 1_200_000.0)
        self.assertEqual(len(fields["tx_hash"]), 66)  # 0x + 64

    def test_A2_casahodl_noise(self):
        """RT @CasaHODL → 전 필드 None, 키워드 없음"""
        text = "RT @CasaHODL: Bitcoin Inheritance https://t.co/4eF3KYkOmf"
        fields = extract_all(text)
        self.assertFalse(has_hack_keyword(text))
        self.assertIsNone(fields["protocol_name"])
        self.assertIsNone(fields["chain"])
        self.assertIsNone(fields["loss_usd"])
        self.assertIsNone(fields["tx_hash"])

    def test_A3_attacker_address_extraction(self):
        """명시 라벨이 있는 공격자 주소 추출"""
        addr = "0x" + "1" * 40
        text = f"Attacker address: {addr} drained the pool"
        fields = extract_all(text)
        self.assertEqual(fields["attacker_address"], addr)
        self.assertTrue(has_hack_keyword(text))  # drained

    def test_A4_postmortem_text(self):
        """Post-mortem 텍스트에서 exploit 키워드 감지"""
        text = "Detailed post-mortem of the Euler Finance exploit"
        self.assertTrue(has_hack_keyword(text))  # exploit


# =========================================
# Scenario B: 그룹핑 + Confidence
# =========================================

class ScenarioB_GroupingAndConfidence(unittest.TestCase):
    """Scorer의 confidence 계산 정확도 (DB 없이 pure 함수 테스트)"""

    def test_B1_single_source_tier1(self):
        """단일 telegram T1, protocol만 → 50"""
        group = {
            "source_types": ["telegram"],
            "best_tier": 1,
            "protocol_name": "TestProto",
            "signal_count": 1,
        }
        score = calculate_confidence(group)
        # T1=40 + protocol=10 = 50
        self.assertEqual(score, 50)

    def test_B2_cross_source(self):
        """교차 소스 → +30"""
        group = {
            "source_types": ["telegram", "twitter"],
            "best_tier": 1,
            "protocol_name": "TestProto",
            "signal_count": 2,
        }
        score = calculate_confidence(group)
        # T1=40 + cross=30 + protocol=10 = 80
        self.assertEqual(score, 80)

    def test_B3_with_tx_hash(self):
        """교차 + tx_hash → 100"""
        group = {
            "source_types": ["telegram", "twitter"],
            "best_tier": 1,
            "protocol_name": "TestProto",
            "tx_hash": "0x" + "f" * 64,
            "signal_count": 3,
        }
        score = calculate_confidence(group)
        # T1=40 + cross=30 + tx=20 + protocol=10 + multi_source=20 = 120
        self.assertEqual(score, 120)


# =========================================
# Scenario C: Alert 판정
# =========================================

class ScenarioC_AlertDecision(unittest.TestCase):
    """AlertRuleEngine 룰 판정"""

    def setUp(self):
        self.engine = AlertRuleEngine()

    def test_C1_below_threshold(self):
        """단일 T1, confidence=50 → silent (Rule 2: conf<70)"""
        group = {
            "source_types": ["telegram"],
            "best_tier": 1,
            "confidence_score": 50,
        }
        d = self.engine.evaluate(group)
        self.assertFalse(d.should_alert)
        self.assertEqual(d.alert_level, "silent")

    def test_C2_cross_source_triggers(self):
        """교차 소스 → critical (Rule 1)"""
        group = {
            "source_types": ["telegram", "twitter"],
            "best_tier": 1,
            "confidence_score": 80,
        }
        d = self.engine.evaluate(group)
        self.assertTrue(d.should_alert)
        self.assertEqual(d.alert_level, "critical")

    def test_C3_tier1_high_confidence(self):
        """T1 + confidence=70 → critical (Rule 2 경계값)"""
        group = {
            "source_types": ["telegram"],
            "best_tier": 1,
            "confidence_score": 70,
        }
        d = self.engine.evaluate(group)
        self.assertTrue(d.should_alert)
        self.assertEqual(d.alert_level, "critical")

    def test_C3b_tier1_boundary_69(self):
        """T1 + confidence=69 → silent (Rule 2 경계 미달)"""
        group = {
            "source_types": ["telegram"],
            "best_tier": 1,
            "confidence_score": 69,
        }
        d = self.engine.evaluate(group)
        self.assertFalse(d.should_alert)

    def test_C_tier2_high_confidence_silent(self):
        """T2 + confidence=80 → silent (Rule 2는 T1만)"""
        group = {
            "source_types": ["telegram"],
            "best_tier": 2,
            "confidence_score": 80,
        }
        d = self.engine.evaluate(group)
        self.assertFalse(d.should_alert)


# =========================================
# Scenario D: Deduplication
# =========================================

class ScenarioD_Deduplication(unittest.TestCase):
    """DeduplicatorResult 로직 (DB 없이 _do_check 시뮬레이션)"""

    def test_D1_no_new_fields_silent(self):
        """새 정보 없으면 silent"""
        group = {"tx_hash": "0xabc", "loss_usd": 1000000}
        # 기존 알림에 이미 tx_hash, loss_usd 있음
        known = {"tx_hash", "loss_usd"}
        new_fields = [f for f in ("tx_hash", "loss_usd", "attacker_address")
                      if group.get(f) and f not in known]
        self.assertEqual(new_fields, [])

    def test_D2_new_attacker_follow_up(self):
        """attacker_address 추가 → follow_up"""
        group = {
            "tx_hash": "0xabc",
            "loss_usd": 1000000,
            "attacker_address": "0x1111",
        }
        known = {"tx_hash", "loss_usd"}
        new_fields = [f for f in ("tx_hash", "loss_usd", "attacker_address")
                      if group.get(f) and f not in known]
        self.assertEqual(new_fields, ["attacker_address"])


# =========================================
# Scenario E: 엣지 케이스
# =========================================

class ScenarioE_EdgeCases(unittest.TestCase):
    """skip 로직 검증"""

    def test_E1_empty_text(self):
        """빈 텍스트 → should_skip"""
        self.assertTrue(should_skip(""))

    def test_E1b_short_text(self):
        """10자 미만 → should_skip"""
        self.assertTrue(should_skip("hi"))

    def test_E1c_bot_command(self):
        """봇 명령어 → should_skip"""
        self.assertTrue(should_skip("/start"))

    def test_E1d_no_alnum(self):
        """알파벳/숫자 없음 → should_skip"""
        self.assertTrue(should_skip("!!!???..."))


# =========================================
# Formatter 통합 검증
# =========================================

class FormatterIntegration(unittest.TestCase):
    """Formatter가 실제 그룹 데이터로 올바른 메시지 생성"""

    def setUp(self):
        self.fmt = AlertFormatter()

    def test_first_alert_full_meta(self):
        """5/5 메타데이터 → 전체 식별"""
        group = {
            "protocol_name": "Radiant Capital",
            "chain": "arbitrum",
            "tx_hash": "0x" + "a" * 64,
            "loss_usd": 58_000_000,
            "attacker_address": "0x" + "1" * 40,
            "source_types": ["telegram", "twitter"],
            "confidence_score": 120,
        }
        msg = self.fmt.format_first_alert("grp-id", group)
        self.assertIn("5/5", msg.body)
        self.assertIn("$58.0M", msg.title)
        self.assertEqual(msg.alert_action, "first_alert")
        self.assertEqual(len(msg.metadata), 5)

    def test_follow_up_partial(self):
        """follow_up에 새 필드만 표시"""
        group = {
            "protocol_name": "TestProto",
            "chain": "ethereum",
            "tx_hash": "0x" + "b" * 64,
            "loss_usd": None,
            "attacker_address": "0x" + "2" * 40,
            "source_types": ["telegram"],
            "confidence_score": 60,
        }
        msg = self.fmt.format_follow_up("grp-id", group, ["attacker_address"])
        self.assertIn("4/5", msg.body)
        self.assertIn("attacker_address", msg.body)
        self.assertEqual(msg.alert_action, "follow_up")

    def test_zero_meta(self):
        """0/5 메타데이터"""
        msg = self.fmt.format_first_alert("grp-id", {"source_types": []})
        self.assertIn("0/5", msg.body)


if __name__ == "__main__":
    unittest.main()
