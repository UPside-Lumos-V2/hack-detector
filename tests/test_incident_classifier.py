import unittest
from datetime import datetime, timezone

from src.incident_classifier import is_actionable_hack_incident, normalize_confidence
from src.models import HackSignal, SourceType


class IncidentClassifierTest(unittest.TestCase):
    def _signal(
        self,
        raw_text: str,
        *,
        llm_is_hack: bool | None = None,
        llm_confidence: float | None = None,
        protocol_name: str | None = None,
        loss_usd: float | None = None,
        tx_hash: str | None = None,
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
            tx_hash=tx_hash,
            llm_is_hack=llm_is_hack,
            llm_confidence=llm_confidence,
        )

    def test_active_exploit_with_loss_is_actionable(self):
        signal = self._signal(
            "Protocol was exploited resulting in total losses of $5.87M",
            llm_is_hack=True,
            protocol_name="TrustedVolumes",
            loss_usd=5_870_000,
        )

        self.assertTrue(is_actionable_hack_incident(signal))

    def test_onchain_bounty_message_is_other(self):
        signal = self._signal(
            "Onchain message: kept $100 as bounty, returned ~$1100 already",
            tx_hash="0x" + "a" * 64,
            loss_usd=100,
        )

        self.assertFalse(is_actionable_hack_incident(signal))

    def test_llm_not_hack_is_other(self):
        signal = self._signal(
            "Security newsletter covering recent exploit news",
            llm_is_hack=False,
            llm_confidence=0.95,
        )

        self.assertFalse(is_actionable_hack_incident(signal))

    def test_confidence_score_is_normalized(self):
        self.assertEqual(normalize_confidence(70), 0.7)
        self.assertEqual(normalize_confidence(110), 1.0)
        self.assertEqual(normalize_confidence(0.95), 0.95)


if __name__ == "__main__":
    _ = unittest.main()
