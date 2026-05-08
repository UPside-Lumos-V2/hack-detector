import unittest

from src.extractors.field_extractor import (
    extract_addresses,
    extract_all,
    extract_attacker_address,
    extract_chain,
    extract_loss_usd,
    extract_protocol_name,
    normalize_chain_name,
    normalize_protocol_name,
)


class FieldExtractorTest(unittest.TestCase):
    def test_non_incident_retweet_has_no_extracted_metadata(self):
        text = "RT @CasaHODL: Bitcoin Inheritance https://t.co/4eF3KYkOmf"

        self.assertEqual(
            extract_all(text),
            {
                "tx_hash": None,
                "attacker_address": None,
                "loss_usd": None,
                "protocol_name": None,
                "chain": None,
            },
        )

    def test_tx_hash_is_not_truncated_into_address(self):
        tx_hash = "0x" + "a" * 64

        self.assertEqual(extract_addresses(tx_hash), [])
        self.assertIsNone(extract_attacker_address(tx_hash))
        self.assertEqual(extract_all(f"exploit tx {tx_hash}")["tx_hash"], tx_hash)

    def test_attacker_address_requires_explicit_attacker_context(self):
        attacker = "0x" + "1" * 40
        contract = "0x" + "2" * 40

        self.assertEqual(
            extract_attacker_address(f"Attacker address: {attacker}"),
            attacker,
        )
        self.assertIsNone(extract_attacker_address(f"Pool contract: {contract}"))

    def test_ambiguous_aliases_do_not_match_plain_language(self):
        self.assertIsNone(extract_protocol_name("someone posted one more report"))
        self.assertIsNone(extract_chain("the solution was published"))

    def test_protocol_chain_and_loss_patterns_still_extract_incident_fields(self):
        text = "Radiant Capital exploited on Arbitrum for 1.2M USDC"

        self.assertEqual(extract_protocol_name(text), "Radiant Capital")
        self.assertEqual(extract_chain(text), "arbitrum")
        self.assertEqual(extract_loss_usd(text), 1_200_000)

    # ── "Network: X" 라벨 체인 감지 ──

    def test_network_label_mainnet_is_ethereum(self):
        """🌎 Network: mainnet → ethereum"""
        text = "🌎 Network: mainnet\n💰 Stolen: $1.2M"
        self.assertEqual(extract_chain(text), "ethereum")

    def test_network_label_bsc(self):
        """Network: BSC → bsc"""
        text = "Alert: exploit detected\nNetwork: BSC\nLoss: $500K"
        self.assertEqual(extract_chain(text), "bsc")

    def test_network_label_arbitrum(self):
        """Chain: Arbitrum → arbitrum"""
        text = "Chain: Arbitrum\nProtocol drained for $2M"
        self.assertEqual(extract_chain(text), "arbitrum")

    def test_network_label_case_insensitive(self):
        """대소문자 무관하게 매칭"""
        self.assertEqual(extract_chain("network: MAINNET"), "ethereum")
        self.assertEqual(extract_chain("NETWORK: bsc"), "bsc")

    def test_network_label_takes_priority_over_keyword(self):
        """라벨이 키워드보다 우선"""
        text = "🌎 Network: mainnet\nBridged from BSC"
        self.assertEqual(extract_chain(text), "ethereum")

    def test_chain_normalization_accepts_common_llm_labels(self):
        self.assertEqual(normalize_chain_name("BNB Chain"), "bsc")
        self.assertEqual(normalize_chain_name("Ethereum Mainnet"), "ethereum")
        self.assertEqual(normalize_chain_name("Arbitrum One"), "arbitrum")

    def test_protocol_normalization_rejects_ambiguous_alias_only(self):
        self.assertEqual(normalize_protocol_name("Radiant"), "Radiant Capital")
        self.assertIsNone(normalize_protocol_name("one"))


if __name__ == "__main__":
    unittest.main()
