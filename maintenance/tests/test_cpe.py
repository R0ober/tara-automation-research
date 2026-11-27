from __future__ import annotations

import unittest

from tara_maintenance.cpe import cpe_version, product_key, rule_matches_version

INSTALLED = "cpe:2.3:o:linux:linux_kernel:5.10.70:*:*:*:*:*:*:*"
WILDCARD = "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"


class CpeVersionTests(unittest.TestCase):
    def test_product_key_ignores_version_and_handles_escaped_separators(self) -> None:
        self.assertEqual(
            product_key(WILDCARD), ("o", "linux", "linux_kernel")
        )
        self.assertEqual(
            product_key("cpe:2.3:o:ti:sys\\/bios:6.83:*:*:*:*:*:*:*"),
            ("o", "ti", "sys\\/bios"),
        )
        self.assertIsNone(product_key("not-a-cpe"))

    def test_version_is_read_from_formatted_binding(self) -> None:
        self.assertEqual(cpe_version(INSTALLED), "5.10.70")

    def test_inclusive_boundaries_include_equal_versions(self) -> None:
        rule = {
            "cpe": WILDCARD,
            "version_start_including": "5.8",
            "version_end_including": "5.10.70",
        }

        self.assertTrue(rule_matches_version(rule, INSTALLED))

    def test_exclusive_end_rejects_equal_version(self) -> None:
        rule = {"cpe": WILDCARD, "version_end_excluding": "5.10.70"}

        self.assertFalse(rule_matches_version(rule, INSTALLED))

    def test_exclusive_start_rejects_equal_version(self) -> None:
        rule = {"cpe": WILDCARD, "version_start_excluding": "5.10.70"}

        self.assertFalse(rule_matches_version(rule, INSTALLED))

    def test_numeric_comparison_is_not_lexicographic(self) -> None:
        rule = {
            "cpe": WILDCARD,
            "version_start_including": "5.8",
            "version_end_excluding": "5.10.102",
        }

        self.assertTrue(rule_matches_version(rule, INSTALLED))

    def test_equivalent_trailing_zero_versions_match_boundary(self) -> None:
        rule = {"cpe": WILDCARD, "version_start_including": "2.0.0"}
        installed = "cpe:2.3:a:eclipse:mosquitto:2.0:*:*:*:*:*:*:*"

        self.assertTrue(rule_matches_version(rule, installed))

    def test_nonnumeric_version_is_unresolved(self) -> None:
        rule = {"cpe": WILDCARD, "version_end_including": "5.9.0-rc1"}

        self.assertIsNone(rule_matches_version(rule, INSTALLED))

    def test_wildcard_without_range_matches_all_versions(self) -> None:
        self.assertTrue(rule_matches_version({"cpe": WILDCARD}, INSTALLED))

    def test_not_applicable_version_does_not_mean_all_versions(self) -> None:
        rule = {"cpe": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}

        self.assertFalse(rule_matches_version(rule, INSTALLED))

    def test_exact_different_version_is_excluded(self) -> None:
        rule = {"cpe": "cpe:2.3:o:linux:linux_kernel:5.9.1:*:*:*:*:*:*:*"}

        self.assertFalse(rule_matches_version(rule, INSTALLED))


if __name__ == "__main__":
    unittest.main()
