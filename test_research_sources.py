"""
test_research_sources.py
~~~~~~~~~~~~~~~~~~~~~~~~

Regression checks for the Phase-2 multi-source ingestion helpers added to the
research pipeline: CVE extraction from Metasploit module paths, the git-log
parser, and the multi-source observation merger.

These validate the ingestion mechanism end-to-end without requiring network, a
git binary, or a huge repository clone. They are NOT evidence of real-world
predictive validity; they prove that an independent, verifiably dated second
source can be turned into leakage-safe observations and that a genuinely
multi-source cohort is detected as such.
"""

import json
import tempfile
import unittest
from pathlib import Path

from dtem.evaluation.diagnostics import source_independence_audit
from dtem.evaluation.research_pipeline import (
    _extract_cve_tokens_from_path, _parse_msf_add_log, merge_observation_files,
)

# Realistic `git log --reverse --diff-filter=A --name-only --format=%cI%x09%H`
# output: a commit header line, a blank line, then each added file path.
SAMPLE_LOG = (
    "2025-01-20T10:00:00+00:00\tdeadbeef\n"
    "\n"
    "modules/exploits/windows/cve_2025_0108_ivanti.rb\n"
    "\n"
    "2021-07-01T00:00:00+00:00\tcafe1234\n"
    "\n"
    "modules/post/cve_2021_34527_printnightmare.rb\n"
    "modules/exploits/linux/http/some_product_named_rce.rb\n"
)


class CvePathExtractionTests(unittest.TestCase):
    def test_underscore_dated_filename(self):
        self.assertEqual(_extract_cve_tokens_from_path("modules/exploits/windows/cve_2025_0108_ivanti.rb"),
                         ["CVE-2025-0108"])

    def test_zero_padding_normalized(self):
        self.assertIn("CVE-2021-34527",
                      _extract_cve_tokens_from_path("modules/post/cve_2021_34527_x.rb"))

    def test_literal_cve_in_path(self):
        self.assertEqual(_extract_cve_tokens_from_path("modules/CVE-2018-15449.rb"),
                         ["CVE-2018-15449"])

    def test_multiple_cves_deduped_in_order(self):
        tokens = _extract_cve_tokens_from_path("modules/cve_2020_0001_a_cve_2020_0001_b.rb")
        self.assertEqual(tokens, ["CVE-2020-0001"])

    def test_no_cve_returns_empty(self):
        self.assertEqual(_extract_cve_tokens_from_path("modules/exploits/http/versal_ll_rce.rb"), [])


class MetasploitLogParserTests(unittest.TestCase):
    def setUp(self):
        self.events, self.added = _parse_msf_add_log(SAMPLE_LOG)

    def test_scans_all_added_module_files(self):
        self.assertEqual(self.added, 3)

    def test_only_cve_named_files_become_events(self):
        self.assertEqual(len(self.events), 2)
        self.assertEqual({e["cve_id"] for e in self.events},
                         {"CVE-2025-0108", "CVE-2021-34527"})

    def test_first_add_date_becomes_publication_and_availability(self):
        by_cve = {e["cve_id"]: e for e in self.events}
        self.assertEqual(by_cve["CVE-2025-0108"]["published_at"], "2025-01-20T10:00:00+00:00")
        self.assertEqual(by_cve["CVE-2025-0108"]["available_at"], "2025-01-20T10:00:00+00:00")
        self.assertEqual(by_cve["CVE-2021-34527"]["published_at"], "2021-07-01T00:00:00+00:00")

    def test_records_are_marked_as_independent_exploit_source(self):
        for event in self.events:
            self.assertEqual(event["source"], "Metasploit")
            self.assertEqual(event["source_type"], "exploit_module")
            self.assertEqual(event["exploit_evidence"], "verified_exploit")


class MergeAndIndependenceTests(unittest.TestCase):
    def _write(self, dir_path: Path, name: str, rows: list[dict]) -> Path:
        path = dir_path / name
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        return path

    def test_merge_marks_two_sources_and_dedups_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            nvd_a = {"cve_id": "CVE-2025-0108", "source": "NVD", "url": "u1",
                     "event_id": "e1", "published_at": "2025-01-10T00:00:00+00:00"}
            msf_a = {"cve_id": "CVE-2025-0108", "source": "Metasploit", "url": "u2",
                     "event_id": "e2", "published_at": "2025-01-20T10:00:00+00:00"}
            nvd_path = self._write(d, "nvd.jsonl", [nvd_a, nvd_a])  # duplicate row
            msf_path = self._write(d, "msf.jsonl", [msf_a])
            out = d / "merged.jsonl"
            manifest = merge_observation_files([nvd_path, msf_path], out)
            self.assertEqual(manifest["distinct_sources"], 2)
            self.assertEqual(manifest["merged_record_count"], 2)
            self.assertEqual(manifest["dropped_duplicates"], 1)
            merged = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines() if l.strip()]
            audit = source_independence_audit(merged)
            self.assertEqual(audit["distinct_sources"], 2)
            self.assertFalse(audit["single_source_cohort"])

    def test_single_source_cohort_still_detected_after_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            rows = [{"cve_id": "CVE-2025-0108", "source": "NVD", "url": f"u{i}",
                     "event_id": f"e{i}", "published_at": "2025-01-10T00:00:00+00:00"}
                    for i in range(3)]
            nvd_path = self._write(d, "nvd.jsonl", rows)
            out = d / "merged.jsonl"
            merge_observation_files([nvd_path], out)
            merged = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines() if l.strip()]
            audit = source_independence_audit(merged)
            self.assertTrue(audit["single_source_cohort"])


if __name__ == "__main__":
    unittest.main()
