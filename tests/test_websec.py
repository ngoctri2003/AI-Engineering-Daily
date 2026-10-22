import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from app import secsources as ss
from app import websec as w

NOW = datetime(2026, 10, 22, 9, 0, tzinfo=timezone.utc)
CUTOFF = NOW - timedelta(hours=48)
WATCH = w.load_json(w.PROFILE_DIR / "watchlist.json")["products"]
FIXTURE = Path(__file__).parent / "fixture_websec.json"


def cand(**kw):
    base = dict(id="CVE-2026-0001", source="t", title="Title", url="https://example.com/x",
                published_at="2026-10-22T00:00:00+00:00", cve_ids=["CVE-2026-0001"], source_product="Chrome")
    base.update(kw)
    return ss.make_candidate(**base)


class FetcherTests(unittest.TestCase):
    def test_kev_window_and_flags(self):
        data = {"vulnerabilities": [
            {"cveID": "CVE-2026-1111", "vendorProject": "Google", "product": "Chromium V8",
             "vulnerabilityName": "V8 type confusion", "dateAdded": "2026-10-21",
             "shortDescription": "desc", "requiredAction": "Apply updates."},
            {"cveID": "CVE-2020-0001", "vendorProject": "Old", "product": "Old", "dateAdded": "2020-01-01"}]}
        out, info = ss.fetch_kev({"name": "KEV", "url": "u"}, CUTOFF, get=lambda url: data)
        self.assertEqual([c["id"] for c in out], ["CVE-2026-1111"])
        self.assertTrue(out[0]["in_kev"] and out[0]["exploited"])
        self.assertIn("newest entry 2026-10-21", info)

    def test_global_advisory_per_package_and_window(self):
        advs = [
            {"ghsa_id": "GHSA-aaaa", "cve_id": "CVE-2026-2222", "summary": "next flaw", "severity": "critical",
             "html_url": "https://github.com/advisories/GHSA-aaaa", "published_at": "2026-10-21T10:00:00Z",
             "cvss": {"score": 9.1},
             "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "Next"},
                                  "vulnerable_version_range": "< 15.1.2", "first_patched_version": "15.1.2"}]},
            {"ghsa_id": "GHSA-old", "published_at": "2026-09-01T10:00:00Z", "vulnerabilities": []}]
        out, _ = ss.fetch_ghsa({"name": "G", "ecosystem": "npm"}, CUTOFF, get=lambda url, h: advs)
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0]["package"], out[0]["cvss"], out[0]["fixed_in"]), ("next", 9.1, "15.1.2"))

    def test_repo_advisory_patched_versions_and_empty_cvss(self):
        adv = {"ghsa_id": "GHSA-bbbb", "cve_id": None, "summary": "s", "published_at": "2026-10-22T01:00:00Z",
               "cvss": {"score": None},
               "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "express"}, "patched_versions": "4.21.3"}]}
        out = ss.advisory_to_candidates(adv, {"name": "R", "product": "Express"}, CUTOFF)
        self.assertEqual((out[0]["id"], out[0]["cvss"], out[0]["fixed_in"]), ("GHSA-bbbb", None, "4.21.3"))

    def test_feed_qualify_pattern_and_wild_flag(self):
        xml = ("<rss><channel>"
               "<item><title>Stable Channel Update</title><link>https://c.example/1</link>"
               "<pubDate>Wed, 21 Oct 2026 08:00:00 GMT</pubDate>"
               "<description>Critical CVE-2026-3333 fix. An exploit exists in the wild.</description></item>"
               "<item><title>Beta update</title><link>https://c.example/2</link>"
               "<pubDate>Wed, 21 Oct 2026 09:00:00 GMT</pubDate><description>no cve here</description></item>"
               "</channel></rss>")
        src = {"name": "Chrome Releases", "url": "u", "product": "Chrome", "pattern": r"CVE-\d{4}-\d{4,7}"}
        out, _ = ss.fetch_feed(src, CUTOFF, get_text=lambda url: xml)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0]["exploited"])
        self.assertEqual((out[0]["severity"], out[0]["cve_ids"]), ("critical", ["CVE-2026-3333"]))

    def test_collect_survives_a_failing_source(self):
        def boom(src, cutoff, token=None):
            raise RuntimeError("down")
        logs = []
        cands, status = ss.collect([{"name": "A", "type": "x"}], NOW, log=logs.append, fetchers={"x": boom})
        self.assertEqual(cands, [])
        self.assertTrue(status["A"].startswith("ERROR"))

    def test_stale_source_is_flagged(self):
        fetch = lambda src, cutoff, token=None: ([], "ok (0 in window, newest entry 2026-01-01)")
        _, status = ss.collect([{"name": "A", "type": "x", "stale_after_days": 14}], NOW, log=lambda m: None,
                               fetchers={"x": fetch})
        self.assertTrue(status["A"].startswith("STALE?"))

    def test_cvelist_url_and_cvss(self):
        self.assertTrue(ss.cvelist_url("CVE-2024-1234").endswith("/cves/2024/1xxx/CVE-2024-1234.json"))
        self.assertTrue(ss.cvelist_url("CVE-2024-12345").endswith("/cves/2024/12xxx/CVE-2024-12345.json"))
        rec = {"containers": {"cna": {"metrics": [{"cvssV3_1": {"baseScore": 7.5}}]},
                              "adp": [{"metrics": [{"cvssV3_1": {"baseScore": 9.8}}, {"other": {}}]}]}}
        self.assertEqual(ss.extract_cvss(rec), 9.8)
        self.assertIsNone(ss.extract_cvss({}))

    def test_enrich_keeps_empty_on_failure(self):
        c1, c2 = cand(), cand(id="CVE-2026-0002", cve_ids=["CVE-2026-0002"])

        def get(url):
            if "0002" in url:
                raise RuntimeError("404")
            return {"containers": {"cna": {"metrics": [{"cvssV3_1": {"baseScore": 8.8}}]}}}
        ss.enrich_cvss([c1, c2], get=get, log=lambda m: None)
        self.assertEqual((c1["cvss"], c2["cvss"]), (8.8, None))


class FilterTests(unittest.TestCase):
    def kept(self, **kw):
        return w.prefilter([cand(**kw)], WATCH)

    def test_threshold_boundary(self):
        self.assertEqual(len(self.kept(cvss=8.0)), 1)
        self.assertEqual(len(self.kept(cvss=7.9)), 0)

    def test_empty_cvss_without_other_signal_is_dropped(self):
        self.assertEqual(len(self.kept(cvss=None)), 0)

    def test_unlisted_product_dropped_unless_kev(self):
        self.assertEqual(len(w.prefilter([cand(source_product="Unknown Thing", cvss=9.9)], WATCH)), 0)
        kev = cand(source_product="", vendor="Cisco", product="IOS XE", in_kev=True, exploited=True)
        got = w.prefilter([kev], WATCH)
        self.assertEqual(len(got), 1)
        self.assertIsNone(got[0][1])

    def test_package_and_alias_matching(self):
        self.assertEqual(w.match_watchlist(cand(ecosystem="npm", package="next", source_product=""), WATCH)["name"], "Next.js")
        self.assertIsNone(w.match_watchlist(cand(ecosystem="npm", package="nextra", source_product=""), WATCH))
        self.assertEqual(w.match_watchlist(cand(source_product="", vendor="PHP Group", product="PHP"), WATCH)["name"], "PHP")
        self.assertIsNone(w.match_watchlist(cand(source_product="", vendor="x", product="phpMyAdmin"), WATCH))
        self.assertIsNone(w.match_watchlist(cand(source_product="", vendor="x", product="WebKitGTK"), WATCH))

    def test_vendor_release_and_critical_hint_qualify(self):
        self.assertEqual(len(self.kept(vendor_security_release=True)), 1)
        self.assertEqual(len(self.kept(severity="critical")), 1)
        self.assertEqual(len(self.kept(severity="high")), 0)

    def test_drop_posted(self):
        a, b = cand(), cand(id="https://f/1", cve_ids=[])
        self.assertEqual(w.drop_posted([a, b], {"CVE-2026-0001"}), [b])
        self.assertEqual(w.drop_posted([a, b], {"CVE-2026-0001", "https://f/1"}), [])


class SelectionTests(unittest.TestCase):
    def batches(self):
        kept = w.prefilter([
            cand(id="CVE-2026-0010", cve_ids=["CVE-2026-0010"], source_product="Chrome", exploited=True, cvss=8.8),
            cand(id="CVE-2026-0011", cve_ids=["CVE-2026-0011"], source_product="Chrome", cvss=9.0),
            cand(id="CVE-2026-0020", cve_ids=["CVE-2026-0020"], source_product="Firefox", cvss=9.5),
            cand(id="CVE-2026-0030", cve_ids=["CVE-2026-0030"], source_product="Node.js", cvss=8.1),
            cand(id="CVE-2026-0040", cve_ids=["CVE-2026-0040"], source_product="PHP", cvss=8.6),
            cand(id="CVE-2026-0050", cve_ids=["CVE-2026-0050"], source_product="", vendor="Cisco", product="IOS", in_kev=True, exploited=True),
        ], WATCH)
        return w.group_batches(kept)

    def test_same_product_same_day_is_one_batch(self):
        chrome = [b for b in self.batches() if b["product"] == "Chrome"]
        self.assertEqual(len(chrome), 1)
        self.assertEqual((chrome[0]["cve_ids"], chrome[0]["cvss"], chrome[0]["tier"]), (["CVE-2026-0010", "CVE-2026-0011"], 9.0, 1))

    def test_cap_order_and_one_liners(self):
        detailed, others = w.select(self.batches())
        self.assertEqual(len(detailed), 3)
        self.assertEqual([b["product"] for b in detailed], ["Chrome", "Firefox", "PHP"])
        self.assertEqual(sorted(b["product"] for b in others), ["Cisco IOS", "Node.js"])
        self.assertTrue(all(b["tier"] == 4 for b in others if b["product"] == "Cisco IOS"))

    def test_tier4_never_detailed(self):
        only = [b for b in self.batches() if b["tier"] == 4]
        detailed, others = w.select(only)
        self.assertEqual((detailed, len(others)), ([], 1))


def batch(**kw):
    base = {"batch_id": "B1", "product": "Next.js", "count": 1, "title": "Next.js auth bypass", "ids": ["CVE-2026-0100"],
            "url": "https://example.com/n", "published_at": "2026-10-22", "cve_ids": ["CVE-2026-0100"], "cvss": 9.1,
            "severity": "critical", "in_kev": False, "exploited": False, "fixed_in": "15.1.2", "affected": "< 15.1.2",
            "summary": "Authentication bypass in middleware.", "category": "FRAMEWORK", "tag": "#JavaScript", "tier": 2}
    base.update(kw)
    return base


WORDS = " ".join(["word"] * 14)
GOOD = {"batch_id": "B1", "headline": "Next.js auth bypass CVE-2026-0100",
        "description": f"Flaw in middleware lets requests skip authentication. {WORDS}",
        "impact": f"Versions below 15.1.2 are affected when middleware guards routes. {WORDS}",
        "action": "Update to 15.1.2 and redeploy."}


class ValidationTests(unittest.TestCase):
    def errs(self, **over):
        return w.validate_summary({**GOOD, **over}, batch())

    def test_good(self):
        self.assertEqual(self.errs(), [], self.errs())

    def test_invented_cve(self):
        self.assertTrue(any("CVE IDs" in e for e in self.errs(headline="Flaw CVE-2026-9999")))

    def test_invented_version(self):
        self.assertTrue(any("numbers" in e for e in self.errs(action="Update to 15.9.9 and redeploy.")))

    def test_word_count_em_dash_emoji_missing(self):
        self.assertTrue(any("words" in e for e in self.errs(description="short", impact="short", action="short")))
        self.assertTrue(any("em dash" in e for e in self.errs(headline="A — B")))
        self.assertTrue(any("emoji" in e for e in self.errs(headline="A \U0001F680")))
        self.assertTrue(any("missing action" in e for e in self.errs(action="")))

    def test_score_must_match_data(self):
        self.assertTrue(any("numbers" in e for e in self.errs(impact=f"CVSS 9.9 reported. {WORDS} {WORDS}")))
        self.assertEqual(self.errs(impact=f"CVSS 9.1 reported. {WORDS} {WORDS}"), [])


@mock.patch.dict(os.environ, {"LLM_PROVIDER": "mock"})
class RenderTests(unittest.TestCase):
    SETTINGS = w.load_json(w.PROFILE_DIR / "profile.json")

    def test_digest_and_check(self):
        b = batch()
        other = batch(batch_id="B2", product="Node.js", cve_ids=["CVE-2026-0200"], ids=["CVE-2026-0200"], url="https://example.com/o")
        text = w.render_digest([(b, GOOD)], [other], self.SETTINGS, "22/10/2026")
        self.assertTrue(text.startswith("*Tech Stack Security Daily: 22/10/2026*"))
        self.assertIn("`#JavaScript` `#CVE`", text)
        self.assertEqual(w.check_digest(text, [(b, GOOD)], [other]), [])

    def test_exploited_tag(self):
        text = w.render_item(batch(exploited=True), GOOD, self.SETTINGS["strings"])
        self.assertIn("`#ZeroDay`", text)

    def test_check_catches_stray_cve_and_cap(self):
        b = batch()
        text = w.render_digest([(b, GOOD)], [], self.SETTINGS, "22/10/2026") + " CVE-2026-7777"
        self.assertTrue(any("outside" in e for e in w.check_digest(text, [(b, GOOD)], [])))
        pairs = [(b, GOOD)] * 4
        self.assertTrue(any("more than" in e for e in w.check_digest("x", pairs, [])))

    def test_invalid_summary_degrades_to_one_line(self):
        bad = {**GOOD, "headline": "CVE-2026-9999 invented"}
        resp = {"items": [bad]}
        pairs, failed = w.summarize([batch()], NOW, "sys", resp, log=lambda m: None)
        self.assertEqual((pairs, [b["batch_id"] for b in failed]), ([], ["B1"]))

    def test_unknown_batch_id_ignored_and_missing_item_degrades(self):
        resp = {"items": [{**GOOD, "batch_id": "B99"}]}
        pairs, failed = w.summarize([batch()], NOW, "sys", resp, log=lambda m: None)
        self.assertEqual((pairs, [b["batch_id"] for b in failed]), ([], ["B1"]))


class RunTests(unittest.TestCase):
    def run_main(self, state_path, dry_run):
        out = io.StringIO()
        with mock.patch.object(w, "STATE", state_path), mock.patch.object(w.slack, "post") as post, redirect_stdout(out):
            code = w.run(dry_run=dry_run, mock_file=str(FIXTURE), now=NOW)
        return code, out.getvalue(), post

    def test_dry_run_prints_digest_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "posted-websec.json"
            code, out, post = self.run_main(state, True)
            self.assertEqual(code, 0)
            self.assertIn("Tech Stack Security Daily: 22/10/2026", out)
            self.assertIn("[dry-run]", out)
            post.assert_not_called()
            self.assertFalse(state.exists())

    def test_post_saves_state_and_second_run_posts_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "posted-websec.json"
            code, out, post = self.run_main(state, False)
            post.assert_called_once()
            saved = json.loads(state.read_text(encoding="utf-8"))
            self.assertIn("CVE-2026-1001", {i for p in saved["posted"] for i in p["ids"]})
            code2, out2, post2 = self.run_main(state, False)
            post2.assert_not_called()
            self.assertIn("Nothing to post", out2)

    def tearDown(self):
        os.environ.pop("LLM_PROVIDER", None)


@mock.patch.dict(os.environ, {"LLM_PROVIDER": "mock"})
class ReviewRegressionTests(unittest.TestCase):
    def test_links_mentions_and_markup_are_rejected(self):
        for bad in ("see https://evil.example/p", "ping <!channel>", "a | b", "use `code`", "a & b", "www.evil.example"):
            self.assertTrue(any("markup" in e for e in w.validate_summary({**GOOD, "action": bad + " " + WORDS}, batch())), bad)

    def test_non_string_fields_degrade_instead_of_crashing(self):
        resp = {"items": [{**GOOD, "batch_id": ["B1"]}, {**GOOD, "headline": ["x"]}, "text", None, {**GOOD, "impact": 5}]}
        pairs, failed = w.summarize([batch()], NOW, "sys", resp, log=lambda m: None)
        self.assertEqual((pairs, [b["batch_id"] for b in failed]), ([], ["B1"]))

    def test_one_liner_never_uses_free_text(self):
        line = w.one_liner(batch(cve_ids=[], title="Bug related to CVE-2020-0001 <!channel>"), {"fixed": "fix"})
        self.assertNotIn("CVE-2020-0001", line)
        self.assertNotIn("<", line)

    def test_same_cve_from_two_sources_is_one_batch(self):
        kev = cand(id="CVE-2026-5000", cve_ids=["CVE-2026-5000"], source_product="", vendor="Vercel", product="Next.js",
                   in_kev=True, exploited=True, published_at="2026-10-22T00:00:00+00:00")
        ghsa = cand(id="CVE-2026-5000", cve_ids=["CVE-2026-5000"], source_product="", ecosystem="npm", package="next",
                    cvss=9.0, published_at="2026-10-21T10:00:00+00:00")
        batches = w.group_batches(w.prefilter([kev, ghsa], WATCH))
        self.assertEqual(len(batches), 1)
        self.assertEqual((batches[0]["cve_ids"], batches[0]["cvss"], batches[0]["tier"]), (["CVE-2026-5000"], 9.0, 1))

    def test_enrich_uses_highest_score_over_all_cves(self):
        c = cand(cve_ids=["CVE-2026-0001", "CVE-2026-0002"])
        scores = {"0001": 5.0, "0002": 9.8}
        get = lambda url: {"containers": {"cna": {"metrics": [{"cvssV3_1": {"baseScore": next(v for k, v in scores.items() if k in url)}}]}}}
        ss.enrich_cvss([c], get=get, log=lambda m: None)
        self.assertEqual(c["cvss"], 9.8)

    def test_vendor_release_qualifies_even_with_low_first_score(self):
        self.assertTrue(w.qualifies(cand(cvss=5.0, vendor_security_release=True)))
        self.assertFalse(w.qualifies(cand(cvss=5.0)))

    def test_version_must_match_whole_token(self):
        self.assertTrue(any("numbers" in e for e in w.validate_summary(
            {**GOOD, "action": "Update to 5.1 and redeploy."}, batch(fixed_in="15.1.2", affected="< 15.1.2", title="x 25.1 y"))))

    def test_negated_in_the_wild_is_not_exploited(self):
        self.assertFalse(ss.exploited_in_wild("There are no reports of exploitation in the wild."))
        self.assertTrue(ss.exploited_in_wild("Google is aware that an exploit for CVE-2026-1 exists in the wild."))

    def test_corrupt_state_raises_instead_of_resetting(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "posted-websec.json"
            bad.write_text("{not json", encoding="utf-8")
            with mock.patch.object(w, "STATE", bad):
                with self.assertRaises(w.RunError):
                    w.load_state()

    def test_failed_slack_post_leaves_state_unwritten(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "posted-websec.json"
            with mock.patch.object(w, "STATE", state), mock.patch.object(w.slack, "post", side_effect=RuntimeError("slack down")):
                with redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
                    w.run(dry_run=False, mock_file=str(FIXTURE), now=NOW)
            self.assertFalse(state.exists())

    def tearDown(self):
        os.environ.pop("LLM_PROVIDER", None)


if __name__ == "__main__":
    unittest.main()
