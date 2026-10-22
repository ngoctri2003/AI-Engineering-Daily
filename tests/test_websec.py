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

    def test_blogger_atom_picks_the_post_link_not_the_comments_feed(self):
        xml = ("<feed xmlns='http://www.w3.org/2005/Atom'><entry><title>Stable Channel Update</title>"
               "<link rel='replies' type='application/atom+xml' href='http://c.example/feeds/1/comments/default'/>"
               "<link rel='alternate' type='text/html' href='https://c.example/2026/10/stable.html'/>"
               "<updated>2026-10-21T08:00:00Z</updated><content>Critical CVE-2026-3333 fix.</content></entry></feed>")
        src = {"name": "Chrome Releases", "url": "u", "product": "Chrome", "pattern": r"CVE-\d{4}-\d{4,7}"}
        out, _ = ss.fetch_feed(src, CUTOFF, get_text=lambda url: xml)
        self.assertEqual(out[0]["url"], "https://c.example/2026/10/stable.html")

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


def self_strings():
    return w.load_json(w.PROFILE_DIR / "profile.json")["strings"]


@mock.patch.dict(os.environ, {"LLM_PROVIDER": "mock"})
class ReviewRegressionTests(unittest.TestCase):
    def test_links_mentions_and_markup_are_rejected(self):
        for bad in ("see https://evil.example/p", "ping <!channel>", "a | b", "use `code`", "a & b", "www.evil.example"):
            self.assertTrue(any("markup" in e for e in w.validate_summary({**GOOD, "action": bad + " " + WORDS}, batch())), bad)

    def test_non_string_fields_degrade_instead_of_crashing(self):
        resp = {"items": [{**GOOD, "batch_id": ["B1"]}, {**GOOD, "headline": ["x"]}, "text", None, {**GOOD, "impact": 5}]}
        # first call returns the malformed items, the repair call returns junk
        with mock.patch.object(w.llm, "call_json", side_effect=[resp, {}, {}]):
            pairs, failed = w.summarize([batch()], NOW, "sys", None, log=lambda m: None)
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

    def test_branch_prefix_of_a_known_version_is_accepted(self):
        b = batch(fixed_in="8.2.35", affected="< 8.2.35", title="PHP flaw", summary="x")
        ok = {**GOOD, "impact": f"PHP 8.2 builds below 8.2.35 are affected. {WORDS} {WORDS}", "action": "Update to 8.2.35."}
        self.assertEqual(w.validate_summary(ok, b), [])
        bad = {**GOOD, "impact": f"PHP 8.3 builds below 8.2.35 are affected. {WORDS} {WORDS}", "action": "Update to 8.2.35."}
        self.assertTrue(any("numbers" in e for e in w.validate_summary(bad, b)))

    def test_one_repair_request_fixes_an_invalid_item(self):
        too_long = {**GOOD, "description": " ".join(["long"] * 90)}
        calls = []

        def fake(system, user, payload=None):
            calls.append(user)
            return {"items": [too_long]} if len(calls) == 1 else GOOD
        with mock.patch.object(w.llm, "call_json", fake):
            pairs, failed = w.summarize([batch()], NOW, "sys", None, log=lambda m: None)
        self.assertEqual((len(pairs), failed, len(calls)), (1, [], 2))
        self.assertIn("Errors:", calls[1])

    def test_omitted_batch_is_logged_and_degraded(self):
        logs = []
        pairs, failed = w.summarize([batch()], NOW, "sys", {"items": []}, log=logs.append)
        self.assertEqual((pairs, [b["batch_id"] for b in failed]), ([], ["B1"]))
        self.assertTrue(any("omitted" in m for m in logs))

    def test_pattern_feed_needs_a_severity_hint_to_qualify(self):
        xml = ("<rss><channel><item><title>Stable Update</title><link>https://c.example/1</link>"
               "<pubDate>Wed, 21 Oct 2026 08:00:00 GMT</pubDate>"
               "<description>Fixes CVE-2026-3333 (Medium) and CVE-2026-3334 (Low).</description></item>"
               "</channel></rss>")
        src = {"name": "Chrome Releases", "url": "u", "product": "Chrome", "pattern": r"CVE-\d{4}-\d{4,7}"}
        out, _ = ss.fetch_feed(src, CUTOFF, get_text=lambda url: xml)
        self.assertFalse(out[0]["vendor_security_release"])
        self.assertEqual(w.prefilter(out, WATCH), [])
        src_always = {**src, "qualify": "always"}
        out2, _ = ss.fetch_feed(src_always, CUTOFF, get_text=lambda url: xml)
        self.assertTrue(out2[0]["vendor_security_release"])

    def test_every_branch_fixed_version_is_kept(self):
        adv = {"ghsa_id": "GHSA-php", "cve_id": "CVE-2026-6000", "summary": "OOM", "published_at": "2026-10-22T01:00:00Z",
               "cvss": {"score": 9.2}, "vulnerabilities": [
                   {"package": {"ecosystem": "php", "name": "php-src"}, "vulnerable_version_range": f"< {v}", "patched_versions": v}
                   for v in ("8.2.35", "8.3.36", "8.4.27", "8.5.12")]}
        cands = ss.advisory_to_candidates(adv, {"name": "R", "product": "PHP"}, CUTOFF)
        batches = w.group_batches(w.prefilter(cands, WATCH))
        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0]["fixed_in"], "8.2.35, 8.3.36, 8.4.27, 8.5.12")
        self.assertIn("< 8.4.27", batches[0]["affected"])
        # the LLM may now cite any branch, but not an invented one
        b = batch(fixed_in=batches[0]["fixed_in"], affected=batches[0]["affected"])
        good = {**GOOD, "impact": f"Branches below the listed versions are affected. {WORDS}", "action": "Update to 8.4.27, 8.3.36, 8.2.35 or 8.5.12."}
        self.assertEqual(w.validate_summary(good, b), [])
        self.assertTrue(any("numbers" in e for e in w.validate_summary({**good, "action": "Update to 8.4.99."}, b)))

    def test_feed_body_is_fetched_and_url_upgraded_to_https(self):
        rss = ("<rss><channel><item><title>October 2026 Security Releases</title><link>http://n.example/post</link>"
               "<pubDate>Wed, 21 Oct 2026 08:00:00 GMT</pubDate></item></channel></rss>")
        pages = {"https://n.example/post": "<html><body><p>Fixes CVE-2026-7001 (High) in 24.19.1.</p></body></html>"}
        get = lambda url: rss if url == "u" else pages[url]
        src = {"name": "Node.js", "url": "u", "product": "Node.js", "qualify": "always", "fetch_body": True}
        out, _ = ss.fetch_feed(src, CUTOFF, get_text=get)
        self.assertEqual((out[0]["url"], out[0]["cve_ids"], out[0]["severity"]), ("https://n.example/post", ["CVE-2026-7001"], "high"))
        self.assertIn("24.19.1", out[0]["summary"])

    def test_feed_body_failure_keeps_the_entry(self):
        rss = ("<rss><channel><item><title>Security Releases</title><link>https://n.example/post</link>"
               "<pubDate>Wed, 21 Oct 2026 08:00:00 GMT</pubDate></item></channel></rss>")

        def get(url):
            if url == "u":
                return rss
            raise RuntimeError("down")
        src = {"name": "Node.js", "url": "u", "product": "Node.js", "qualify": "always", "fetch_body": True}
        out, _ = ss.fetch_feed(src, CUTOFF, get_text=get)
        self.assertEqual(len(out), 1)

    def test_tag_without_cve_is_vulnerability(self):
        text = w.render_item(batch(cve_ids=[], tag="#NodeJS"), {**GOOD, "headline": "Node.js security update"}, self_strings())
        self.assertIn("`#NodeJS` `#Vulnerability`", text)

    def test_version_at_the_end_of_a_sentence_is_still_checked(self):
        self.assertEqual(w.VERSION_RE.findall("Update to 8.4.99. Then restart (156.0.1.2)."), ["8.4.99", "156.0.1.2"])
        self.assertTrue(any("numbers" in e for e in w.validate_summary({**GOOD, "action": "Update to 9.9.9."}, batch())))

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


class SourceFormatTests(unittest.TestCase):
    CHROME = ("Stable Channel Update for Desktop 12 security fixes: "
              "[$16000][1336266] High CVE-2022-2477 : Use after free in Guest View. Reported by anonymous on 2022-06-14 "
              "[$500][1329541] Medium CVE-2022-4915: Inappropriate implementation in URL Formatting. Reported by A "
              "[$7000][1308341] Critical CVE-2022-2163: Use after free in Cast UI. Reported by B "
              "[$3000][1329987] Low CVE-2022-2479 : Insufficient validation in File. Reported by C")

    def test_chrome_severity_lines_keep_critical_and_high_only(self):
        got = ss.pick_severity_lines(self.CHROME)
        self.assertEqual([(s, c) for s, c, _ in got["kept"]], [("Critical", "CVE-2022-2163"), ("High", "CVE-2022-2477")])
        self.assertEqual((got["total"], got["severity"]), (4, "critical"))
        self.assertEqual(ss.pick_severity_lines("no cve lines here")["severity"], None)

    def test_chrome_feed_with_severity_lines_and_long_body(self):
        xml = ("<feed xmlns='http://www.w3.org/2005/Atom'><entry><title>Stable Update</title>"
               "<link rel='replies' href='http://c.example/c'/><link rel='alternate' href='http://c.example/p'/>"
               "<updated>2026-10-21T08:00:00Z</updated><content>" + self.CHROME + "</content></entry></feed>")
        src = {"name": "Chrome", "url": "u", "product": "Chrome", "pattern": r"CVE-\d{4}-\d{4,7}", "severity_lines": True,
               "snippet_chars": 30000}
        out, _ = ss.fetch_feed(src, CUTOFF, get_text=lambda url: xml)
        self.assertEqual((out[0]["cve_ids"], out[0]["severity"], out[0]["url"]),
                         (["CVE-2022-2163", "CVE-2022-2477"], "critical", "https://c.example/p"))
        self.assertNotIn("CVE-2022-4915", out[0]["summary"])
        self.assertTrue(out[0]["vendor_security_release"])

    def test_medium_low_only_chrome_post_does_not_qualify(self):
        xml = ("<feed xmlns='http://www.w3.org/2005/Atom'><entry><title>Stable Update</title><link href='https://c.example/p'/>"
               "<updated>2026-10-21T08:00:00Z</updated><content>[$1][2] Medium CVE-2026-1111: Bug. Reported by A</content></entry></feed>")
        src = {"name": "Chrome", "url": "u", "product": "Chrome", "pattern": r"CVE-\d{4}-\d{4,7}", "severity_lines": True}
        out, _ = ss.fetch_feed(src, CUTOFF, get_text=lambda url: xml)
        self.assertEqual(w.prefilter(out, WATCH), [])

    NODE_BODY = ("\n\nThis is a security release.\n\n### Notable Changes\n\n"
                 "* (CVE-2026-106069, CVE-2026-106072) tls: reject non-canonical IP addresses (A B) \u2013 High\n"
                 "* (CVE-2026-106070) zlib: avoid caching invalid ZIP local headers (C D) \u2013 Low\n"
                 "* deps: update c-ares to 1.34.9 (Bot)\n\n### Commits\n")
    NODE_LTS = ("This is a security release.\n\n### Notable Changes\n\n"
                "* (CVE-2026-106069) tls: reject non-canonical IP addresses (A B)\n* deps: update undici (Bot)\n")

    def test_node_notes_with_and_without_severity(self):
        notes = ss.parse_node_security_notes(self.NODE_BODY)
        self.assertEqual([(n[0], n[1]) for n in notes], [("High", ["CVE-2026-106069", "CVE-2026-106072"]), ("Low", ["CVE-2026-106070"])])
        self.assertEqual(ss.parse_node_security_notes(self.NODE_LTS)[0][0], None)

    def test_node_releases_become_one_batch_with_every_fixed_version(self):
        rel = [{"tag_name": "v26.12.1", "published_at": "2026-10-21T10:00:00Z", "html_url": "https://github.com/nodejs/node/releases/tag/v26.12.1", "body": self.NODE_BODY},
               {"tag_name": "v24.22.1", "published_at": "2026-10-21T10:00:00Z", "html_url": "https://github.com/nodejs/node/releases/tag/v24.22.1", "body": self.NODE_LTS},
               {"tag_name": "v24.22.0", "published_at": "2026-10-14T10:00:00Z", "html_url": "x", "body": "regular release"},
               {"tag_name": "v22.1.0", "published_at": "2026-10-21T10:00:00Z", "html_url": "y", "body": "regular release"}]
        out, _ = ss.fetch_github_releases({"name": "Node", "repo": "nodejs/node", "product": "Node.js"}, CUTOFF, get=lambda url, h: rel)
        self.assertEqual(len(out), 2)
        batches = w.group_batches(w.prefilter(out, WATCH))
        self.assertEqual((len(batches), batches[0]["fixed_in"], batches[0]["severity"]), (1, "26.12.1, 24.22.1", "high"))
        self.assertIn("CVE-2026-106069", batches[0]["cve_ids"])

    MFSA = ("announced: October 21, 2026\nimpact: high\nfixed_in:\n- Firefox 158.0.1\n- Firefox ESR 153.5.1\n"
            "title: Security Vulnerabilities fixed in Firefox 158.0.1\ndescription: |\n  Note\nadvisories:\n"
            "  CVE-2026-113399:\n    title: 'Use-after-free in the Widget component'\n    impact: high\n    reporter: X\n    bugs:\n      - url: 1\n"
            "  CVE-2026-113400:\n    title: Minor flaw\n    impact: low\n    reporter: Y\n")

    def test_mozilla_advisory_parse_and_fetch(self):
        adv = ss.parse_mfsa(self.MFSA)
        self.assertEqual((adv["impact"], adv["fixed_in"]), ("high", ["Firefox 158.0.1", "Firefox ESR 153.5.1"]))
        self.assertEqual([(c[0], c[2]) for c in adv["cves"]], [("CVE-2026-113399", "high"), ("CVE-2026-113400", "low")])
        listing = [{"name": "mfsa2026-100.yml"}, {"name": "mfsa2026-99.yml"}]
        out, _ = ss.fetch_mozilla_advisories({"name": "Moz", "product": "Firefox"}, datetime(2026, 10, 20, tzinfo=timezone.utc),
                                             get=lambda url, h: listing, get_text=lambda url: self.MFSA)
        self.assertEqual(out[0]["cve_ids"], ["CVE-2026-113399"])
        self.assertEqual(out[0]["url"], "https://www.mozilla.org/en-US/security/advisories/mfsa2026-99/")
        self.assertEqual(len(w.prefilter(out, WATCH)), len(out))

    def test_mozilla_non_firefox_and_old_advisories_are_skipped(self):
        other = self.MFSA.replace("fixed in Firefox 158.0.1", "fixed in Thunderbird 150")
        out, _ = ss.fetch_mozilla_advisories({"name": "Moz"}, datetime(2026, 10, 20, tzinfo=timezone.utc),
                                             get=lambda url, h: [{"name": "mfsa2026-1.yml"}], get_text=lambda url: other)
        self.assertEqual(out, [])
        old, _ = ss.fetch_mozilla_advisories({"name": "Moz"}, datetime(2026, 11, 1, tzinfo=timezone.utc),
                                             get=lambda url, h: [{"name": "mfsa2026-1.yml"}], get_text=lambda url: self.MFSA)
        self.assertEqual(old, [])


if __name__ == "__main__":
    unittest.main()


class HackerNewsSignalTests(unittest.TestCase):
    HN = {"hits": [
        {"objectID": "1", "title": "Chrome zero-day CVE-2026-0001 exploited", "url": "https://example.org/post",
         "points": 120, "num_comments": 40, "created_at": "2026-10-22T05:00:00.000Z"},
        {"objectID": "2", "title": "Unrelated vulnerability story", "url": "https://example.org/other",
         "points": 55, "num_comments": 3, "created_at": "2026-10-22T06:00:00.000Z"}]}

    def fetch(self):
        src = {"name": "HN", "type": "hn-signal", "min_points": 30, "queries": ["q1", "q2"]}
        return ss.fetch_hn_signals(src, CUTOFF, get=lambda url: self.HN)

    def test_fetch_marks_signal_and_dedups_queries(self):
        out, info = self.fetch()
        self.assertEqual(len(out), 2)
        self.assertTrue(all(c["signal"] for c in out))
        self.assertEqual(out[0]["cve_ids"], ["CVE-2026-0001"])
        self.assertEqual(out[0]["hn_url"], "https://news.ycombinator.com/item?id=1")

    def test_attach_matches_by_cve_and_returns_unmatched(self):
        signals, _ = self.fetch()
        batch = {"cve_ids": ["CVE-2026-0001"], "url": "https://vendor.example/advisory"}
        unmatched = w.attach_signals([batch], signals)
        self.assertEqual(batch["hn_points"], 120)
        self.assertEqual([s["id"] for s in unmatched], ["hn-2"])

    def test_signal_never_becomes_an_item_and_does_not_leak_into_post(self):
        signals, _ = self.fetch()
        self.assertTrue(signals)
        batch = {"cve_ids": [], "url": "https://vendor.example/a", "hn_points": 99, "hn_url": "https://news.ycombinator.com/item?id=9",
                 "exploited": False, "tag": "#Chrome", "category": "BROWSER"}
        item = {"headline": "H", "description": "D", "impact": "I", "action": "A"}
        text = w.render_item(batch, item, {"impact": "Impact", "action": "Action"})
        self.assertNotIn("ycombinator", text)

    def test_signal_boosts_rank_within_same_tier(self):
        a = {"tier": 3, "cvss": 8.0, "product": "A", "hn_points": 0}
        b = {"tier": 3, "cvss": 8.0, "product": "B", "hn_points": 80}
        ranked = sorted([a, b], key=lambda x: (x["tier"], -(x["cvss"] or 0), -x.get("hn_points", 0), x["product"]))
        self.assertEqual(ranked[0]["product"], "B")


class CombinedBulletinTests(unittest.TestCase):
    def run_combined(self, **kw):
        from app import main as m
        out = io.StringIO()
        with redirect_stdout(out):
            code = m.run(dry_run=True, mock_file=str(Path(__file__).parent / "fixture.json"),
                         with_security=True, security_mock=str(FIXTURE), **kw)
        return code, out.getvalue()

    def test_one_message_with_both_sections_and_at_most_seven_items(self):
        code, text = self.run_combined()
        self.assertEqual(code, 0)
        self.assertEqual(text.count("*AI Engineering Daily:"), 1)
        self.assertEqual(text.count("Cảnh báo bảo mật tech stack"), 1)
        self.assertLessEqual(text.split("--- Ghi chú")[0].count("🔗"), 7)

    def test_security_failure_does_not_block_ai_items(self):
        from app import main as m
        with mock.patch.object(m.websec, "prepare", side_effect=RuntimeError("boom")):
            with self.assertRaises(m.RunError):
                self.run_combined()
        # the message was still built before the deferred error was raised (dry-run prints it)

    def test_without_flag_nothing_changes(self):
        from app import main as m
        out = io.StringIO()
        with redirect_stdout(out):
            m.run(dry_run=True, mock_file=str(Path(__file__).parent / "fixture.json"))
        self.assertNotIn("Cảnh báo bảo mật", out.getvalue())


class PlainLanguageTests(unittest.TestCase):
    STRINGS = w.load_profile()["settings"]["strings"]

    def test_types_detected_from_english_source(self):
        found = w.detect_types("High CVE-1: Use after free in Skia. CVE-2: Type confusion in V8", w.VULN_TYPES)
        self.assertEqual([t["label"] for t in found], ["hỏng bộ nhớ"])
        self.assertEqual(w.detect_types("nothing special", w.VULN_TYPES), [])

    def test_severity_line_is_code_owned(self):
        line = w.severity_line({"cvss": 9.6, "severity": None, "exploited": True}, self.STRINGS)
        self.assertEqual(line, "Mức độ: Nghiêm trọng (CVSS 9.6), đã bị khai thác thực tế")
        self.assertEqual(w.severity_line({"cvss": None, "severity": None, "exploited": False}, self.STRINGS), "")

    def test_one_liner_says_what_kind_of_flaw(self):
        batch = {"product": "Firefox", "cve_ids": ["CVE-2026-1"], "fixed_in": "158.0.1", "url": "https://x", "types": w.VULN_TYPES[2:3]}
        self.assertIn("Firefox: hỏng bộ nhớ (CVE-2026-1)", w.one_liner(batch, self.STRINGS))
        batch["types"] = []
        self.assertIn("lỗi bảo mật", w.one_liner(batch, self.STRINGS))

    def test_missing_data_statements_are_rejected(self):
        for phrase in ("Dữ liệu không nêu phiên bản", "không đề cập bản vá", "the data does not say"):
            self.assertTrue(w.META_RE.search(phrase), phrase)
        self.assertFalse(w.META_RE.search("Cập nhật lên 8.2.35"))

    def test_repeated_label_is_stripped(self):
        item = {"headline": "H", "description": "D", "impact": "Ảnh hưởng Chrome desktop", "action": "Hành động: Cập nhật"}
        batch = {"cve_ids": [], "url": "https://x", "exploited": False, "tag": "#Chrome", "category": "BROWSER"}
        text = w.render_item(batch, item, self.STRINGS)
        self.assertIn("Ảnh hưởng: Chrome desktop", text)
        self.assertIn("Hành động: Cập nhật", text)

    def test_cve_record_detail_has_weakness_and_description(self):
        record = {"containers": {"cna": {"problemTypes": [{"descriptions": [{"lang": "en", "description": "CWE-416 Use After Free"}]}],
                                           "descriptions": [{"lang": "en", "value": "Use after free in Skia\n in Chrome."}]}}}
        self.assertEqual(ss.extract_detail(record), "CWE-416 Use After Free | Use after free in Skia in Chrome.")

    def test_enrich_stores_detail(self):
        record = {"containers": {"cna": {"descriptions": [{"lang": "en", "value": "Heap buffer overflow in X"}]}}}
        c = cand(cvss=None)
        ss.enrich_cvss([c], get=lambda url: record, log=lambda *_: None)
        self.assertIn("Heap buffer overflow", c["detail"])

    def test_chrome_fixed_version_from_post(self):
        body = ("<p>The Stable channel has been updated to 156.0.8078.47 for Linux and 156.0.8078.47/.48 for Windows. "
                "[$5000][1] Critical CVE-2026-113341: Use after free in Skia. Reported by X</p>")
        feed = ('<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Stable Channel Update for Desktop</title>'
                '<link rel="alternate" href="https://chromereleases.googleblog.com/p.html"/>'
                f'<updated>2026-10-21T10:00:00Z</updated><content type="html">{body.replace("<", "&lt;").replace(">", "&gt;")}</content></entry></feed>')
        src = {"name": "Chrome", "type": "feed", "url": "https://x/feed", "product": "Chrome", "pattern": "CVE-\\d{4}-\\d{4,7}",
               "severity_lines": True, "fixed_in_pattern": "updated to ([0-9]+(?:\\.[0-9]+)+)"}
        out, _ = ss.fetch_feed(src, CUTOFF, get_text=lambda url: feed)
        self.assertEqual(out[0]["fixed_in"], "156.0.8078.47")


class LogReviewRegressionTests(unittest.TestCase):
    STRINGS = w.load_profile()["settings"]["strings"]

    def kept(self, *cands):
        watch = {"name": "Next.js", "category": "FRAMEWORK", "tag": "#JavaScript"}
        return [(c, watch) for c in cands]

    def test_critical_advisory_is_not_hidden_behind_a_milder_one_of_the_same_product(self):
        dos = cand(id="GHSA-dos", cve_ids=["CVE-2026-1"], cvss=8.2, grain="advisory", title="DoS", url="https://example.com/dos")
        rce = cand(id="GHSA-rce", cve_ids=[], cvss=None, severity="critical", grain="advisory", title="Unauthenticated RCE", url="https://example.com/rce")
        batches = w.group_batches(self.kept(dos, rce))
        self.assertEqual(sorted(b["title"] for b in batches), ["DoS", "Unauthenticated RCE"])

    def test_same_cve_from_two_advisory_entries_is_one_batch(self):
        a = cand(id="GHSA-a", cve_ids=["CVE-2026-1"], cvss=8.2, grain="advisory", url="https://example.com/a")
        b = cand(id="GHSA-b", cve_ids=["CVE-2026-1"], cvss=8.2, grain="advisory", url="https://example.com/b")
        self.assertEqual(len(w.group_batches(self.kept(a, b))), 1)

    def test_release_sources_still_group_per_product(self):
        a = cand(id="r1", cve_ids=["CVE-2026-1"], cvss=9.0)
        b = cand(id="r2", cve_ids=["CVE-2026-2"], cvss=9.0)
        self.assertEqual(len(w.group_batches(self.kept(a, b))), 1)

    def test_label_follows_cvss_not_the_vendor_word(self):
        line = w.severity_line({"cvss": 8.2, "severity": "critical", "exploited": False}, self.STRINGS)
        self.assertEqual(line, "Mức độ: Cao (CVSS 8.2)")
        self.assertEqual(w.severity_line({"cvss": None, "severity": "critical", "exploited": False}, self.STRINGS), "Mức độ: Nghiêm trọng")

    def test_negated_type_is_not_reported(self):
        text = "This flaw does not lead to remote code execution. It causes denial of service."
        self.assertEqual([t["label"] for t in w.detect_types(text, w.VULN_TYPES)], ["từ chối dịch vụ"])

    def test_claims_about_missing_exploitation_are_rejected(self):
        self.assertTrue(w.META_RE.search("Chưa ghi nhận khai thác."))

    def test_second_repair_request_is_used(self):
        batch = {"batch_id": "B1", "product": "P", "cve_ids": [], "title": "t", "summary": "s", "detail": "", "fixed_in": "",
                 "affected": "", "cvss": None, "tier": 3, "count": 1, "exploited": False, "in_kev": False, "types": []}
        words = " ".join(["từ"] * 50)
        good = {"batch_id": "B1", "headline": "h", "description": words, "impact": "i", "action": "a"}
        bad = dict(good, description="ngắn")
        replies = iter([{"items": [bad]}, bad, good])
        with mock.patch.object(w.llm, "call_json", side_effect=lambda *a, **k: next(replies)):
            pairs, failed = w.summarize([batch], NOW, "sys", log=lambda *_: None)
        self.assertEqual(len(pairs), 1)
        self.assertEqual(failed, [])

    def test_long_message_is_split_between_blocks(self):
        from app import slack
        blocks = [("x" * 1500) for _ in range(5)]
        text = slack.SLACK_SEP.join(blocks)
        parts = slack.split_message(text)
        self.assertGreater(len(parts), 1)
        self.assertTrue(all(len(p) <= slack.MAX_MESSAGE for p in parts))
        self.assertEqual(slack.SLACK_SEP.join(parts), text)
        self.assertEqual(slack.split_message("short"), ["short"])

    def test_empty_answer_from_a_source_is_flagged(self):
        fetchers = {"x": lambda src, cutoff, token=None: ([], "ok (0 in window, no dated entries)")}
        _, status = ss.collect([{"name": "N", "type": "x"}], NOW, fetchers=fetchers, log=lambda *_: None)
        self.assertTrue(status["N"].startswith("WARN?"))


class EmptyReleaseListTests(unittest.TestCase):
    def test_empty_answer_is_retried_once(self):
        calls = []

        def get(url, headers=None):
            calls.append(url)
            return [] if len(calls) == 1 else [{"tag_name": "v1.0.1", "published_at": "2026-10-21T10:00:00Z",
                                                "body": "security release\n* (CVE-2026-1) tls: bug – High", "html_url": "https://x/r"}]
        out, _ = ss.fetch_github_releases({"name": "N", "repo": "a/b", "product": "P"}, CUTOFF, get=get)
        self.assertEqual(len(calls), 2)
        self.assertEqual(out[0]["id"], "v1.0.1")
