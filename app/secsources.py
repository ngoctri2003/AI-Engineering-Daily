"""Fetchers that normalize security data into candidate dicts. Stdlib only.

Every fetcher returns (candidates, info) where info is a short status string that
includes the newest entry date, so a stale source is visible in the run log.
"""
import json
import os
import re
import urllib.request
from datetime import datetime, timedelta, timezone

from . import sources as news_sources

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
GITHUB_API = "https://api.github.com"
CVELIST_RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
MAX_SUMMARY = 1200
MAX_ENRICH = 40
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def get_json(url, headers=None, timeout=25):
    req = urllib.request.Request(url, headers={**news_sources.UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def github_headers(token=None):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def make_candidate(**kw):
    base = {
        "id": "", "source": "", "title": "", "url": "", "published_at": None, "summary": "",
        "cve_ids": [], "vendor": "", "product": "", "source_product": "", "category": None,
        "ecosystem": "", "package": "", "cvss": None, "severity": None,
        "in_kev": False, "exploited": False, "vendor_security_release": False,
        "fixed_in": "", "affected": "",
    }
    base.update(kw)
    return base


def _date(value):
    d = news_sources.parse_date(value)
    return d.astimezone(timezone.utc) if d else None


def fetch_kev(src, cutoff, get=get_json, **_):
    """CISA Known Exploited Vulnerabilities (JSON). dateAdded has day precision only."""
    data = get(src["url"])
    out, newest = [], None
    for v in data.get("vulnerabilities", []):
        added = _date(v.get("dateAdded"))
        if added is None:
            continue
        newest = max(newest, added) if newest else added
        if added.date() < cutoff.date():
            continue
        cve = v.get("cveID", "")
        out.append(make_candidate(
            id=cve, source=src["name"], title=v.get("vulnerabilityName") or cve,
            url=f"https://www.cve.org/CVERecord?id={cve}", published_at=added.isoformat(),
            summary=" ".join(x for x in (v.get("shortDescription"), v.get("requiredAction")) if x)[:MAX_SUMMARY],
            cve_ids=[cve] if cve else [], vendor=v.get("vendorProject", ""), product=v.get("product", ""),
            in_kev=True, exploited=True))
    return out, _info(len(out), newest)


def _patched(vuln):
    for key in ("first_patched_version", "patched_versions"):
        val = vuln.get(key)
        if isinstance(val, dict):
            val = val.get("identifier")
        if val:
            return str(val)
    return ""


def advisory_to_candidates(adv, src, cutoff):
    """One candidate per vulnerable package of a GitHub advisory (global or repository advisory)."""
    published = _date(adv.get("published_at"))
    if published is None or published < cutoff:
        return []
    ghsa = adv.get("ghsa_id", "")
    cve = adv.get("cve_id") or ""
    score = (adv.get("cvss") or {}).get("score")
    text = " ".join(x for x in (adv.get("summary"), adv.get("description")) if x)
    out = []
    for vuln in (adv.get("vulnerabilities") or [{}])[:10]:
        pkg = vuln.get("package") or {}
        out.append(make_candidate(
            id=cve or ghsa, source=src["name"], title=adv.get("summary") or ghsa,
            url=adv.get("html_url") or f"https://github.com/advisories/{ghsa}",
            published_at=published.isoformat(), summary=text[:MAX_SUMMARY],
            cve_ids=[cve] if cve else [], source_product=src.get("product", ""),
            ecosystem=(pkg.get("ecosystem") or src.get("ecosystem") or "").lower(),
            package=(pkg.get("name") or "").lower(),
            cvss=float(score) if isinstance(score, (int, float)) and score > 0 else None,
            severity=(adv.get("severity") or None), fixed_in=_patched(vuln),
            affected=vuln.get("vulnerable_version_range") or ""))
    return out


def fetch_ghsa(src, cutoff, get=get_json, token=None, **_):
    """Global reviewed advisories for one ecosystem; the date window is applied in code."""
    url = (f"{GITHUB_API}/advisories?type=reviewed&ecosystem={src['ecosystem']}"
           "&sort=published&direction=desc&per_page=100")
    advisories = get(url, github_headers(token))
    out = [c for adv in advisories for c in advisory_to_candidates(adv, src, cutoff)]
    newest = max((_date(a.get("published_at")) for a in advisories if _date(a.get("published_at"))), default=None)
    return out, _info(len(out), newest)


def fetch_repo_advisories(src, cutoff, get=get_json, token=None, **_):
    """Published security advisories of one repository (often earlier than the global database)."""
    url = f"{GITHUB_API}/repos/{src['repo']}/security-advisories?state=published&per_page=30"
    advisories = get(url, github_headers(token))
    out = [c for adv in advisories for c in advisory_to_candidates(adv, src, cutoff)]
    newest = max((_date(a.get("published_at")) for a in advisories if _date(a.get("published_at"))), default=None)
    return out, _info(len(out), newest)


def exploited_in_wild(text):
    """True when the text says exploitation happens in the wild; a negation shortly before the phrase cancels it."""
    for m in re.finditer(r"in the wild", text, re.I):
        before = text[max(0, m.start() - 60):m.start()]
        if not re.search(r"\b(no|not|without|never)\b", before, re.I):
            return True
    return False


def fetch_feed(src, cutoff, get_text=news_sources.http_get, **_):
    """Vendor RSS/Atom feed. Only entries that qualify (config 'qualify') become candidates."""
    entries = news_sources.parse_feed(get_text(src["url"]), {"name": src["name"], "priority": "P0"}, EPOCH)
    newest = max((_date(e["published_at"]) for e in entries), default=None)
    pattern = re.compile(src["pattern"], re.I) if src.get("pattern") else None
    out = []
    for e in entries:
        published = _date(e["published_at"])
        if published is None or published < cutoff:
            continue
        text = f"{e['title']} {e['snippet']}"
        if src.get("qualify") != "always" and not (pattern and pattern.search(text)):
            continue
        out.append(make_candidate(
            id=e["url"], source=src["name"], title=e["title"], url=e["url"],
            published_at=published.isoformat(), summary=e["snippet"][:MAX_SUMMARY],
            cve_ids=sorted(set(CVE_RE.findall(text))), source_product=src.get("product", ""),
            exploited=exploited_in_wild(text),
            severity="critical" if re.search(r"\bcritical\b", text, re.I) else (
                "high" if re.search(r"\bhigh\b", text, re.I) else None),
            vendor_security_release=True))
    return out, _info(len(out), newest)


FETCHERS = {"kev": fetch_kev, "ghsa": fetch_ghsa, "repo-advisories": fetch_repo_advisories, "feed": fetch_feed}


def _info(count, newest):
    return f"ok ({count} in window, newest entry {newest:%Y-%m-%d})" if newest else f"ok ({count} in window, no dated entries)"


def collect(sources, now, token=None, window_hours=48, log=print, fetchers=None):
    """Run every source; one failing source never breaks the run."""
    fetchers = fetchers or FETCHERS
    cutoff = now - timedelta(hours=window_hours)
    cands, status = [], {}
    for src in sources:
        try:
            fetcher = fetchers[src["type"]]
            got, info = fetcher(src, cutoff, token=token)
            stale_days = src.get("stale_after_days")
            m = re.search(r"newest entry (\d{4}-\d{2}-\d{2})", info)
            if stale_days and m and (now.date() - datetime.fromisoformat(m.group(1)).date()).days > stale_days:
                info = f"STALE? {info} (older than {stale_days} days)"
            status[src["name"]] = info
            cands.extend(got)
        except Exception as ex:
            status[src["name"]] = f"ERROR: {type(ex).__name__}: {ex}"
    for name, info in status.items():
        log(f"[source] {name}: {info}")
    return cands, status


def cvelist_url(cve_id):
    _, year, num = cve_id.split("-")
    return f"{CVELIST_RAW}/{year}/{int(num) // 1000}xxx/{cve_id}.json"


def extract_cvss(record):
    """Highest base score among CNA and ADP metrics (CVSS 3.0, 3.1, 4.0); None when absent."""
    containers = record.get("containers") or {}
    blocks = [containers.get("cna") or {}] + list(containers.get("adp") or [])
    scores = []
    for block in blocks:
        for metric in block.get("metrics") or []:
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                score = (metric.get(key) or {}).get("baseScore")
                if isinstance(score, (int, float)):
                    scores.append(float(score))
    return max(scores) if scores else None


def enrich_cvss(cands, get=get_json, log=print, limit=MAX_ENRICH, per_candidate=5):
    """Fill missing CVSS from cvelistV5 (highest score across the candidate's CVEs).

    A failed lookup leaves the score empty, never guessed. Lookups are cached per CVE ID.
    Brand-new CVEs may not be in cvelistV5 yet (HTTP 404); they pass the filter only through other signals.
    """
    cache, lookups = {}, 0
    for c in cands:
        if c["cvss"] is not None or not c["cve_ids"]:
            continue
        scores = []
        for cve in c["cve_ids"][:per_candidate]:
            if cve not in cache:
                if lookups >= limit:
                    log(f"[enrich] limit {limit} reached, remaining CVEs keep an empty score")
                    break
                lookups += 1
                try:
                    cache[cve] = extract_cvss(get(cvelist_url(cve)))
                except Exception as ex:
                    cache[cve] = None
                    log(f"[enrich] {cve}: {type(ex).__name__}: {ex}")
            if cache.get(cve) is not None:
                scores.append(cache[cve])
        c["cvss"] = max(scores) if scores else None
    return cands
