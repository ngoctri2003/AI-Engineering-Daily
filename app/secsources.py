"""Fetchers that normalize security data into candidate dicts. Stdlib only.

Every fetcher returns (candidates, info) where info is a short status string that
includes the newest entry date, so a stale source is visible in the run log.
"""
import json
import os
import re
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from . import sources as news_sources

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
GITHUB_API = "https://api.github.com"
CVELIST_RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
MAX_SUMMARY = 3000
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
        "signal": False, "hn_points": 0, "hn_url": "", "detail": "", "grain": "product",
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
            grain="advisory" if src.get("type") == "ghsa" else "product",
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


SEVERITY_LINE_RE = re.compile(r"\b(Critical|High|Medium|Low)\s+(CVE-\d{4}-\d{4,7})\s*:\s*([^\n]{0,160}?)(?:\.\s+Reported by|\.?\s*$|\.\s+\[)", re.M)
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def pick_severity_lines(text):
    """Chrome-style lines '[bounty][bug] High CVE-2026-1: description. Reported by ...'.
    Only Critical and High fixes are kept (Chrome High is about CVSS 8.8); counts of the rest are kept for context."""
    found, seen = [], set()
    for sev, cve, desc in SEVERITY_LINE_RE.findall(text):
        if cve not in seen:
            seen.add(cve)
            found.append((sev, cve, desc.strip()))
    kept = sorted((x for x in found if x[0] in ("Critical", "High")), key=lambda x: SEVERITY_ORDER[x[0]])
    severity = "critical" if any(x[0] == "Critical" for x in kept) else ("high" if kept else None)
    return {"kept": kept, "total": len(found), "severity": severity}


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
        url = e["url"].replace("http://", "https://", 1)
        snippet = e["snippet"]
        if src.get("fetch_body"):
            # Some feeds carry only a title (Node.js). Read the post itself so CVEs and fixed versions are available.
            try:
                snippet = news_sources.strip_html(get_text(url))[:news_sources.ENTRY_CHARS] or snippet
            except Exception:
                pass
        text = f"{e['title']} {snippet}"
        picked = None
        if src.get("severity_lines"):
            picked = pick_severity_lines(snippet)
            if picked["kept"]:
                snippet = (f"{e['title']}. Critical/High fixes ({len(picked['kept'])} of {picked['total']} listed): "
                           + "; ".join(f"{c} ({sev}): {d}" for sev, c, d in picked["kept"][:15]))
        if src.get("qualify") != "always" and not (pattern and pattern.search(text)):
            continue
        out.append(make_candidate(
            id=url, source=src["name"], title=e["title"], url=url,
            published_at=published.isoformat(), summary=snippet[:MAX_SUMMARY],
            cve_ids=([c for _, c, _ in picked["kept"]] if picked is not None else sorted(set(CVE_RE.findall(text)))),
            source_product=src.get("product", ""),
            exploited=exploited_in_wild(text),
            severity=(picked["severity"] if picked is not None else (
                "critical" if re.search(r"\bcritical\b", text, re.I) else (
                    "high" if re.search(r"\bhigh\b", text, re.I) else None))),
            vendor_security_release=False))
        c = out[-1]
        if src.get("fixed_in_pattern"):
            m = re.search(src["fixed_in_pattern"], text)
            if m:
                c["fixed_in"] = m.group(1)
        # A feed set to "always" is a security release by nature. A pattern feed (Chrome) must also
        # carry a critical or high hint, or an in-the-wild hint, so medium/low-only releases do not qualify.
        c["vendor_security_release"] = src.get("qualify") == "always" or c["exploited"] or c["severity"] in ("critical", "high")
    return out, _info(len(out), newest)


NODE_LINE_RE = re.compile(r"^\*\s*\((CVE-[^)]*)\)\s*(.*?)(?:\s+[\u2013-]\s*(Critical|High|Medium|Low))?\s*$", re.M)


def parse_node_security_notes(body):
    """Lines like '* (CVE-2026-1, CVE-2026-2) tls: reject ... (Name) \u2013 High'. The severity suffix exists on the
    Current release only; LTS backports list the same CVEs without it, so it is optional."""
    out = []
    for cves, desc, sev in NODE_LINE_RE.findall(body):
        out.append((sev or None, [c.strip() for c in cves.split(",") if c.strip()], desc.strip()))
    return out


def fetch_github_releases(src, cutoff, get=get_json, token=None, **_):
    """Security releases announced in GitHub release notes (Node.js lists every CVE with its severity there)."""
    url = f"{GITHUB_API}/repos/{src['repo']}/releases?per_page=15"
    releases = get(url, github_headers(token))
    if not releases:  # an empty list for a busy repository is not believable; ask once more
        releases = get(url, github_headers(token))
    pattern = re.compile(src.get("body_pattern", "security release"), re.I)
    out, newest = [], None
    for r in releases:
        pub = _date(r.get("published_at"))
        if pub is None or r.get("draft"):
            continue
        newest = max(newest, pub) if newest else pub
        body = r.get("body") or ""
        if pub < cutoff or not pattern.search(body):
            continue
        notes = parse_node_security_notes(body)
        cves = []
        for _, ids, _ in notes:
            cves += [c for c in ids if c not in cves]
        tag = r.get("tag_name", "")
        labels = {n[0] for n in notes if n[0]}
        severity = "critical" if "Critical" in labels else ("high" if "High" in labels else None)
        out.append(make_candidate(
            id=tag, source=src["name"], title=f"{src.get('product', src['repo'])} {tag.lstrip('v')} security release",
            url=r.get("html_url") or f"https://github.com/{src['repo']}/releases/tag/{tag}",
            published_at=pub.isoformat(), cve_ids=cves[:15], source_product=src.get("product", ""),
            summary="; ".join(f"{', '.join(ids)}: {d}" + (f" ({sev})" if sev else "") for sev, ids, d in notes)[:MAX_SUMMARY],
            severity=severity, vendor_security_release=bool(notes), fixed_in=tag.lstrip("v")))
    return out, _info(len(out), newest)


MFSA_CVE_RE = re.compile(r"^  (CVE-\d{4}-\d{4,7}):\s*\n((?:    .*\n?)+)", re.M)


def parse_mfsa(text):
    """Small reader for the fixed shape of Mozilla advisory YAML (the engine is stdlib only, no YAML parser)."""
    def scalar(key):
        m = re.search(rf"^{key}:\s*(.+)$", text, re.M)
        return m.group(1).strip().strip("'\"") if m else ""
    fixed = re.search(r"^fixed_in:\s*\n((?:- .*\n?)+)", text, re.M)
    cves = []
    for cve, block in MFSA_CVE_RE.findall(text):
        title = re.search(r"^    title:\s*(.+)$", block, re.M)
        impact = re.search(r"^    impact:\s*(\w+)", block, re.M)
        cves.append((cve, title.group(1).strip().strip("'\"") if title else "", impact.group(1).lower() if impact else ""))
    return {"announced": scalar("announced"), "impact": scalar("impact").lower(), "title": scalar("title"),
            "fixed_in": [x[2:].strip() for x in fixed.group(1).splitlines()] if fixed else [], "cves": cves}


def fetch_mozilla_advisories(src, cutoff, get=get_json, get_text=news_sources.http_get, token=None, **_):
    """Mozilla Foundation Security Advisories from the canonical GitHub repository (structured YAML)."""
    year = cutoff.year
    listing = get(f"{GITHUB_API}/repos/mozilla/foundation-security-advisories/contents/announce/{year}", github_headers(token))
    names = sorted((x["name"] for x in listing if x["name"].endswith(".yml")),
                   key=lambda n: int(re.search(r"-(\d+)\.yml$", n).group(1)))[-8:]
    out, newest = [], None
    for name in names:
        adv = parse_mfsa(get_text(f"https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/{year}/{name}"))
        try:
            announced = datetime.strptime(adv["announced"], "%B %d, %Y").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        newest = max(newest, announced) if newest else announced
        if announced.date() < cutoff.date() or "firefox" not in adv["title"].lower():
            continue
        top = [c for c in adv["cves"] if c[2] in ("critical", "high")]
        if not top:
            continue
        severity = "critical" if any(c[2] == "critical" for c in top) else "high"
        out.append(make_candidate(
            id=name, source=src["name"], title=adv["title"],
            url=f"https://www.mozilla.org/en-US/security/advisories/{name[:-4]}/",
            published_at=announced.isoformat(), cve_ids=[c[0] for c in top][:15],
            summary="; ".join(f"{c[0]} ({c[2]}): {c[1]}" for c in top[:15])[:MAX_SUMMARY],
            source_product=src.get("product", "Firefox"), severity=severity, vendor_security_release=True,
            fixed_in=", ".join(adv["fixed_in"])))
    return out, _info(len(out), newest)


def fetch_hn_signals(src, cutoff, get=get_json, **_):
    """Hacker News stories used only as a detection signal (never posted on their own).

    A story matches a batch only when its title or link carries one of the batch's CVE IDs, or it links to the same page.
    """
    since = int(cutoff.timestamp())
    min_points = int(src.get("min_points", 30))
    out, seen, newest = [], set(), None
    for query in src["queries"]:
        url = ("https://hn.algolia.com/api/v1/search_by_date?query=" + urllib.parse.quote(query)
               + f"&tags=story&numericFilters=created_at_i>{since},points>{min_points}&hitsPerPage=20")
        for h in get(url).get("hits", []):
            oid = h.get("objectID")
            if not oid or oid in seen:
                continue
            seen.add(oid)
            created = _date(h.get("created_at"))
            newest = max(newest, created) if created and newest else (created or newest)
            title = h.get("title") or ""
            link = h.get("url") or ""
            out.append(make_candidate(
                id=f"hn-{oid}", source=src["name"], title=title, url=link or f"https://news.ycombinator.com/item?id={oid}",
                published_at=created.isoformat() if created else None,
                summary=f"Hacker News points={h.get('points')}, comments={h.get('num_comments')}",
                cve_ids=sorted(set(CVE_RE.findall(f"{title} {link}"))), signal=True,
                hn_points=int(h.get("points") or 0), hn_url=f"https://news.ycombinator.com/item?id={oid}"))
    return out, _info(len(out), newest)


FETCHERS = {"hn-signal": fetch_hn_signals, "github-releases": fetch_github_releases, "mozilla-advisories": fetch_mozilla_advisories, "kev": fetch_kev, "ghsa": fetch_ghsa, "repo-advisories": fetch_repo_advisories, "feed": fetch_feed}


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
            if "no dated entries" in info and not got:
                info = f"WARN? empty answer, {info}"
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


def extract_detail(record):
    """Plain facts from a CVE record: weakness names (CWE) and the first English description (shortened)."""
    cna = (record.get("containers") or {}).get("cna") or {}
    cwes = [d.get("description", "") for pt in cna.get("problemTypes") or [] for d in pt.get("descriptions") or []
            if d.get("lang", "en").startswith("en") and d.get("description")]
    desc = next((d.get("value", "") for d in cna.get("descriptions") or [] if d.get("lang", "en").startswith("en")), "")
    parts = ["; ".join(dict.fromkeys(cwes)), re.sub(r"\s+", " ", desc).strip()[:300]]
    return " | ".join(p for p in parts if p)


def enrich_cvss(cands, get=get_json, log=print, limit=MAX_ENRICH, per_candidate=5):
    """Fill missing CVSS from cvelistV5 (highest score across the candidate's CVEs).

    A failed lookup leaves the score empty, never guessed. Lookups are cached per CVE ID.
    Brand-new CVEs may not be in cvelistV5 yet (HTTP 404); they pass the filter only through other signals.
    """
    cache, lookups = {}, 0
    for c in cands:
        if c["cvss"] is not None or not c["cve_ids"]:
            continue
        scores, details = [], []
        for cve in c["cve_ids"][:per_candidate]:
            if cve not in cache:
                if lookups >= limit:
                    log(f"[enrich] limit {limit} reached, remaining CVEs keep an empty score")
                    break
                lookups += 1
                try:
                    record = get(cvelist_url(cve))
                    cache[cve] = (extract_cvss(record), extract_detail(record))
                except Exception as ex:
                    cache[cve] = (None, "")
                    log(f"[enrich] {cve}: {type(ex).__name__}: {ex}")
            score, detail = cache.get(cve, (None, ""))
            if score is not None:
                scores.append(score)
            if detail:
                details.append(f"{cve}: {detail}")
        c["cvss"] = max(scores) if scores else None
        c["detail"] = " || ".join(details)[:1500]
    return cands
