"""Tech Stack Security bulletin (profile "websec").

Pipeline: fetch -> enrich CVSS -> filter in code -> group by patch batch -> rank and cap ->
LLM summarizes only the selected batches -> validate against the source data -> post.
The LLM never chooses links, labels, CVE IDs or severity; code owns all of them.
"""
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import formatter, llm, secsources, slack

HERE = Path(__file__).parent
ROOT = HERE.parent
PROFILE_DIR = ROOT / "profiles" / "websec"
STATE = ROOT / "state" / "posted-websec.json"
TZ_VN = timezone(timedelta(hours=7))
CVSS_THRESHOLD = 8.0
CRITICAL_SCORE = 9.0
MAX_DETAILED = 3
MAX_OTHERS = 8
WORDS_MIN, WORDS_MAX = 40, 70
MAX_STATE = 500
MARKUP_RE = re.compile(r"https?:|www\.|[<>&|`]|@(?:channel|here|everyone)", re.I)
VERSION_RE = re.compile(r"(?<![\w.])\d+(?:\.\d+)+(?![\w.])")


class RunError(Exception):
    """Operational error that the owner must be told about."""


SCHEMA = """Return ONLY one JSON object:
{"items": [{"batch_id": "...", "headline": "...", "description": "...", "impact": "...", "action": "..."}]}
Rules:
- Write every text value in Vietnamese. Keep product names, CVE IDs and version numbers exactly as given.
- Return one item per batch in the data, using the given batch_id. Do not add batches.
- headline: what is affected and what happened, include the CVE ID when there is one.
- description: 1-2 facts taken only from the batch data.
- impact: one sentence on who is affected (versions, conditions) taken only from the batch data.
- action: one concrete step, for example the fixed version to update to. If the data has no fixed version, say so.
- description + impact + action together: 40-70 words. No emoji. No em dash.
- Use only information present in the batch data. Never invent CVE IDs, version numbers, scores or links.
- If the data is too thin to explain the issue, omit that batch."""


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_profile():
    return {
        "settings": load_json(PROFILE_DIR / "profile.json"),
        "watchlist": load_json(PROFILE_DIR / "watchlist.json")["products"],
        "sources": load_json(PROFILE_DIR / "sources.json"),
        "rules": (PROFILE_DIR / "rules.md").read_text(encoding="utf-8"),
    }


def load_state():
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"posted": []}
    except json.JSONDecodeError as ex:
        raise RunError(f"{STATE.name} is not valid JSON, fix or remove it to avoid reposting: {ex}")


def save_state(state):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def _word_match(alias, text):
    return re.search(r"(?<![a-z0-9])" + re.escape(alias.lower()) + r"(?![a-z0-9])", text) is not None


def match_watchlist(cand, products):
    """Return the watchlist entry a candidate belongs to, or None."""
    package = (cand.get("package") or "").lower()
    for p in products:
        if package and cand.get("ecosystem") == p.get("ecosystem") and package in [x.lower() for x in p.get("packages", [])]:
            return p
    hay = " ".join((cand.get("vendor", ""), cand.get("product", ""), cand.get("source_product", ""))).lower()
    for p in products:
        if any(_word_match(a, hay) for a in p.get("aliases", [])):
            return p
    return None


def qualifies(cand, threshold=CVSS_THRESHOLD):
    """Severity gate: in KEV, exploited in the wild, a vendor security release, a critical hint, or CVSS >= threshold."""
    if cand["in_kev"] or cand["exploited"] or cand["vendor_security_release"]:
        return True
    if (cand.get("severity") or "").lower() == "critical":
        return True
    return cand["cvss"] is not None and cand["cvss"] >= threshold


def prefilter(cands, products, threshold=CVSS_THRESHOLD):
    """Keep qualifying candidates on the watchlist, plus KEV entries outside it (one-line tier only)."""
    kept = []
    for c in cands:
        watch = match_watchlist(c, products)
        if not qualifies(c, threshold):
            continue
        if watch is None and not c["in_kev"]:
            continue
        kept.append((c, watch))
    return kept


def drop_posted(cands, posted_ids):
    """Drop candidates whose CVE IDs (or own id when there is no CVE) were already posted."""
    out = []
    for c in cands:
        ids = c["cve_ids"] or [c["id"]]
        if all(i in posted_ids for i in ids):
            continue
        out.append(c)
    return out


def _tier(batch, watch):
    if watch is None:
        return 4
    if batch["exploited"] or batch["in_kev"]:
        return 1
    if (batch["cvss"] or 0) >= CRITICAL_SCORE or (batch["severity"] or "").lower() == "critical":
        return 2
    return 3


def group_batches(kept):
    """One batch per product inside the window, so one CVE can never appear in two batches."""
    groups = {}
    for c, watch in kept:
        name = watch["name"] if watch else f"{c['vendor']} {c['product']}".strip() or c["source"]
        g = groups.setdefault(name, {"watch": watch, "items": []})
        g["items"].append(c)
    batches = []
    for n, (name, g) in enumerate(sorted(groups.items()), start=1):
        items = g["items"]
        best = max(items, key=lambda x: x["cvss"] or 0)
        cve_ids, ids = [], []
        for i in items:
            cve_ids += [x for x in i["cve_ids"] if x not in cve_ids]
            ids += [x for x in (i["cve_ids"] or [i["id"]]) if x not in ids]
        scores = [i["cvss"] for i in items if i["cvss"] is not None]
        batch = {
            "batch_id": f"B{n}", "product": name, "count": len(items), "title": best["title"], "ids": ids,
            "url": best["url"], "published_at": max(i["published_at"] or "" for i in items), "cve_ids": cve_ids,
            "cvss": max(scores) if scores else None,
            "severity": next((i["severity"] for i in items if i["severity"]), None),
            "in_kev": any(i["in_kev"] for i in items), "exploited": any(i["exploited"] for i in items),
            "fixed_in": next((i["fixed_in"] for i in items if i["fixed_in"]), ""),
            "affected": next((i["affected"] for i in items if i["affected"]), ""),
            "summary": " | ".join(i["summary"] for i in items if i["summary"])[:secsources.MAX_SUMMARY * 2],
            "category": (g["watch"] or {}).get("category"), "tag": (g["watch"] or {}).get("tag"),
        }
        batch["tier"] = _tier(batch, g["watch"])
        batches.append(batch)
    return batches


def select(batches, max_detailed=MAX_DETAILED, max_others=MAX_OTHERS):
    """Top batches (tier 1-3) get a detailed item; the rest become one-line entries."""
    ranked = sorted(batches, key=lambda b: (b["tier"], -(b["cvss"] or 0), b["product"]))
    detailed = [b for b in ranked if b["tier"] <= 3][:max_detailed]
    rest = [b for b in ranked if b not in detailed]
    return detailed, rest[:max_others]


def build_user_prompt(detailed, now):
    keys = ("batch_id", "product", "cve_ids", "cvss", "exploited", "in_kev", "title", "summary", "fixed_in", "affected", "count")
    data = [{k: b[k] for k in keys} for b in detailed]
    return (f"Today: {now.astimezone(TZ_VN):%Y-%m-%d} (Vietnam time).\n"
            f"BATCH DATA (JSON):\n{json.dumps(data, ensure_ascii=False)}\n\n{SCHEMA}")


def source_text(batch):
    parts = [batch["title"], batch["summary"], batch["fixed_in"], batch["affected"], " ".join(batch["cve_ids"])]
    if batch["cvss"] is not None:
        parts.append(f"{batch['cvss']:g}")
    return " ".join(p for p in parts if p)


def validate_summary(item, batch):
    """Return a list of errors (empty = valid). Every claim must be traceable to the batch data."""
    errs = []
    fields = ("headline", "description", "impact", "action")
    if not isinstance(item, dict) or any(not isinstance(item.get(f), str) for f in fields):
        return ["item fields must all be strings"]
    for f in fields:
        if not formatter.clean(item.get(f)):
            errs.append(f"missing {f}")
    text = " ".join(item[f] for f in fields)
    if MARKUP_RE.search(text):
        errs.append("contains a link, mention or markup character")
    body = " ".join(formatter.clean(item.get(f)) for f in ("description", "impact", "action")).split()
    if not WORDS_MIN <= len(body) <= WORDS_MAX:
        errs.append(f"{len(body)} words, expected {WORDS_MIN}-{WORDS_MAX}")
    if formatter.EM_DASH in text:
        errs.append("contains em dash")
    if formatter.EMOJI_RE.search(text):
        errs.append("contains emoji")
    unknown = [c for c in secsources.CVE_RE.findall(text) if c not in batch["cve_ids"]]
    if unknown:
        errs.append(f"CVE IDs not in source data: {unknown}")
    src = source_text(batch)
    known = set(VERSION_RE.findall(src))
    bad_versions = [v for v in VERSION_RE.findall(text) if v not in known]
    if bad_versions:
        errs.append(f"numbers not in source data: {bad_versions}")
    return errs


def one_liner(batch, strings):
    ids = ", ".join(batch["cve_ids"][:3]) or "security update"
    more = f" +{len(batch['cve_ids']) - 3}" if len(batch["cve_ids"]) > 3 else ""
    fix = f" ({strings['fixed']}: {batch['fixed_in']})" if batch["fixed_in"] else ""
    return f"• {batch['product']}: {ids}{more}{fix} {batch['url']}"


def render_item(batch, item, strings):
    tags = [t for t in (batch["tag"], "#ZeroDay" if batch["exploited"] else "#CVE") if t][:2]
    lines = [f"*[{batch['category']}] {formatter.clean(item['headline'])}*",
             " ".join(f"`{t}`" for t in tags),
             formatter.clean(item["description"]),
             f"{strings['impact']}: {formatter.clean(item['impact'])}",
             f"{strings['action']}: {formatter.clean(item['action'])}",
             f"🔗 {batch['url']}"]
    return "\n".join(lines)


def render_digest(pairs, others, settings, date_str):
    strings = settings["strings"]
    blocks = [f"*{settings['title']}: {date_str}*"] + [render_item(b, i, strings) for b, i in pairs]
    if others:
        blocks.append(f"*{strings['others']}*\n" + "\n".join(one_liner(b, strings) for b in others))
    return f"\n\n{formatter.SEP}\n\n".join(blocks)


def check_digest(text, pairs, others):
    """Final check on the assembled message."""
    errs = []
    if formatter.EM_DASH in text:
        errs.append("digest contains em dash")
    if text.count("🔗") != len(pairs):
        errs.append("link count does not match item count")
    if len(pairs) > MAX_DETAILED:
        errs.append(f"more than {MAX_DETAILED} detailed items")
    if text.count(formatter.SEP) != len(pairs) + (1 if others else 0):
        errs.append("separator count does not match block count")
    allowed = {c for b, _ in pairs for c in b["cve_ids"]} | {c for b in others for c in b["cve_ids"]}
    stray = [c for c in secsources.CVE_RE.findall(text) if c not in allowed]
    if stray:
        errs.append(f"CVE IDs outside the selected data: {stray}")
    return errs


def summarize(detailed, now, system, mock_response=None, log=print):
    """Ask the LLM to summarize the selected batches; invalid items degrade to one-line entries."""
    result = llm.call_json(system, build_user_prompt(detailed, now), mock_response)
    raw = result.get("items", []) if isinstance(result, dict) else []
    by_id = {b["batch_id"]: b for b in detailed}
    pairs, failed, seen = [], [], set()
    for item in raw:
        bid = item.get("batch_id") if isinstance(item, dict) else None
        batch = by_id.get(bid) if isinstance(bid, str) else None
        if batch is None or batch["batch_id"] in seen:
            log(f"[llm] ignored item with unknown or repeated batch_id: {str(item)[:200]}")
            continue
        seen.add(batch["batch_id"])
        errs = validate_summary(item, batch)
        if errs:
            log(f"[validate] {batch['product']} ({batch['batch_id']}) degraded to one line: {'; '.join(errs)}")
            failed.append(batch)
        else:
            pairs.append((batch, item))
    failed += [b for b in detailed if b["batch_id"] not in seen]
    return pairs, failed


def run(dry_run=False, mock_file=None, now=None):
    now = now or datetime.now(timezone.utc)
    profile = load_profile()
    settings = profile["settings"]
    system = profile["rules"] + "\n\nReturn only JSON that matches the schema. No preamble."
    state = load_state()
    posted_ids = {i for p in state["posted"] for i in p["ids"]}
    mock = None
    if mock_file:
        mock = load_json(mock_file)
        os.environ["LLM_PROVIDER"] = "mock"
        cands, status = mock["candidates"], {"mock": "ok"}
    else:
        cands, status = secsources.collect(profile["sources"], now, token=os.environ.get("GITHUB_TOKEN"))
        if status and all(v.startswith("ERROR") for v in status.values()):
            raise RunError("All security sources failed. Check network access and sources.json.")
    cands = drop_posted(cands, posted_ids)
    if not mock:
        # Enrich only what can matter: watchlist products and KEV entries (global feeds are large).
        secsources.enrich_cvss([c for c in cands if c["in_kev"] or match_watchlist(c, profile["watchlist"])])
    kept = prefilter(cands, profile["watchlist"])
    batches = group_batches(kept)
    detailed, others = select(batches)
    print(f"[run] {len(cands)} new candidates, {len(kept)} pass the filter, {len(batches)} batches, "
          f"{len(detailed)} detailed, {len(others)} one-line")
    if not detailed:
        print("No batch reached the detailed tier. Nothing to post.")
        return 0
    pairs, failed = summarize(detailed, now, system, mock["llm_response"] if mock else None)
    others = (failed + others)[:MAX_OTHERS]
    if not pairs:
        print("No valid summary. Nothing to post.")
        return 0
    text = render_digest(pairs, others, settings, f"{now.astimezone(TZ_VN):%d/%m/%Y}")
    problems = check_digest(text, pairs, others)
    if problems:
        raise RunError(f"Final digest check failed: {'; '.join(problems)}")
    print(text)
    for name, info in status.items():
        if info.startswith(("ERROR", "STALE")):
            print(f"[source-note] {name}: {info}")
    if dry_run:
        print("\n[dry-run] Not posted to Slack, state not written.")
        return 0
    slack.post(text)
    for b in [p[0] for p in pairs] + others:
        state["posted"].append({"date": now.isoformat(), "ids": b["ids"],
                                "headline": b["title"], "url": b["url"]})
    state["posted"] = state["posted"][-MAX_STATE:]
    save_state(state)
    print("Posted.")
    return 0
