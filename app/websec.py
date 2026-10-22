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
META_RE = re.compile(r"dữ liệu (?:không|chưa)|không (?:nêu|đề cập|có thông tin|rõ)|the data (?:does not|doesn't)", re.I)
VERSION_RE = re.compile(r"(?<![\w.])\d+(?:\.\d+)+(?!\w)(?!\.\d)")


class RunError(Exception):
    """Operational error that the owner must be told about."""


SCHEMA = """Return ONLY one JSON object:
{"items": [{"batch_id": "...", "headline": "...", "description": "...", "impact": "...", "action": "..."}]}
Rules:
- Write every text value in Vietnamese. Keep product names, CVE IDs and version numbers exactly as given.
- Return one item per batch in the data, using the given batch_id. Do not add batches.
- Write version numbers exactly as they appear in the data. Do not shorten or round them.
- When the data lists several fixed versions (one per branch), name every one of them in the action.
- Do not use the word "batch" in the text; say "bản cập nhật" or "advisory" instead.
- headline: what is affected and what happened, include the CVE ID when there is one.
- Readers are engineers who are not security experts. Say in plain words what the flaw is and what an attacker could do,
  using plain_risk and detail from the data. Explain any technical term in a few words (for example "use after free (lỗi bộ nhớ)").
- Severity, CVSS and exploitation status are shown by the system. Do not repeat them and never write about what the data lacks.
- description: 1-2 facts taken only from the batch data, starting with what the flaw is, in plain words.
- impact: one sentence on who is affected and what could happen (versions, conditions) from the batch data. Do not start it with the word "Ảnh hưởng".
- action: one concrete step, for example the fixed version to update to. If no fixed version is listed, say to update to the latest
  release from the vendor. Never write that the data is missing something.
- description + impact + action together: 40-70 words. No emoji. No em dash.
- Use only information present in the batch data. Never invent CVE IDs, version numbers, scores or links.
- If the data is too thin for a full explanation, still return the item and say plainly what the data does not state;
  keep to the 40-70 word range."""


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


def _join_unique(values, sep=", "):
    """Distinct non-empty values in first-seen order. An advisory often has one fixed version per branch."""
    out = []
    for v in values:
        if v and v not in out:
            out.append(v)
    return sep.join(out)


VULN_TYPES = load_json(PROFILE_DIR / "profile.json").get("vuln_types", [])


def detect_types(text, types, limit=2):
    """Plain-language vulnerability types found in the English source text (code-owned, never LLM-written)."""
    found = []
    for t in types:
        if re.search(t["pattern"], text, re.I) and t not in found:
            found.append(t)
    return found[:limit]


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
            "fixed_in": _join_unique(i["fixed_in"] for i in items),
            "affected": _join_unique((i["affected"] for i in items), sep="; "),
            "summary": " | ".join(i["summary"] for i in items if i["summary"])[:secsources.MAX_SUMMARY * 2],
            "detail": " || ".join(i["detail"] for i in items if i.get("detail"))[:3000],
            "category": (g["watch"] or {}).get("category"), "tag": (g["watch"] or {}).get("tag"),
        }
        batch["types"] = detect_types(f"{batch['title']} {batch['summary']} {batch['detail']}", VULN_TYPES)
        batch["tier"] = _tier(batch, g["watch"])
        batches.append(batch)
    return batches


def attach_signals(batches, signals):
    """Attach Hacker News stories to batches by CVE ID or identical link. Returns signals that matched nothing."""
    unmatched = []
    for sig in signals:
        hit = False
        for b in batches:
            same_cve = bool(set(sig["cve_ids"]) & set(b["cve_ids"]))
            same_link = sig["url"].rstrip("/") == b["url"].rstrip("/")
            if same_cve or same_link:
                hit = True
                if sig["hn_points"] > b.get("hn_points", 0):
                    b["hn_points"], b["hn_url"] = sig["hn_points"], sig["hn_url"]
        if not hit:
            unmatched.append(sig)
    return sorted(unmatched, key=lambda x: -x["hn_points"])


def select(batches, max_detailed=MAX_DETAILED, max_others=MAX_OTHERS):
    """Top batches (tier 1-3) get a detailed item; the rest become one-line entries."""
    ranked = sorted(batches, key=lambda b: (b["tier"], -(b["cvss"] or 0), -b.get("hn_points", 0), b["product"]))
    detailed = [b for b in ranked if b["tier"] <= 3][:max_detailed]
    rest = [b for b in ranked if b not in detailed]
    return detailed, rest[:max_others]


def build_user_prompt(detailed, now):
    keys = ("batch_id", "product", "cve_ids", "cvss", "exploited", "in_kev", "title", "summary", "fixed_in", "affected", "count")
    data = [dict({k: b[k] for k in keys}, detail=b.get("detail", ""), plain_risk=[t["risk"] for t in b.get("types", [])]) for b in detailed]
    return (f"Today: {now.astimezone(TZ_VN):%Y-%m-%d} (Vietnam time).\n"
            f"BATCH DATA (JSON):\n{json.dumps(data, ensure_ascii=False)}\n\n{SCHEMA}")


def source_text(batch):
    parts = [batch["title"], batch["summary"], batch.get("detail", ""), batch["fixed_in"], batch["affected"], " ".join(batch["cve_ids"])]
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
    if META_RE.search(text):
        errs.append("talks about missing data; state facts only and omit what is unknown")
    unknown = [c for c in secsources.CVE_RE.findall(text) if c not in batch["cve_ids"]]
    if unknown:
        errs.append(f"CVE IDs not in source data: {unknown}")
    src = source_text(batch)
    known = set(VERSION_RE.findall(src))
    # A shorter branch such as "8.2" is fine when the data has "8.2.35" (match on a dot boundary only).
    bad_versions = [v for v in VERSION_RE.findall(text) if v not in known and not any(k.startswith(v + ".") for k in known)]
    if bad_versions:
        errs.append(f"numbers not in source data: {bad_versions}")
    return errs


def one_liner(batch, strings):
    kind = ", ".join(t["label"] for t in batch.get("types", [])) or strings.get("generic_type", "security issue")
    ids = ", ".join(batch["cve_ids"][:3])
    more = f" +{len(batch['cve_ids']) - 3}" if len(batch["cve_ids"]) > 3 else ""
    fix = f" ({strings['fixed']}: {batch['fixed_in']})" if batch["fixed_in"] else ""
    return f"• {batch['product']}: {kind}{' (' + ids + more + ')' if ids else ''}{fix} {batch['url']}"


def severity_line(batch, strings):
    """Code-owned severity facts, so the LLM never has to describe them (or what is missing)."""
    score, sev = batch.get("cvss"), batch.get("severity")
    label = strings["critical"] if (score or 0) >= CRITICAL_SCORE or sev == "critical" else (
        strings["high"] if (score or 0) >= CVSS_THRESHOLD or sev == "high" else "")
    parts = [label + (f" (CVSS {score:g})" if score is not None else "") if label else (f"CVSS {score:g}" if score is not None else "")]
    if batch.get("exploited"):
        parts.append(strings["exploited"])
    return f"{strings['severity']}: " + ", ".join(p for p in parts if p) if any(parts) else ""


def _strip_label(text, label):
    return re.sub(rf"^\s*{re.escape(label)}\s*:?\s*", "", text, flags=re.I)


def render_item(batch, item, strings):
    kind = "#ZeroDay" if batch["exploited"] else ("#CVE" if batch["cve_ids"] else "#Vulnerability")
    tags = [t for t in (batch["tag"], kind) if t][:2]
    lines = [f"*[{batch['category']}] {formatter.clean(item['headline'])}*",
             " ".join(f"`{t}`" for t in tags),
             *[x for x in (severity_line(batch, strings),
                           f"{strings['vuln_type']}: " + ", ".join(t["label"] for t in batch["types"]) if batch.get("types") else "") if x],
             formatter.clean(item["description"]),
             f"{strings['impact']}: {_strip_label(formatter.clean(item['impact']), strings['impact'])}",
             f"{strings['action']}: {_strip_label(formatter.clean(item['action']), strings['action'])}",
             f"🔗 {batch['url']}"]
    return "\n".join(lines)


def render_digest(pairs, others, settings, date_str):
    strings = settings["strings"]
    blocks = [f"*{settings['title']}: {date_str}*"] + [render_item(b, i, strings) for b, i in pairs]
    if others:
        blocks.append(f"*{strings['others']}*\n" + "\n".join(one_liner(b, strings) for b in others))
    return f"\n\n{formatter.SEP}\n\n".join(blocks)


def section_blocks(pairs, others, settings):
    """Blocks for embedding in another bulletin: detailed items (first one carries the section heading) and the one-line block."""
    strings = settings["strings"]
    blocks = [render_item(b, i, strings) for b, i in pairs]
    if blocks:
        blocks[0] = f"*{strings['section']}*\n\n{blocks[0]}"
    if others and pairs:
        blocks.append(f"*{strings['others']}*\n" + "\n".join(one_liner(b, strings) for b in others))
    return blocks


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


def repair_prompt(item, batch, errs):
    keys = ("batch_id", "product", "cve_ids", "cvss", "exploited", "in_kev", "title", "summary", "fixed_in", "affected")
    return ("Fix the item below so it passes the listed errors. Keep the facts, use only the batch data, "
            f"stay within 40-70 words for description + impact + action.\nErrors: {errs}\n"
            f"Item: {json.dumps(item, ensure_ascii=False)}\n"
            f"Batch data: {json.dumps({k: batch[k] for k in keys}, ensure_ascii=False)}\n"
            "Return the corrected item as one JSON object with the same batch_id.")


def summarize(detailed, now, system, mock_response=None, log=print):
    """Ask the LLM to summarize the selected batches. An invalid item gets one repair request;
    if it still fails (or the LLM omits the batch) the batch degrades to a one-line entry."""
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
            log(f"[validate] {batch['product']} ({batch['batch_id']}) failed: {'; '.join(errs)}; asking for one repair")
            try:
                fixed = formatter.unwrap_item(llm.call_json(system, repair_prompt(item, batch, errs), mock_response))
                fixed["batch_id"] = batch["batch_id"]
                errs = validate_summary(fixed, batch)
                item = fixed
            except Exception as ex:
                log(f"[llm] repair request failed: {type(ex).__name__}: {ex}")
        if errs:
            log(f"[validate] {batch['product']} ({batch['batch_id']}) degraded to one line: {'; '.join(errs)}")
            failed.append(batch)
        else:
            pairs.append((batch, item))
    for b in detailed:
        if b["batch_id"] not in seen:
            log(f"[llm] {b['product']} ({b['batch_id']}) was omitted by the LLM, degraded to one line")
            failed.append(b)
    return pairs, failed


def prepare(now, mock_file=None, max_detailed=MAX_DETAILED, max_others=MAX_OTHERS, log=print):
    """Collect, filter and summarize. Posts nothing and writes no state.

    Returns a dict: pairs (batch, item), others, settings, status, state. Empty pairs means nothing to post.
    """
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
        cands, status = secsources.collect(profile["sources"], now, token=os.environ.get("GITHUB_TOKEN"), log=log)
        if status and all(v.startswith("ERROR") for v in status.values()):
            raise RunError("All security sources failed. Check network access and sources.json.")
    signals = [c for c in cands if c.get("signal")]
    cands = drop_posted([c for c in cands if not c.get("signal")], posted_ids)
    if not mock:
        # Enrich only what can matter: watchlist products and KEV entries (global feeds are large).
        secsources.enrich_cvss([c for c in cands if c["in_kev"] or match_watchlist(c, profile["watchlist"])])
    kept = prefilter(cands, profile["watchlist"])
    batches = group_batches(kept)
    for sig in attach_signals(batches, signals)[:5]:
        log(f"[signal] HN {sig['hn_points']} points, not matched to any selected item: {sig['title'][:100]} {sig['hn_url']}")
    detailed, others = select(batches, max_detailed, max_others)
    log(f"[run] {len(cands)} new security candidates, {len(kept)} pass the filter, {len(batches)} batches, "
        f"{len(detailed)} detailed, {len(others)} one-line")
    result = {"pairs": [], "others": [], "settings": settings, "status": status, "state": state}
    if not detailed:
        log("No batch reached the detailed tier. Nothing to post.")
        return result
    pairs, failed = summarize(detailed, now, system, mock["llm_response"] if mock else None, log=log)
    if not pairs:
        log("No valid summary. Nothing to post.")
        return result
    result["pairs"] = pairs
    result["others"] = (failed + others)[:max_others]
    return result


def commit_state(prep, now):
    """Remember what was posted so it is not posted again."""
    state = prep["state"]
    for b in [p[0] for p in prep["pairs"]] + prep["others"]:
        state["posted"].append({"date": now.isoformat(), "ids": b["ids"], "headline": b["title"], "url": b["url"]})
    state["posted"] = state["posted"][-MAX_STATE:]
    save_state(state)


def run(dry_run=False, mock_file=None, now=None):
    now = now or datetime.now(timezone.utc)
    prep = prepare(now, mock_file)
    pairs, others, settings = prep["pairs"], prep["others"], prep["settings"]
    if not pairs:
        return 0
    text = render_digest(pairs, others, settings, f"{now.astimezone(TZ_VN):%d/%m/%Y}")
    problems = check_digest(text, pairs, others)
    if problems:
        raise RunError(f"Final digest check failed: {'; '.join(problems)}")
    print(text)
    for name, info in prep["status"].items():
        if info.startswith(("ERROR", "STALE")):
            print(f"[source-note] {name}: {info}")
    if dry_run:
        print("\n[dry-run] Not posted to Slack, state not written.")
        return 0
    slack.post(text)
    commit_state(prep, now)
    print("Posted.")
    return 0
