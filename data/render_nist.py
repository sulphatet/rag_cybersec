"""Render NIST SP 800-61r3 (April 2025) into KB pages.

The PDF has two very different regions, handled separately:

  * Prose (Executive Summary, §1–§2.3, §3 intro, Appendix B glossary): text is
    extracted per page, page headers/footers stripped, and split at numbered
    headings; each numbered (sub)section becomes one document section.
  * CSF 2.0 Community Profile tables (Tables 2 and 3, ~25 pages): a 4-column
    table (CSF Element | Description | Priority | Recommendations/Considerations/
    Notes) that generic table extraction scrambles. Words are assigned to
    columns by x-position (column edges come from the header row on each page)
    and rows are delimited by a CSF identifier (or Function name) appearing in
    column 1. Each CSF element becomes one section, so a gold fact such as
    "GV.RM-06 has priority Medium" maps to exactly one chunk.

Outputs kb/nist/*.md and kb/docs_nist.jsonl.

  python -m data.render_nist
"""
from __future__ import annotations

import collections
import re

import pdfplumber

from .common import KB, RAW, write_jsonl
from .render_attack import to_markdown

PDF = RAW / "sp800-61r3.pdf"
SOURCE = "NIST SP 800-61r3 (April 2025), Incident Response Recommendations and Considerations for Cyber Risk Management"
URL = "https://doi.org/10.6028/NIST.SP.800-61r3"

CSF_ID = re.compile(r"^(?:[A-Z]{2}\.[A-Z]{2}(?:-\d{2})?\b|[A-Z]{2} \([A-Z][a-z]+\))")
HEADING = re.compile(r"^(\d+(?:\.\d+)*)\.\s+([A-Z][^\n]{2,80})$")
FOOTER = re.compile(r"^\d{1,2}$")


# ---------------------------------------------------------------------------
# Table region
# ---------------------------------------------------------------------------
def header_edges(words):
    """Return (col edges, header bottom y) if this page carries the CSF table header."""
    pri = [w for w in words if w["text"] == "Priority"]
    rec = [w for w in words if w["text"] == "Recommendations,"]
    desc = [w for w in words if w["text"] == "Description"]
    csf = [w for w in words if w["text"] == "CSF"]
    if not (pri and rec and desc and csf):
        return None
    # header row = the Priority word; other header words share its line
    top = pri[0]["top"]
    same = lambda ws: [w for w in ws if abs(w["top"] - top) < 3]
    d, r, c = same(desc), same(rec), sorted(same(csf), key=lambda w: w["x0"])
    if not (d and r and len(c) >= 2):
        return None
    # header words: "CSF Element" | "CSF Element Description" | "Priority" | "Recommendations, ..."
    # column 2 starts at the *second* "CSF", not at "Description"
    return [c[0]["x0"] - 2, c[1]["x0"] - 4, pri[0]["x0"] - 4, r[0]["x0"] - 4], pri[0]["bottom"]


def table_rows_from_page(page, state):
    """Yield completed rows; `state` carries the open row across pages."""
    words = page.extract_words(x_tolerance=1.5, y_tolerance=2)
    he = header_edges(words)
    if he is None:
        return
    edges, hdr_bottom = he
    # keep words below the header row and above the page footer (page number)
    body = sorted((w for w in words if w["top"] > hdr_bottom + 1 and w["top"] < page.height - 50),
                  key=lambda w: w["top"])
    # group into visual lines: a new line starts when the vertical gap exceeds 4pt
    lines, cur, cur_top = [], [], None
    for w in body:
        if cur and w["top"] - cur_top > 4:
            lines.append(cur)
            cur = []
        if not cur:
            cur_top = w["top"]
        cur.append(w)
    if cur:
        lines.append(cur)
    for line in lines:
        ws = sorted(line, key=lambda w: w["x0"])
        cols = ["", "", "", ""]
        for w in ws:
            ci = max(i for i, e in enumerate(edges) if w["x0"] >= e) if w["x0"] >= edges[0] else 0
            cols[ci] = (cols[ci] + " " + w["text"]).strip()
        # skip table-title lines and page-header fragments
        joined = " ".join(cols)
        if joined.startswith("Table ") or "NIST SP 800-61r3" in joined or joined.startswith("April 2025"):
            continue
        if FOOTER.match(joined):        # page number
            continue
        if cols[0] and CSF_ID.match(cols[0]):
            if state["row"]:
                yield state["row"]
            state["row"] = {"id": cols[0], "desc": cols[1], "priority": cols[2], "notes": cols[3]}
        elif state["row"]:
            r = state["row"]
            if cols[0]:
                r["id"] = (r["id"] + " " + cols[0]).strip()
            if cols[1]:
                r["desc"] = (r["desc"] + " " + cols[1]).strip()
            if cols[2]:
                r["priority"] = (r["priority"] + " " + cols[2]).strip()
            if cols[3]:
                # new R/C/N item starts a new line for readability
                sep = "\n" if re.match(r"^[RCN]\d+:", cols[3]) else " "
                r["notes"] = (r["notes"] + sep + cols[3]).strip()


def render_table(pdf) -> list[dict]:
    state = {"row": None}
    rows = []
    for page in pdf.pages:
        rows.extend(table_rows_from_page(page, state))
    if state["row"]:
        rows.append(state["row"])
    docs = []
    for r in rows:
        eid = re.match(r"^([A-Z]{2}(?:\.[A-Z]{2}(?:-\d{2})?)?)", r["id"]).group(1)
        level = "subcategory" if "-" in eid else ("category" if "." in eid else "function")
        text = (f"CSF 2.0 Community Profile element {r['id']} ({level})\n"
                f"Description: {r['desc']}\n"
                f"Priority for incident response: {r['priority'] or 'not stated'}")
        if r["notes"]:
            text += f"\nRecommendations, considerations, notes:\n{r['notes']}"
        docs.append({
            "doc_id": f"nist:sp800-61r3:{eid}",
            "source": SOURCE,
            "entity_id": eid,
            "entity_name": r["id"],
            "entity_type": "csf_profile_row",
            "url": URL,
            "sections": [{"name": "Community Profile", "text": text}],
        })
    return docs


# ---------------------------------------------------------------------------
# Prose region
# ---------------------------------------------------------------------------
def page_text(page) -> str:
    t = page.extract_text(x_tolerance=1.5, y_tolerance=2) or ""
    out = []
    for ln in t.split("\n"):
        s = ln.strip()
        if not s or s.startswith("NIST SP 800-61r3") or s.startswith("April 2025") or FOOTER.match(s):
            continue
        out.append(s)
    return "\n".join(out)


def render_prose(pdf, table_pages: set[int]) -> list[dict]:
    """Split the non-table pages at numbered headings; drop TOC/front matter."""
    text = "\n".join(page_text(p) for i, p in enumerate(pdf.pages) if i not in table_pages)
    # cut front matter: start at the Executive Summary; stop at References
    start = text.find("Executive Summary\n")
    end = text.find("\nReferences\n", start)
    body = text[start:end] if start >= 0 and end > start else text
    # split at headings
    parts, cur_title, cur = [], "Executive Summary", []
    for ln in body.split("\n"):
        m = HEADING.match(ln)
        if m and not ln.endswith("."):
            if cur:
                parts.append((cur_title, "\n".join(cur)))
            cur_title, cur = f"{m.group(1)}. {m.group(2)}", []
        elif ln == "Executive Summary" and not cur:
            continue
        else:
            cur.append(ln)
    if cur:
        parts.append((cur_title, "\n".join(cur)))
    # join wrapped lines into paragraphs: a line ending without terminal punctuation continues
    docs = []
    for title, txt in parts:
        paras, buf = [], ""
        for ln in txt.split("\n"):
            if ln.startswith("•") or ln.startswith("-"):
                if buf:
                    paras.append(buf)
                buf = ln
            elif buf and not re.search(r"[.:;!?]$", buf):
                buf += " " + ln
            else:
                if buf:
                    paras.append(buf)
                buf = ln
        if buf:
            paras.append(buf)
        sec_text = "\n".join(paras).strip()
        if len(sec_text.split()) < 25:
            continue
        sid = title.split(".")[0] if title[0].isdigit() else "exec"
        num = re.match(r"^([\d.]+)\.", title)
        eid = f"sec{num.group(1)}" if num else "exec-summary"
        docs.append({
            "doc_id": f"nist:sp800-61r3:{eid}",
            "source": SOURCE,
            "entity_id": eid,
            "entity_name": title,
            "entity_type": "guidance_section",
            "url": URL,
            "sections": [{"name": title, "text": f"NIST SP 800-61r3, {title}\n\n{sec_text}"}],
        })
    return docs


def main():
    pdf = pdfplumber.open(PDF)
    table_pages = {i for i, p in enumerate(pdf.pages) if header_edges(p.extract_words(x_tolerance=1.5, y_tolerance=2))}
    prose = render_prose(pdf, table_pages)
    table = render_table(pdf)
    docs = prose + table
    out_dir = KB / "nist"
    out_dir.mkdir(parents=True, exist_ok=True)
    for d in docs:
        (out_dir / f"{d['entity_id']}.md").write_text(to_markdown(d))
    n = write_jsonl(KB / "docs_nist.jsonl", docs)
    lv = collections.Counter(d["entity_type"] for d in docs)
    pri = collections.Counter(re.search(r"Priority for incident response: (\w+)", d["sections"][0]["text"]).group(1)
                              for d in table)
    print(f"table pages: {sorted(table_pages)}")
    print(f"wrote {n} docs -> {out_dir}: {dict(lv)}; priorities: {dict(pri)}")
    print("prose sections:", [d["entity_name"] for d in prose])


if __name__ == "__main__":
    main()
