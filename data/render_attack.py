"""Render MITRE ATT&CK Enterprise STIX objects into per-entity Markdown pages.

Why render instead of JSON-splitting: a STIX technique object holds only its
description and metadata; mitigations, procedure examples and detection
strategies live in *separate* relationship objects. The entity page joins them,
exactly as attack.mitre.org does. Every section is a deterministic rendering of
source fields (the only text transformation is `common.normalise_text`).

Outputs:
  kb/attack/<ID>.md                    human-readable page
  kb/docs_attack.jsonl                 machine-readable {doc_id, entity_*, url, sections:[{name,text}]}

  python -m data.render_attack [--limit N]
"""
from __future__ import annotations

import argparse
import collections
import json

from .common import (ATTACK_BUNDLE, ATTACK_VERSION, KB, ext_id, is_live,
                     load_bundle, normalise_text, write_jsonl)

ENTITY_TYPES = {
    "attack-pattern": "technique",
    "course-of-action": "mitigation",
    "malware": "software",
    "tool": "software",
    "intrusion-set": "group",
    "campaign": "campaign",
    "x-mitre-tactic": "tactic",
}


class Attack:
    """Indexes a bundle for the joins the renderer needs."""

    def __init__(self, objs: list[dict]):
        self.byid = {o["id"]: o for o in objs}
        self.live = {o["id"]: o for o in objs if is_live(o) and o["type"] != "relationship"}
        self.ext = {ext_id(o): o for o in self.live.values() if ext_id(o)}
        self.tactic_by_short = {o["x_mitre_shortname"]: o for o in objs
                                if o["type"] == "x-mitre-tactic"}
        self.rels = [o for o in objs if o["type"] == "relationship" and is_live(o)
                     and o["source_ref"] in self.live and o["target_ref"] in self.live]
        self.out = collections.defaultdict(list)   # source_ref -> rels
        self.inc = collections.defaultdict(list)   # target_ref -> rels
        for r in self.rels:
            self.out[r["source_ref"]].append(r)
            self.inc[r["target_ref"]].append(r)
        self.parent = {r["source_ref"]: r["target_ref"] for r in self.rels
                       if r["relationship_type"] == "subtechnique-of"}

    def full_name(self, o: dict) -> str:
        """ATT&CK's display name: sub-techniques are 'Parent: Sub'."""
        p = self.parent.get(o["id"])
        return f"{self.byid[p]['name']}: {o['name']}" if p else o["name"]

    # -- helpers ---------------------------------------------------------
    def label(self, oid: str) -> str:
        o = self.byid[oid]
        return f"{ext_id(o)} {self.full_name(o)}"

    def rel_lines(self, rels, other_key: str, filter_type=None) -> list[str]:
        """One line per relationship: '<ID Name>: <relationship description>'."""
        lines = []
        for r in rels:
            other = self.byid[r[other_key]]
            if filter_type and other["type"] not in filter_type:
                continue
            desc = normalise_text(r.get("description"))
            lines.append((ext_id(other) or "", f"{self.label(other['id'])}: {desc}" if desc
                          else self.label(other["id"])))
        lines.sort(key=lambda x: x[0])
        return [t for _, t in lines]

    def tactics_of(self, tech: dict) -> list[dict]:
        out = []
        for kc in tech.get("kill_chain_phases", []):
            if kc.get("kill_chain_name") == "mitre-attack":
                t = self.tactic_by_short.get(kc["phase_name"])
                if t:
                    out.append(t)
        return out

    # -- renderers -------------------------------------------------------
    def technique(self, o: dict) -> dict:
        tid = ext_id(o)
        secs = []
        parent = None
        for r in self.out[o["id"]]:
            if r["relationship_type"] == "subtechnique-of":
                parent = self.byid[r["target_ref"]]
        tactics = self.tactics_of(o)
        meta = []
        meta.append(f"Type: sub-technique of {ext_id(parent)} ({parent['name']})" if parent
                    else "Type: technique")
        meta.append("Tactics: " + ", ".join(t["name"] for t in tactics))
        if o.get("x_mitre_platforms"):
            meta.append("Platforms: " + ", ".join(o["x_mitre_platforms"]))
        secs.append(("Description", f"{tid}: {self.full_name(o)}\n" + " | ".join(meta)
                     + "\n\n" + normalise_text(o.get("description"))))

        subs = sorted((ext_id(self.byid[r["source_ref"]]), self.full_name(self.byid[r["source_ref"]]))
                      for r in self.inc[o["id"]] if r["relationship_type"] == "subtechnique-of")
        if subs:
            secs.append(("Sub-techniques", "\n".join(f"{i}: {n}" for i, n in subs)))

        mit = self.rel_lines([r for r in self.inc[o["id"]] if r["relationship_type"] == "mitigates"],
                             "source_ref")
        if mit:
            secs.append(("Mitigations", "\n".join(mit)))

        proc = self.rel_lines([r for r in self.inc[o["id"]] if r["relationship_type"] == "uses"],
                              "source_ref")
        if proc:
            secs.append(("Procedure Examples", "\n".join(proc)))

        det = []
        for r in self.inc[o["id"]]:
            if r["relationship_type"] != "detects":
                continue
            ds = self.byid[r["source_ref"]]
            det.append(f"{ext_id(ds)} {ds['name']}")
            for aref in ds.get("x_mitre_analytic_refs", []):
                a = self.byid.get(aref)
                if not a:
                    continue
                logs = "; ".join(f"{ls.get('name')} ({ls.get('channel')})"
                                 for ls in a.get("x_mitre_log_source_references", []))
                plat = ", ".join(a.get("x_mitre_platforms", []))
                det.append(f"  {ext_id(a)} [{plat}]: {normalise_text(a.get('description'))}"
                           + (f" Log sources: {logs}" if logs else ""))
        if det:
            secs.append(("Detection Strategies", "\n".join(det)))
        return self._doc(o, "technique", secs)

    def mitigation(self, o: dict) -> dict:
        secs = [("Description", f"{ext_id(o)}: {o['name']}\nType: mitigation\n\n"
                 + normalise_text(o.get("description")))]
        lines = self.rel_lines([r for r in self.out[o["id"]] if r["relationship_type"] == "mitigates"],
                               "target_ref")
        if lines:
            secs.append(("Techniques Addressed", "\n".join(lines)))
        return self._doc(o, "mitigation", secs)

    def software(self, o: dict) -> dict:
        meta = [f"Type: {'malware' if o['type']=='malware' else 'tool'}"]
        if o.get("x_mitre_platforms"):
            meta.append("Platforms: " + ", ".join(o["x_mitre_platforms"]))
        if o.get("x_mitre_aliases"):
            meta.append("Associated software: " + ", ".join(o["x_mitre_aliases"]))
        secs = [("Description", f"{ext_id(o)}: {o['name']}\n" + " | ".join(meta)
                 + "\n\n" + normalise_text(o.get("description")))]
        used = self.rel_lines([r for r in self.out[o["id"]] if r["relationship_type"] == "uses"],
                              "target_ref", {"attack-pattern"})
        if used:
            secs.append(("Techniques Used", "\n".join(used)))
        groups = self.rel_lines([r for r in self.inc[o["id"]] if r["relationship_type"] == "uses"],
                                "source_ref", {"intrusion-set", "campaign"})
        if groups:
            secs.append(("Groups and Campaigns That Use This Software", "\n".join(groups)))
        return self._doc(o, "software", secs)

    def group(self, o: dict) -> dict:
        meta = ["Type: group"]
        if o.get("aliases"):
            meta.append("Associated groups: " + ", ".join(o["aliases"]))
        secs = [("Description", f"{ext_id(o)}: {o['name']}\n" + " | ".join(meta)
                 + "\n\n" + normalise_text(o.get("description")))]
        tech = self.rel_lines([r for r in self.out[o["id"]] if r["relationship_type"] == "uses"],
                              "target_ref", {"attack-pattern"})
        if tech:
            secs.append(("Techniques Used", "\n".join(tech)))
        sw = self.rel_lines([r for r in self.out[o["id"]] if r["relationship_type"] == "uses"],
                            "target_ref", {"malware", "tool"})
        if sw:
            secs.append(("Software Used", "\n".join(sw)))
        camps = self.rel_lines([r for r in self.inc[o["id"]] if r["relationship_type"] == "attributed-to"],
                               "source_ref")
        if camps:
            secs.append(("Campaigns", "\n".join(camps)))
        return self._doc(o, "group", secs)

    def campaign(self, o: dict) -> dict:
        meta = ["Type: campaign"]
        if o.get("aliases"):
            meta.append("Associated campaigns: " + ", ".join(o["aliases"]))
        if o.get("first_seen"):
            meta.append(f"First seen: {o['first_seen'][:7]}")
        if o.get("last_seen"):
            meta.append(f"Last seen: {o['last_seen'][:7]}")
        secs = [("Description", f"{ext_id(o)}: {o['name']}\n" + " | ".join(meta)
                 + "\n\n" + normalise_text(o.get("description")))]
        attr = self.rel_lines([r for r in self.out[o["id"]] if r["relationship_type"] == "attributed-to"],
                              "target_ref")
        if attr:
            secs.append(("Attributed To", "\n".join(attr)))
        tech = self.rel_lines([r for r in self.out[o["id"]] if r["relationship_type"] == "uses"],
                              "target_ref", {"attack-pattern"})
        if tech:
            secs.append(("Techniques Used", "\n".join(tech)))
        sw = self.rel_lines([r for r in self.out[o["id"]] if r["relationship_type"] == "uses"],
                            "target_ref", {"malware", "tool"})
        if sw:
            secs.append(("Software Used", "\n".join(sw)))
        return self._doc(o, "campaign", secs)

    def tactic(self, o: dict) -> dict:
        secs = [("Description", f"{ext_id(o)}: {o['name']}\nType: tactic\n\n"
                 + normalise_text(o.get("description")))]
        techs = sorted((ext_id(t), t["name"]) for t in self.live.values()
                       if t["type"] == "attack-pattern" and not t.get("x_mitre_is_subtechnique")
                       and o in self.tactics_of(t))
        if techs:
            secs.append(("Techniques", "\n".join(f"{i}: {n}" for i, n in techs)))
        return self._doc(o, "tactic", secs)

    def _doc(self, o: dict, etype: str, secs) -> dict:
        eid = ext_id(o)
        url = next((r["url"] for r in o["external_references"] if r.get("source_name") == "mitre-attack"), "")
        return {
            "doc_id": f"attack:{eid}",
            "source": f"MITRE ATT&CK Enterprise v{ATTACK_VERSION}",
            "entity_id": eid,
            "entity_name": self.full_name(o),
            "entity_type": etype,
            "url": url,
            "sections": [{"name": n, "text": t} for n, t in secs if t],
        }

    def render_all(self, limit: int | None = None):
        dispatch = {"attack-pattern": self.technique, "course-of-action": self.mitigation,
                    "malware": self.software, "tool": self.software, "intrusion-set": self.group,
                    "campaign": self.campaign, "x-mitre-tactic": self.tactic}
        docs = []
        for o in sorted(self.live.values(), key=lambda x: ext_id(x) or ""):
            if o["type"] in dispatch and ext_id(o):
                docs.append(dispatch[o["type"]](o))
                if limit and len(docs) >= limit:
                    break
        return docs


def to_markdown(doc: dict) -> str:
    head = f"# {doc['entity_id']} — {doc['entity_name']}\n{doc['source']} | {doc['url']}\n"
    body = "\n".join(f"\n## {s['name']}\n{s['text']}\n" for s in doc["sections"])
    return head + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int)
    ap.add_argument("--only", nargs="*", help="render only these ATT&CK IDs")
    args = ap.parse_args()

    atk = Attack(load_bundle(ATTACK_BUNDLE))
    if args.only:
        docs = [getattr(atk, {"attack-pattern": "technique", "course-of-action": "mitigation",
                              "malware": "software", "tool": "software", "intrusion-set": "group",
                              "campaign": "campaign", "x-mitre-tactic": "tactic"}[atk.ext[i]["type"]])(atk.ext[i])
                for i in args.only]
    else:
        docs = atk.render_all(args.limit)

    out_dir = KB / "attack"
    out_dir.mkdir(parents=True, exist_ok=True)
    for d in docs:
        (out_dir / f"{d['entity_id']}.md").write_text(to_markdown(d))
    if not args.only and not args.limit:
        n = write_jsonl(KB / "docs_attack.jsonl", docs)
        print(f"wrote {n} docs -> {KB/'docs_attack.jsonl'}")
    by_type = collections.Counter(d["entity_type"] for d in docs)
    by_sec = collections.Counter(s["name"] for d in docs for s in d["sections"])
    print("entities:", dict(by_type))
    print("sections:", dict(by_sec))
    print(f"pages written to {out_dir} ({len(docs)})")


if __name__ == "__main__":
    main()
