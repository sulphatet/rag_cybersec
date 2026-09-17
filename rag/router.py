"""Router agent — two-pass query triage (DESIGN §3.2).

Pass 1 (cheap tier): answerable | ambiguous | out_of_scope.
Pass 2 (more capable tier): safe | unsafe — runs on EVERY query, including those
pass 1 called out_of_scope, because the cheap tier can mislabel a dual-use
request as out_of_scope and safety must not depend on that classification.
`unsafe` overrides pass 1 to a refusal.
"""
from __future__ import annotations

from .config import ROLE_ROUTER1, ROLE_ROUTER2
from .llm import call_json

KB_DESCRIPTION = ("a cybersecurity knowledge base covering MITRE ATT&CK Enterprise (adversary "
                  "techniques, mitigations, threat-actor groups, software/malware, campaigns), "
                  "NVD/CVE vulnerability records (CVSS, CWE, affected versions), and NIST SP "
                  "800-61r3 incident-response guidance")

PASS1_SYS = (
    f"You are the triage classifier for a question-answering system whose knowledge base is {KB_DESCRIPTION}.\n"
    "Classify the user's query into exactly one label:\n"
    "- \"answerable\": a clear, specific cybersecurity question that such a KB could plausibly answer.\n"
    "- \"ambiguous\": the query IS about cybersecurity but is under-specified — it refers to "
    "'this'/'it'/'the vulnerability'/'the system' with NO name AND NO description, so there is "
    "nothing concrete to retrieve against until the user clarifies. IMPORTANT: a query that "
    "*describes* a vulnerability, technique, or incident in concrete detail (even without naming a "
    "CVE/ID) is \"answerable\", not ambiguous — the description itself is what we retrieve against. "
    "Only choose ambiguous when there is neither an identifier nor enough description to search on.\n"
    "- \"out_of_scope\": NOT about cybersecurity at all (e.g. cooking, sports, general trivia, "
    "weather). Use this ONLY when the topic itself is non-cybersecurity — never merely because a "
    "cybersecurity question is vague or lacks a name (that is 'ambiguous').\n"
    "Judge only the query's topic and specificity, NOT whether the exact fact is in the KB.\n"
    'Respond with strict JSON only: {"label": "answerable|ambiguous|out_of_scope", '
    '"reason": "<one short clause>", "clarifying_question": "<only if ambiguous, else empty>"}.'
)

PASS2_SYS = (
    "You are a safety classifier for a cybersecurity question-answering system. Decide whether the "
    "query is:\n"
    "- \"safe\": a request to UNDERSTAND or DEFEND against a threat (definitions, impact, detection, "
    "mitigation, which group uses what, CVSS/CWE facts) — the normal work of a SOC analyst.\n"
    "- \"unsafe\": a request for OPERATIONAL ASSISTANCE in conducting an attack — e.g. 'write a working "
    "exploit/payload', step-by-step instructions to compromise or exfiltrate from a system the user "
    "indicates they do not own, or to weaponise a technique against a live target.\n"
    "Explaining how an attack works, for defence, is safe. Providing a ready-to-run attack against a "
    "specific/arbitrary target is unsafe.\n"
    'Respond with strict JSON only: {"label": "safe|unsafe", "reason": "<one short clause>"}.'
)


def _label(parsed, allowed, default):
    if parsed and str(parsed.get("label", "")).strip().lower() in allowed:
        return parsed["label"].strip().lower()
    return default


def route(query: str) -> dict:
    """Return {scope, pass1, pass2, clarifying_question, neurons}."""
    neurons = 0.0
    p1, t1, n1 = call_json(ROLE_ROUTER1, [{"role": "system", "content": PASS1_SYS},
                                          {"role": "user", "content": f"Query: {query}\nJSON:"}],
                           temperature=0.0, max_tokens=160)
    neurons += n1
    label1 = _label(p1, {"answerable", "ambiguous", "out_of_scope"}, "answerable")
    pass1 = {"label": label1, "reason": (p1 or {}).get("reason", ""), "raw": t1}
    result = {"scope": label1, "router_pass1": pass1, "router_pass2": None,
              "clarifying_question": (p1 or {}).get("clarifying_question", "") if label1 == "ambiguous" else "",
              "neurons": neurons}
    # Pass 2 (safety) runs on EVERY query, out_of_scope included: a dual-use
    # request can be mislabelled out_of_scope by the cheap pass-1 tier, and an
    # `unsafe` verdict must be able to override that into an explicit refusal.
    p2, t2, n2 = call_json(ROLE_ROUTER2, [{"role": "system", "content": PASS2_SYS},
                                          {"role": "user", "content": f"Query: {query}\nJSON:"}],
                           temperature=0.0, max_tokens=120)
    neurons += n2
    label2 = _label(p2, {"safe", "unsafe"}, "safe")
    result["router_pass2"] = {"label": label2, "reason": (p2 or {}).get("reason", ""), "raw": t2}
    result["neurons"] = neurons
    if label2 == "unsafe":
        result["scope"] = "unsafe"
        result["clarifying_question"] = ""
    return result
