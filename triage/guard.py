"""A deterministic check that runs before the model: text in log data that talks to the triage.

Usernames, hostnames and request fields never legitimately contain sentences addressed to an AI or
to the SOC, so a match is escalated regardless of what the model says. It is a tripwire for the
obvious attempts, not a complete defence: a payload can avoid these words, which is why the
hardened prompt and the model's own judgement still matter.
"""

from __future__ import annotations

import re

PATTERNS = [
    r"\b(ignore|disregard|override)\b.{0,40}\b(previous|prior|above|instructions?|rules?)\b",
    r"\b(classify|mark|label|treat|close|resolve)\b.{0,30}\b(as|this)\b.{0,30}"
    r"\b(close[d]?|benign|false positive|safe|expected)\b",
    r"\b(automated|ai|llm|gpt|assistant|triage)\b.{0,20}\b(note|instruction|message|system)\b",
    r"\b(note|message|instruction)s?\b.{0,10}\bto\b.{0,20}\b(ai|triage|soc|analyst|assistant)\b",
    r"\b(approved|authori[sz]ed|sanctioned)\b.{0,30}\b(red[- ]?team|pen(etration)?[- ]?test|exercise)\b",
]
_RX = [re.compile(p, re.I) for p in PATTERNS]


def strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    return []


def findings(case: dict) -> list[str]:
    """Field values that look like instructions to the triage, de-duplicated."""
    hits = []
    for text in strings(case["summary"]):
        if any(rx.search(text) for rx in _RX) and text not in hits:
            hits.append(text)
    return hits
