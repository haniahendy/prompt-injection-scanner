"""Scanning engine: normalization, rule matching, risk scoring."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List

from .rules import INVISIBLE_CHARS, INVISIBLE_WEIGHT, RULES

MEDIUM_THRESHOLD = 30
HIGH_THRESHOLD = 60


@dataclass
class Finding:
    rule: str
    category: str
    weight: int
    span: str
    start: int
    end: int
    note: str = ""


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    score: int = 0
    tier: str = "low"
    normalized_changed: bool = False

    def by_category(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return counts


def normalize_text(text: str) -> str:
    """NFKC-normalize and strip invisible format characters.

    Attackers hide ASCII commands behind fullwidth glyphs, accents, or
    zero-width characters; rules match the normalized form.
    """
    normalized = unicodedata.normalize("NFKC", text)
    return "".join(ch for ch in normalized if ch not in INVISIBLE_CHARS)


def _tier(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def scan_text(text: str, *, include_normalized: bool = True) -> ScanResult:
    """Scan one text; returns findings and an aggregate risk tier.

    Scoring: sum of the highest weight per category (stacking many hits of
    the same trick counts once) plus a small bonus per extra category,
    capped at 100.
    """
    result = ScanResult()
    seen_spans = set()

    def _run(haystack: str, note: str = "") -> None:
        for rule in RULES:
            for match in rule.pattern.finditer(haystack):
                key = (rule.name, match.start(), match.end())
                if key in seen_spans:
                    continue
                seen_spans.add(key)
                result.findings.append(Finding(
                    rule=rule.name, category=rule.category,
                    weight=rule.weight, span=match.group(0)[:120],
                    start=match.start(), end=match.end(), note=note))

    _run(text)
    normalized = normalize_text(text)
    if include_normalized and normalized != text:
        result.normalized_changed = True
        _run(normalized, note="matched after Unicode normalization")

    invis = sorted({INVISIBLE_CHARS[ch] for ch in text if ch in INVISIBLE_CHARS})
    if invis:
        result.findings.append(Finding(
            rule="unicode-invisible-chars", category="unicode_evasion",
            weight=INVISIBLE_WEIGHT, span=", ".join(invis),
            start=0, end=0, note="invisible/bidi control characters present"))

    best_per_category: Dict[str, int] = {}
    for f in result.findings:
        best_per_category[f.category] = max(
            best_per_category.get(f.category, 0), f.weight)
    categories = len(best_per_category)
    score = sum(best_per_category.values()) + 5 * max(0, categories - 1)
    result.score = min(100, score)
    result.tier = _tier(result.score)
    return result
