"""Render scan results as JSON or text."""

from __future__ import annotations

import json

from .scanner import ScanResult


def render_json(result: ScanResult) -> str:
    return json.dumps({
        "score": result.score,
        "tier": result.tier,
        "categories": result.by_category(),
        "normalized_changed": result.normalized_changed,
        "findings": [
            {"rule": f.rule, "category": f.category, "weight": f.weight,
             "span": f.span, "start": f.start, "end": f.end, "note": f.note}
            for f in result.findings
        ],
    }, indent=2)


def render_text(result: ScanResult, label: str = "input") -> str:
    lines = [f"{label}: score={result.score} tier={result.tier}"]
    for f in result.findings:
        note = f" ({f.note})" if f.note else ""
        lines.append(f"  [{f.category}] {f.rule} w={f.weight}: "
                     f"{f.span!r}{note}")
    if not result.findings:
        lines.append("  no findings")
    return "\n".join(lines)
