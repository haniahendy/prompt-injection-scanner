"""Weighted pattern rules.

Each rule is (name, category, weight, compiled regex). Weights feed the
aggregate risk score; a single weak hit should stay below the medium
threshold, while a strong override phrase or two medium hits cross it.
Patterns are deliberately simple (no nested quantifiers) so matching cost
stays linear-ish on hostile input.
"""

from __future__ import annotations

import re
from typing import List, NamedTuple


class Rule(NamedTuple):
    name: str
    category: str
    weight: int
    pattern: "re.Pattern[str]"


def _rx(p: str) -> "re.Pattern[str]":
    return re.compile(p, re.IGNORECASE)


RULES: List[Rule] = [
    # Instruction override
    Rule("override-ignore-instructions", "instruction_override", 45,
         _rx(r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|your)\s+(?:instructions?|rules?|guidelines?|prompts?)")),
    Rule("override-disregard", "instruction_override", 40,
         _rx(r"\bdisregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|your)\b")),
    Rule("override-forget", "instruction_override", 40,
         _rx(r"\bforget\s+(?:everything|all\s+(?:your|previous)|your\s+(?:instructions?|training|rules?))")),
    Rule("override-new-instructions", "instruction_override", 35,
         _rx(r"\bnew\s+instructions?\s*[:.\-]")),
    Rule("override-do-anything-now", "instruction_override", 40,
         _rx(r"\bdo\s+anything\s+now\b|\bDAN\s+mode\b|\bjailbreak\b")),

    # Persona hijack
    Rule("persona-you-are-now", "persona_hijack", 30,
         _rx(r"\byou\s+are\s+now\s+(?:a|an|the)\b")),
    Rule("persona-act-as-unrestricted", "persona_hijack", 30,
         _rx(r"\bact\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|evil|jailbroken|no.filter)")),
    Rule("persona-pretend-no-rules", "persona_hijack", 30,
         _rx(r"\bpretend\s+(?:you\s+(?:have|are)|to\s+be)\s+(?:no|an?\s+\w*\s*(?:without)\s+)(?:rules|restrictions|filters|limits)")),

    # System-prompt probing
    Rule("probe-reveal-prompt", "prompt_probe", 35,
         _rx(r"\b(?:reveal|show|print|repeat|display|output|tell\s+me)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|system\s+message)\b")),
    Rule("probe-what-were-you-told", "prompt_probe", 25,
         _rx(r"\bwhat\s+(?:were|are)\s+you\s+(?:told|instructed|programmed)\s+to\b")),

    # Exfiltration-shaped requests
    Rule("exfil-send-to-url", "exfiltration", 40,
         _rx(r"\b(?:send|post|forward|upload|transmit)\b[^.\n]{0,40}?\bto\s+https?://")),
    Rule("exfil-encode-and-send", "exfiltration", 30,
         _rx(r"\b(?:encode|encrypt|base64)\s+(?:the\s+)?(?:\w+\s+){0,3}and\s+(?:send|post|email)\b")),

    # Delimiter / markup smuggling
    Rule("delim-chat-markers", "delimiter_injection", 35,
         _rx(r"<\|im_(?:start|end)\|>|<\|system\|>|<\|assistant\|>|\[INST\]|\[/INST\]|<<SYS>>")),
    Rule("delim-fence-system", "delimiter_injection", 30,
         _rx(r"```\s*(?:system|instruction|prompt)\b")),
    Rule("delim-header-instruction", "delimiter_injection", 20,
         _rx(r"^#{1,4}\s*(?:system|new)\s+(?:message|prompt|instructions?)\s*$")),

    # Encoded payloads
    Rule("encoding-base64-blob", "encoded_payload", 20,
         re.compile(r"\b[A-Za-z0-9+/]{48,}={0,2}\b")),
    Rule("encoding-hex-blob", "encoded_payload", 15,
         re.compile(r"\b(?:0x)?[0-9a-fA-F]{64,}\b")),
]

# Zero-width and bidi control characters worth flagging on their own.
INVISIBLE_CHARS = {
    "​": "zero-width space",
    "‌": "zero-width non-joiner",
    "‍": "zero-width joiner",
    "﻿": "byte order mark",
    "‪": "left-to-right embedding",
    "‫": "right-to-left embedding",
    "‮": "right-to-left override",
    "⁦": "left-to-right isolate",
    "⁧": "right-to-left isolate",
    "⁨": "first strong isolate",
    "⁩": "pop directional isolate",
}
INVISIBLE_WEIGHT = 25
