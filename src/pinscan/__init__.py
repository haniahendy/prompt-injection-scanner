"""Heuristic prompt-injection scanner for LLM application pipelines.

Flags text that tries to override instructions, hijack the assistant
persona, probe for the system prompt, exfiltrate data, smuggle control
delimiters, or hide behind encodings and invisible Unicode. Deterministic
pattern rules with weights - a triage layer, not a classifier.
"""

from .scanner import Finding, ScanResult, normalize_text, scan_text
from .report import render_json, render_text

__all__ = ["Finding", "ScanResult", "normalize_text", "scan_text",
           "render_json", "render_text"]

__version__ = "0.1.0"
