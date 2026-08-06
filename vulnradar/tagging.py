import json
import os
import re
from typing import Any, Dict, List, Tuple

import anthropic
from sqlalchemy.orm import Session

from vulnradar.db.models import Entry

MODEL_NAME = os.getenv("VULNRADAR_TAG_MODEL", "claude-haiku-4-5-20251001")

CANONICAL_VULN_TAGS = [
    "sqli", "xss", "ssrf", "xxe", "ssti", "idor", "deserialization", "csrf",
    "race-condition", "prototype-pollution", "lfi", "rfi", "open-redirect", "jwt",
    "cors", "rce", "auth-bypass", "buffer-overflow", "memory-corruption",
    "privilege-escalation", "dos", "info-leak", "subdomain-takeover",
    "account-takeover", "api", "oauth", "waf-bypass", "cms", "websockets",
    "hpp", "host-header-injection", "http-desync", "phishing", "weak-credentials",
    "middleware", "path-traversal", "rate-limit", "hardcoded-credentials", "insecure-defaults"
]

CANONICAL_LANG_TAGS = [
    "php", "java", "python", "node", "js", "go", "ruby", "wordpress", "django",
    "spring", "express", "laravel", "asp", "csharp", "rails", "aws",
    "docker", "kubernetes", "graphql", "nginx", "apache"
]

LANG_SYNONYMS = {
    "dotnet": "csharp",
    ".net": "csharp",
    "asp.net": "csharp",
    "golang": "go",
    "javascript": "js"
}

SYSTEM_PROMPT = f"""You are an automated security vulnerability tagger.
Given a batch of vulnerability entries (each with index, title, and summary), categorize them using CANONICAL tags.

STRICT RULES:
1. ONLY use tags from these allowed canonical lists:
   - Allowed vuln_tags: {', '.join(CANONICAL_VULN_TAGS)}
   - Allowed lang_tags: {', '.join(CANONICAL_LANG_TAGS)}
2. DO NOT use 'dotnet', use 'csharp' for .NET/C# technologies.
3. MULTI-DIMENSIONAL TAGGING: Provide BOTH ROOT CAUSE tags (e.g. hardcoded-credentials, sqli, auth-bypass, deserialization, buffer-overflow, insecure-defaults, xss, ssrf) AND IMPACT tags (e.g. rce, dos, info-leak, privilege-escalation) whenever described. Do NOT limit to only final impact if root cause is specified.
4. If no language/tech tag applies, return empty list [] for lang_tags.
5. If no specific vulnerability tag applies, return empty list [] for vuln_tags.
6. Output MUST BE ONLY A RAW JSON ARRAY. No explanations, no markdown formatting, no ```json blocks.

Required JSON Structure:
[
  {{"index": 0, "lang_tags": ["php"], "vuln_tags": ["sqli"]}},
  {{"index": 1, "lang_tags": [], "vuln_tags": ["hardcoded-credentials", "rce"]}}
]
"""

def clean_tag_value(tag: str, is_lang: bool = False) -> str:
    cleaned = tag.strip().lower()
    if is_lang and cleaned in LANG_SYNONYMS:
        return LANG_SYNONYMS[cleaned]
    return cleaned

def get_target_entries(db: Session, missing_only: bool = True, limit: int = 100) -> List[Entry]:
    """
    Retrieves entries needing LLM auto-tagging.
    If missing_only is True, selects entries where vuln_tags is empty OR vuln_tags == ['general-cve'].
    If limit <= 0, returns ALL matching target entries without a limit.
    """
    all_entries = db.query(Entry).order_by(Entry.id.desc()).all()
    targets = []

    for entry in all_entries:
        v_tags = entry.vuln_tags or []

        if missing_only:
            # An entry needs tagging if its vulnerability classification is missing or generic fallback
            needs_tag = (
                len(v_tags) == 0 or
                (len(v_tags) == 1 and v_tags[0] == "general-cve")
            )
        else:
            needs_tag = True

        if needs_tag:
            targets.append(entry)
            if limit and limit > 0 and len(targets) >= limit:
                break

    return targets

def merge_entry_tags(
    entry_lang_tags: List[str],
    entry_vuln_tags: List[str],
    predicted_lang: List[str],
    predicted_vuln: List[str]
) -> Tuple[List[str], List[str]]:
    """
    UNION MERGE POLICY:
    1. If entry_lang_tags is empty -> Fill with cleaned predicted_lang tags.
       If entry_lang_tags is non-empty -> Keep existing tags and append new predicted lang tags.
    2. If entry_vuln_tags is ['general-cve'] or empty -> Replace with cleaned predicted_vuln tags.
       If entry_vuln_tags has specific tags -> Keep existing tags and append new predicted vuln tags.
    """
    # 1. Process Lang Tags
    final_lang = list(entry_lang_tags or [])
    for tag in predicted_lang:
        c_tag = clean_tag_value(tag, is_lang=True)
        if c_tag and c_tag in CANONICAL_LANG_TAGS and c_tag not in final_lang:
            final_lang.append(c_tag)

    # 2. Process Vuln Tags
    existing_v = list(entry_vuln_tags or [])
    if existing_v == ["general-cve"]:
        existing_v = []

    final_vuln = list(existing_v)
    for tag in predicted_vuln:
        c_tag = clean_tag_value(tag, is_lang=False)
        if c_tag and c_tag in CANONICAL_VULN_TAGS and c_tag not in final_vuln:
            final_vuln.append(c_tag)

    if not final_vuln:
        final_vuln = ["general-cve"]

    return final_lang, final_vuln

def parse_json_response(response_text: str) -> List[Dict[str, Any]]:
    """Cleans markdown syntax and parses JSON array response."""
    text = response_text.strip()

    if text.startswith("```"):
        text = re.sub(r'^```(?:json)?\s*', '', text)
        text = re.sub(r'\s*```$', '', text)

    text = text.strip()
    data = json.loads(text)
    if isinstance(data, list):
        return data
    raise ValueError("LLM response is not a JSON array")

def process_tagging_batch(
    client: anthropic.Anthropic,
    batch_entries: List[Entry]
) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Sends a batch of entries to Claude API and returns predicted tags with token stats.
    """
    batch_input = []
    for idx, entry in enumerate(batch_entries):
        summary_short = (entry.summary[:250] + "...") if entry.summary and len(entry.summary) > 250 else (entry.summary or "")
        batch_input.append({
            "index": idx,
            "title": entry.title,
            "summary": summary_short
        })

    user_message = json.dumps(batch_input, ensure_ascii=False, indent=2)

    response = client.messages.create(
        model=MODEL_NAME,
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}]
    )

    response_text = response.content[0].text
    parsed_items = parse_json_response(response_text)

    input_tokens = getattr(response.usage, "input_tokens", 0)
    output_tokens = getattr(response.usage, "output_tokens", 0)

    return parsed_items, input_tokens, output_tokens
