import re
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import String, and_, cast, or_, select
from sqlalchemy.orm import Session

from vulnradar.db.models import Entry
from vulnradar.priority import priority_for_entry


def parse_since_period(since_str: str) -> Tuple[datetime, timedelta, str]:
    """
    Parses flexible time strings like '1d', '7d', '24h', '48h', '30m'.
    Returns (cutoff_datetime, delta, human_readable_description).
    """
    text = since_str.strip().lower()
    match = re.match(r'^(\d+)\s*([dhm]|days?|hours?|mins?|minutes?)$', text)

    if not match:
        delta = timedelta(days=1)
        period_desc = "1 day (24h)"
    else:
        num = int(match.group(1))
        unit = match.group(2)

        if unit.startswith('d'):
            delta = timedelta(days=num)
            period_desc = f"{num} day(s)"
        elif unit.startswith('h'):
            delta = timedelta(hours=num)
            period_desc = f"{num} hour(s)"
        elif unit.startswith('m'):
            delta = timedelta(minutes=num)
            period_desc = f"{num} minute(s)"
        else:
            delta = timedelta(days=num)
            period_desc = f"{num} day(s)"

    now = datetime.now()
    cutoff = now - delta

    return cutoff, delta, period_desc

def get_digest_entries(
    db: Session,
    since_str: str = "1d",
    lang_str: Optional[str] = None,
    vuln_type: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 50
) -> Dict[str, Any]:
    """
    Retrieves entries fetched since the specified period.
    Prioritizes entries with in_kev=True at the top while preserving full untruncated counts.
    """
    cutoff, delta, period_desc = parse_since_period(since_str)

    stmt = select(Entry).where(Entry.fetched_at >= cutoff)

    conditions = []

    # Multi-language filter (e.g. php,java -> php OR java)
    if lang_str and lang_str.strip():
        langs = [language.strip().lower() for language in lang_str.split(",") if language.strip()]
        if langs:
            lang_conds = [
                cast(Entry.lang_tags, String).ilike(f"%{language}%")
                for language in langs
            ]
            conditions.append(or_(*lang_conds))

    # Shared matching logic with search.py
    if vuln_type and vuln_type.strip():
        type_pattern = f"%{vuln_type.strip().lower()}%"
        conditions.append(cast(Entry.vuln_tags, String).ilike(type_pattern))

    if source and source.strip():
        conditions.append(Entry.source.ilike(source.strip()))

    if conditions:
        stmt = stmt.where(and_(*conditions))

    # Order with in_kev=True FIRST, then fetched_at DESC
    stmt = stmt.order_by(Entry.in_kev.desc(), Entry.fetched_at.desc())

    # Get full untruncated result list to calculate exact totals
    all_untruncated = list(db.execute(stmt).scalars().all())
    all_untruncated.sort(
        key=lambda entry: (priority_for_entry(entry).score, entry.fetched_at),
        reverse=True,
    )
    unlimited_total = len(all_untruncated)
    unlimited_kev = sum(1 for e in all_untruncated if e.in_kev)
    unlimited_non_kev = unlimited_total - unlimited_kev

    if limit and limit > 0:
        displayed_entries = all_untruncated[:limit]
    else:
        displayed_entries = all_untruncated

    return {
        "entries": displayed_entries,
        "total_count": unlimited_total,
        "kev_count": unlimited_kev,
        "non_kev_count": unlimited_non_kev,
        "displayed_count": len(displayed_entries),
        "period_desc": period_desc,
        "cutoff": cutoff
    }
