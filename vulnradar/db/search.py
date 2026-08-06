from typing import List, Optional

from sqlalchemy import String, and_, cast, or_, select
from sqlalchemy.orm import Session

from vulnradar.db.models import Entry


def search_entries(
    db: Session,
    keyword: Optional[str] = None,
    lang: Optional[str] = None,
    vuln_type: Optional[str] = None,
    source: Optional[str] = None,
    in_kev: Optional[bool] = None,
    limit: int = 20
) -> List[Entry]:
    """
    Search entries in database with full-text keyword matching and filters.
    """
    stmt = select(Entry)

    conditions = []

    if keyword and keyword.strip():
        kw_pattern = f"%{keyword.strip()}%"
        conditions.append(
            or_(
                Entry.title.ilike(kw_pattern),
                Entry.summary.ilike(kw_pattern)
            )
        )

    if source and source.strip():
        conditions.append(Entry.source.ilike(source.strip()))

    if in_kev:
        conditions.append(Entry.in_kev.is_(True))

    if lang and lang.strip():
        lang_pattern = f"%{lang.strip().lower()}%"
        conditions.append(
            or_(
                cast(Entry.lang_tags, String).ilike(lang_pattern),
                Entry.title.ilike(lang_pattern),
                Entry.summary.ilike(lang_pattern)
            )
        )

    if vuln_type and vuln_type.strip():
        type_pattern = f"%{vuln_type.strip().lower()}%"
        conditions.append(
            or_(
                cast(Entry.vuln_tags, String).ilike(type_pattern),
                Entry.title.ilike(type_pattern),
                Entry.summary.ilike(type_pattern)
            )
        )

    if conditions:
        stmt = stmt.where(and_(*conditions))

    # Order by published_date descending (nulls last) or fetched_at descending
    stmt = stmt.order_by(Entry.published_date.desc().nulls_last(), Entry.fetched_at.desc())
    if limit > 0:
        stmt = stmt.limit(limit)

    return list(db.execute(stmt).scalars().all())
