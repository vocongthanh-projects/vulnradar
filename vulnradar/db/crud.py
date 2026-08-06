import logging
from typing import Any, Dict, List, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnradar.db.models import Entry

logger = logging.getLogger("vulnradar.crud")

def upsert_entries(db: Session, entries_data: List[Dict[str, Any]]) -> Tuple[int, int]:
    """
    Inserts or updates entries in the database.
    For CVE entries (entry_type == "cve"), deduplication matches on source_id (CVE ID)
    across ALL sources so that NVD and CISA KEV entries update the same single record
    and preserve in_kev=True without creating duplicate rows.
    """
    inserted_count = 0
    updated_count = 0

    if not entries_data:
        return (0, 0)

    for data in entries_data:
        source = data.get("source")
        source_id = data.get("source_id")
        entry_type = data.get("entry_type")

        if not source or not source_id:
            continue

        existing = None

        # For CVEs, match primarily on source_id across all sources
        if entry_type == "cve":
            existing = db.execute(
                select(Entry).where(Entry.source_id == source_id, Entry.entry_type == "cve")
            ).scalars().first()
        else:
            existing = db.execute(
                select(Entry).where(Entry.source == source, Entry.source_id == source_id)
            ).scalar_one_or_none()

        if existing:
            # Update fields on existing entry
            for key, val in data.items():
                if key in ["id", "source", "fetched_at"]:
                    continue
                if hasattr(existing, key):
                    if key == "in_kev":
                        existing.in_kev = existing.in_kev or bool(val)
                    elif val is not None:
                        # For summary/title, prefer detailed text if existing is shorter
                        if key == "summary" and existing.summary and len(existing.summary) > len(str(val)):
                            continue
                        setattr(existing, key, val)
            updated_count += 1
        else:
            # Insert new entry
            entry = Entry(**data)
            db.add(entry)
            inserted_count += 1

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Error during db commit in upsert_entries: {e}")
        raise e

    return (inserted_count, updated_count)
