import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass

class Entry(Base):
    __tablename__ = "entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    summary_vi: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    published_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    entry_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # "cve", "writeup", "payload_reference"
    lang_tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    vuln_tags: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    raw_data: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Progress & Solved Tracking
    is_solved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    solved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    solved_payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    solved_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Viewed / Read Tracking
    is_viewed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    viewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    view_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Optional local project tags (for example ["payments", "public-api"]).
    projects: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    __table_args__ = (
        UniqueConstraint("source", "source_id", name="uq_source_source_id"),
    )

    def __repr__(self) -> str:
        return f"<Entry(source='{self.source}', source_id='{self.source_id}', title='{self.title[:30]}...')>"
