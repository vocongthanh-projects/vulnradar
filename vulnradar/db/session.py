import os
from contextlib import contextmanager
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

# Load environment variables
env_path = Path(__file__).resolve().parent.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

# Default SQLite database file path in the vulnradar directory if not specified.
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "vulnradar.db"
DATABASE_URL = os.getenv("VULNRADAR_DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

if DATABASE_URL == f"sqlite:///{DEFAULT_DB_PATH}":
    DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Session:
    """Return a session. The caller owns it and must close it."""
    return SessionLocal()


@contextmanager
def db_session():
    """Yield a session and always close it when the context exits."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Alias for get_db
get_session = get_db


def init_db():
    """Create all tables in the database and ensure schema columns exist."""
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        # Check and migrate columns if missing
        cols = [
            ("summary_vi", "TEXT"),
            ("is_solved", "BOOLEAN DEFAULT 0"),
            ("solved_at", "DATETIME"),
            ("solved_payload", "TEXT"),
            ("solved_notes", "TEXT"),
            ("is_viewed", "BOOLEAN DEFAULT 0"),
            ("viewed_at", "DATETIME"),
            ("view_notes", "TEXT"),
            ("projects", "TEXT DEFAULT '[]'"),
        ]
        for col_name, col_type in cols:
            try:
                conn.execute(text(f"SELECT {col_name} FROM entries LIMIT 1"))
            except Exception:
                try:
                    conn.execute(text(f"ALTER TABLE entries ADD COLUMN {col_name} {col_type}"))
                    conn.commit()
                except Exception:
                    pass
