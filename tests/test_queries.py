import unittest
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnradar.db.models import Base, Entry
from vulnradar.db.search import search_entries
from vulnradar.digest import get_digest_entries


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()
        now = datetime.now(timezone.utc)
        self.db.add_all(
            [
                Entry(
                    source="nvd",
                    source_id="CVE-2099-0001",
                    title="Critical auth bypass",
                    summary="Authentication bypass in a Java service",
                    entry_type="cve",
                    lang_tags=["java"],
                    vuln_tags=["auth-bypass"],
                    cvss_score=9.8,
                    in_kev=True,
                    fetched_at=now,
                ),
                Entry(
                    source="nvd",
                    source_id="CVE-2099-0002",
                    title="Low impact information leak",
                    summary="Minor information disclosure",
                    entry_type="cve",
                    lang_tags=["python"],
                    vuln_tags=["info-leak"],
                    cvss_score=3.1,
                    in_kev=False,
                    fetched_at=now,
                ),
            ]
        )
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_search_combines_keyword_and_tag_filters(self):
        results = search_entries(
            self.db,
            keyword="auth",
            lang="java",
            vuln_type="auth-bypass",
        )
        self.assertEqual([entry.source_id for entry in results], ["CVE-2099-0001"])

    def test_digest_orders_by_explainable_priority(self):
        digest = get_digest_entries(self.db, since_str="1d")
        self.assertEqual(digest["total_count"], 2)
        self.assertEqual(digest["kev_count"], 1)
        self.assertEqual(digest["entries"][0].source_id, "CVE-2099-0001")
