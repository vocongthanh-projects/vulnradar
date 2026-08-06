import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnradar.db.crud import upsert_entries
from vulnradar.db.models import Base, Entry


def _cve(source, in_kev=False, cvss_score=None):
    return {
        "source": source,
        "source_id": "CVE-2099-0001",
        "title": "Synthetic vulnerability",
        "summary": "Synthetic test data",
        "entry_type": "cve",
        "lang_tags": [],
        "vuln_tags": ["auth-bypass"],
        "cvss_score": cvss_score,
        "in_kev": in_kev,
        "raw_data": {},
    }


class CrudTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_cve_is_deduplicated_across_sources_and_keeps_kev(self):
        self.assertEqual(upsert_entries(self.db, [_cve("nvd", cvss_score=9.8)]), (1, 0))
        self.assertEqual(upsert_entries(self.db, [_cve("cisa_kev", in_kev=True)]), (0, 1))

        records = self.db.query(Entry).all()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].source, "nvd")
        self.assertTrue(records[0].in_kev)
        self.assertEqual(records[0].cvss_score, 9.8)
