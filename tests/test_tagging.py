import unittest

from vulnradar.tagging import merge_entry_tags


class TaggingTests(unittest.TestCase):
    def test_tag_merge_normalizes_and_replaces_generic_tag(self):
        lang, vuln = merge_entry_tags(
            entry_lang_tags=[],
            entry_vuln_tags=["general-cve"],
            predicted_lang=["dotnet"],
            predicted_vuln=["auth-bypass", "not-canonical"],
        )
        self.assertEqual(lang, ["csharp"])
        self.assertEqual(vuln, ["auth-bypass"])
