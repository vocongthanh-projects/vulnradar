from typing import Any, Dict, List


class BaseConnector:
    """Base Interface for all VulnRadar data connectors."""
    source_name: str = "base"

    def fetch(self) -> List[Dict[str, Any]]:
        """
        Fetch and parse records from the data source.
        Returns a list of dicts matching the Entry schema fields:
        - source (str)
        - source_id (str)
        - title (str)
        - url (Optional[str])
        - summary (Optional[str])
        - published_date (Optional[datetime])
        - entry_type (str: "cve" | "writeup" | "payload_reference")
        - lang_tags (List[str])
        - vuln_tags (List[str])
        - cvss_score (Optional[float])
        - epss_score (Optional[float])
        - in_kev (bool)
        - raw_data (Optional[dict])
        """
        raise NotImplementedError("Subclasses must implement fetch()")
