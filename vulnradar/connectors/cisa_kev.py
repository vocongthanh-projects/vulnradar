from datetime import datetime, timezone
from typing import Any, Dict, List

import requests

from vulnradar.connectors.base import BaseConnector
from vulnradar.connectors.nvd import extract_vuln_tags_from_text

CISA_KEV_PRIMARY_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_GITHUB_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

class CISAKEVConnector(BaseConnector):
    source_name: str = "cisa_kev"

    def fetch(self) -> List[Dict[str, Any]]:
        print("[*] Fetching CISA Known Exploited Vulnerabilities (KEV) catalog...")
        records = []
        resp = None

        # Try primary URL first
        try:
            resp = requests.get(CISA_KEV_PRIMARY_URL, headers=HEADERS, timeout=15)
            if resp.status_code != 200:
                resp = None
        except Exception:
            resp = None

        # Fallback to official cisagov GitHub mirror if primary blocked by Akamai/403
        if resp is None or resp.status_code != 200:
            try:
                resp = requests.get(CISA_KEV_GITHUB_URL, headers=HEADERS, timeout=15)
            except Exception as e:
                print(f"[-] Error fetching CISA KEV from GitHub mirror: {e}")
                return []

        if not resp or resp.status_code != 200:
            print(f"[-] CISA KEV Feed Error HTTP {resp.status_code if resp else 'No response'}")
            return []

        try:
            data = resp.json()
            items = data.get("vulnerabilities", [])

            for item in items:
                cve_id = item.get("cveID")
                if not cve_id:
                    continue

                vuln_name = item.get("vulnerabilityName", "")
                short_desc = item.get("shortDescription", "")
                required_action = item.get("requiredAction", "")
                date_added = item.get("dateAdded")

                published_date = None
                if date_added:
                    try:
                        published_date = datetime.strptime(date_added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    except Exception:
                        published_date = None

                full_desc = f"{vuln_name}. {short_desc} Required Action: {required_action}".strip()
                vuln_tags = extract_vuln_tags_from_text(full_desc)

                title = f"{cve_id} - {vuln_name}" if vuln_name else f"{cve_id} - {short_desc[:60]}"

                record = {
                    "source": self.source_name,
                    "source_id": cve_id,
                    "title": title,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "summary": full_desc,
                    "published_date": published_date,
                    "entry_type": "cve",
                    "lang_tags": [],
                    "vuln_tags": vuln_tags,
                    "cvss_score": None,
                    "epss_score": None,
                    "in_kev": True,
                    "raw_data": item
                }
                records.append(record)

        except Exception as e:
            print(f"[-] Exception while parsing CISA KEV Feed: {e}")

        return records
