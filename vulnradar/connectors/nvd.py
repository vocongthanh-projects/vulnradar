import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import requests
from dotenv import load_dotenv

from vulnradar.connectors.base import BaseConnector

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def extract_vuln_tags_from_text(text: str) -> List[str]:
    """Extracts vulnerability tags from description text."""
    if not text:
        return ["general-cve"]

    text_lower = text.lower()
    tags = []
    keyword_map = {
        "sql injection": "sqli",
        "sqli": "sqli",
        "cross-site scripting": "xss",
        "xss": "xss",
        "server-side request forgery": "ssrf",
        "ssrf": "ssrf",
        "remote code execution": "rce",
        "command injection": "rce",
        "code execution": "rce",
        "xml external entity": "xxe",
        "xxe": "xxe",
        "path traversal": "path-traversal",
        "directory traversal": "path-traversal",
        "buffer overflow": "buffer-overflow",
        "memory corruption": "memory-corruption",
        "use after free": "memory-corruption",
        "privilege escalation": "privilege-escalation",
        "elevation of privilege": "privilege-escalation",
        "denial of service": "dos",
        "authentication bypass": "auth-bypass",
        "authorization bypass": "auth-bypass",
        "insecure deserialization": "deserialization",
        "deserialization": "deserialization",
        "cross-site request forgery": "csrf",
        "csrf": "csrf",
        "information disclosure": "info-leak",
    }
    for kw, tag in keyword_map.items():
        if kw in text_lower and tag not in tags:
            tags.append(tag)
    return tags if tags else ["general-cve"]

class NVDConnector(BaseConnector):
    source_name: str = "nvd"

    def __init__(self):
        load_dotenv()
        self.api_key = os.getenv("NVD_API_KEY", "").strip()
        self.is_complete: bool = True
        self.total_expected: int = 0
        self.total_fetched: int = 0
        self.failed_at_page: int = 0

    def fetch(self, days: int = 7) -> List[Dict[str, Any]]:
        self.is_complete = True
        self.total_expected = 0
        self.total_fetched = 0
        self.failed_at_page = 0

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        pub_start = start_time.strftime("%Y-%m-%dT00:00:00.000")
        pub_end = end_time.strftime("%Y-%m-%dT23:59:59.999")

        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
            delay = 0.2
        else:
            delay = 0.7

        records = []
        start_index = 0
        results_per_page = 500
        page_num = 0

        while True:
            page_num += 1
            params = {
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "resultsPerPage": results_per_page,
                "startIndex": start_index
            }
            print(f"[*] Querying NVD API (page {page_num}, startIndex={start_index})...")

            max_retries = 3
            retry_delays = [5, 10, 20]
            resp = None
            page_success = False

            for attempt in range(1, max_retries + 1):
                try:
                    resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=60)

                    # Handle invalid API key (403 or 404 from NVD)
                    if resp.status_code in [403, 404] and "apiKey" in headers:
                        print("    [!] CẢNH BÁO: NVD_API_KEY không hợp lệ. Tự động chuyển sang chế độ không dùng API Key...")
                        headers.pop("apiKey", None)
                        delay = 0.7
                        resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=60)

                    if resp.status_code == 200:
                        page_success = True
                        break
                    elif resp.status_code in [403, 429, 503, 504]:
                        print(f"    [!] HTTP {resp.status_code} on page {page_num} (attempt {attempt}/{max_retries}). Waiting {retry_delays[attempt-1]}s...")
                    else:
                        print(f"    [!] HTTP {resp.status_code} on page {page_num} (attempt {attempt}/{max_retries})...")
                except Exception as e:
                    print(f"    [!] Connection error on page {page_num} (attempt {attempt}/{max_retries}): {e}")

                if attempt < max_retries:
                    time.sleep(retry_delays[attempt - 1])

            if not page_success or not resp:
                print(f"[!] ⚠ CẢNH BÁO: Ingest NVD dừng sớm tại page {page_num} do lỗi kết nối/API sau {max_retries} lần thử.")
                self.is_complete = False
                self.failed_at_page = page_num
                break

            data = resp.json()
            if page_num == 1:
                self.total_expected = data.get("totalResults", 0)
                print(f"[*] NVD API Report: Total expected CVEs in last {days} days = {self.total_expected}")

            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities:
                cve_dict = item.get("cve", {})
                cve_id = cve_dict.get("id")
                if not cve_id:
                    continue

                # Extract English summary
                descriptions = cve_dict.get("descriptions", [])
                summary = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        summary = d.get("value", "")
                        break
                if not summary and descriptions:
                    summary = descriptions[0].get("value", "")

                # Published date
                pub_str = cve_dict.get("published")
                published_date = None
                if pub_str:
                    try:
                        published_date = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
                    except Exception:
                        published_date = None

                # CVSS Score
                metrics = cve_dict.get("metrics", {})
                cvss_score = None
                for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if metric_key in metrics and metrics[metric_key]:
                        cvss_data = metrics[metric_key][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        if cvss_score is not None:
                            cvss_score = float(cvss_score)
                            break

                # Vuln tags
                vuln_tags = extract_vuln_tags_from_text(summary)

                # Title
                short_desc = (summary[:80] + "...") if len(summary) > 80 else summary
                title = f"{cve_id} - {short_desc}" if short_desc else cve_id

                record = {
                    "source": self.source_name,
                    "source_id": cve_id,
                    "title": title,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "summary": summary,
                    "published_date": published_date,
                    "entry_type": "cve",
                    "lang_tags": [],
                    "vuln_tags": vuln_tags,
                    "cvss_score": cvss_score,
                    "epss_score": None,
                    "in_kev": False,
                    "raw_data": cve_dict
                }
                records.append(record)

            start_index += len(vulnerabilities)
            if start_index >= self.total_expected or not vulnerabilities:
                break

            time.sleep(delay)

        self.total_fetched = len(records)
        return records
