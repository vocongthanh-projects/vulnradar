import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from vulnradar.connectors.base import BaseConnector

REPO_URL = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
CACHE_DIR = Path(__file__).resolve().parent.parent / "cache" / "PayloadsAllTheThings"

# Explicit 1-to-1 mapping for ALL directories in PayloadsAllTheThings
VULN_TAG_MAP = {
    "API Key Leaks": ["api-key-leak"],
    "Account Takeover": ["account-takeover"],
    "Brute Force Rate Limit": ["brute-force", "rate-limit"],
    "Business Logic Errors": ["business-logic"],
    "CORS Misconfiguration": ["cors"],
    "CRLF Injection": ["crlf"],
    "CSS Injection": ["css-injection"],
    "CSV Injection": ["csv-injection"],
    "CVE Exploits": ["cve"],
    "Clickjacking": ["clickjacking"],
    "Client Side Path Traversal": ["cspt", "path-traversal"],
    "Command Injection": ["rce", "command-injection"],
    "Cross-Site Request Forgery": ["csrf"],
    "DNS Rebinding": ["dns-rebinding"],
    "DOM Clobbering": ["dom-clobbering", "xss"],
    "Denial of Service": ["dos"],
    "Dependency Confusion": ["dependency-confusion"],
    "Directory Traversal": ["lfi", "path-traversal"],
    "Encoding Transformations": ["encoding"],
    "External Variable Modification": ["variable-override"],
    "File Inclusion": ["lfi", "rfi"],
    "Google Web Toolkit": ["gwt"],
    "GraphQL Injection": ["graphql"],
    "HTTP Parameter Pollution": ["hpp"],
    "Headless Browser": ["headless-browser"],
    "Hidden Parameters": ["parameter-discovery"],
    "Insecure Deserialization": ["deserialization"],
    "Insecure Direct Object References": ["idor", "bola"],
    "Insecure Management Interface": ["management-interface"],
    "Insecure Randomness": ["insecure-randomness"],
    "Insecure Source Code Management": ["scm-leak"],
    "JSON Web Token": ["jwt"],
    "Java RMI": ["java-rmi"],
    "LDAP Injection": ["ldap"],
    "LaTeX Injection": ["latex-injection"],
    "Mass Assignment": ["mass-assignment"],
    "Methodology and Resources": ["methodology"],
    "NoSQL Injection": ["nosql"],
    "OAuth Misconfiguration": ["oauth"],
    "ORM Leak": ["orm-leak"],
    "Open Redirect": ["open-redirect"],
    "Prompt Injection": ["prompt-injection", "ai"],
    "Prototype Pollution": ["prototype-pollution"],
    "Race Condition": ["race-condition"],
    "Regular Expression": ["regex-dos"],
    "Request Smuggling": ["request-smuggling"],
    "Reverse Proxy Misconfigurations": ["proxy-misconfig"],
    "SAML Injection": ["saml"],
    "SQL Injection": ["sqli"],
    "Server Side Include Injection": ["ssi"],
    "Server Side Request Forgery": ["ssrf"],
    "Server Side Template Injection": ["ssti"],
    "Tabnabbing": ["tabnabbing"],
    "Type Juggling": ["type-juggling"],
    "Upload Insecure Files": ["file-upload"],
    "Virtual Hosts": ["vhost"],
    "Web Cache Deception": ["cache-deception"],
    "Web Sockets": ["websocket"],
    "XPATH Injection": ["xpath"],
    "XS-Leak": ["xs-leak"],
    "XSLT Injection": ["xslt"],
    "XSS Injection": ["xss"],
    "XXE Injection": ["xxe"],
    "Zip Slip": ["zip-slip"],
    "_LEARNING_AND_SOCIALS": ["learning"],
    "_template_vuln": ["template"],
}

def clean_markdown(text: str) -> str:
    """Strips markdown syntax and returns clean plain text summary (up to 300 chars)."""
    # Remove code blocks
    text = re.sub(r'```[\s\S]*?```', '', text)
    # Remove inline code
    text = re.sub(r'`([^`]+)`', r'\1', text)
    # Remove markdown links [text](url) -> text
    text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)
    # Remove headers, bullets, blockquotes
    text = re.sub(r'^[#*>\-\+\s]+', '', text, flags=re.MULTILINE)
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text[:300]

def dir_to_vuln_tags(dir_name: str) -> List[str]:
    """Maps directory name to vuln_tags using explicit dictionary or fallback slugify."""
    if dir_name in VULN_TAG_MAP:
        return VULN_TAG_MAP[dir_name]

    for key, tags in VULN_TAG_MAP.items():
        if key.lower() == dir_name.lower():
            return tags

    # Fallback slugify
    slug = re.sub(r'[^a-zA-Z0-9]+', '-', dir_name.lower()).strip('-')
    return [slug] if slug else ["general"]

class PayloadsAllTheThingsConnector(BaseConnector):
    source_name: str = "payloadsallthethings"

    def __init__(self, repo_dir: Path = CACHE_DIR):
        self.repo_dir = repo_dir

    def ensure_repo(self):
        """Clones PayloadsAllTheThings if not present locally."""
        if not self.repo_dir.exists() or not (self.repo_dir / ".git").exists():
            self.repo_dir.parent.mkdir(parents=True, exist_ok=True)
            print(f"[*] Cloning PayloadsAllTheThings repo into {self.repo_dir}...")
            subprocess.run(
                ["git", "clone", "--depth", "1", REPO_URL, str(self.repo_dir)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        else:
            try:
                subprocess.run(
                    ["git", "pull", "--depth", "1"],
                    cwd=self.repo_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=15
                )
            except Exception:
                pass

    def fetch(self) -> List[Dict[str, Any]]:
        self.ensure_repo()

        records = []
        for root, dirs, files in os.walk(self.repo_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.')]

            rel_root = Path(root).relative_to(self.repo_dir)
            parts = rel_root.parts

            if not parts:
                top_dir = "General"
            else:
                top_dir = parts[0]

            vuln_tags = dir_to_vuln_tags(top_dir)

            for file in files:
                if not file.endswith('.md'):
                    continue

                full_path = Path(root) / file
                rel_path = full_path.relative_to(self.repo_dir)
                source_id = str(rel_path)

                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except Exception:
                    content = ""

                summary = clean_markdown(content)

                # Title formatting
                if file == "README.md":
                    if top_dir == "General":
                        title = "PayloadsAllTheThings - Overview / Root README"
                    else:
                        title = f"PayloadsAllTheThings - {top_dir}"
                        if len(parts) > 1:
                            title += f" / {' / '.join(parts[1:])}"
                else:
                    clean_file_name = file.replace('.md', '').replace('_', ' ').replace('-', ' ').title()
                    if top_dir == "General":
                        title = f"PayloadsAllTheThings - {clean_file_name}"
                    else:
                        title = f"PayloadsAllTheThings - {top_dir} / {clean_file_name}"

                github_url = f"https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/{rel_path}"

                record = {
                    "source": self.source_name,
                    "source_id": source_id,
                    "title": title,
                    "url": github_url,
                    "summary": summary,
                    "published_date": None,
                    "entry_type": "payload_reference",
                    "lang_tags": [],
                    "vuln_tags": vuln_tags,
                    "cvss_score": None,
                    "epss_score": None,
                    "in_kev": False,
                    "raw_data": {
                        "relative_path": str(rel_path),
                        "top_directory": top_dir
                    }
                }
                records.append(record)

        return records
