import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from vulnradar.connectors.base import BaseConnector

HOWTOHUNT_REPO = "https://github.com/KathanP19/HowToHunt.git"
HOLYTIPS_REPO = "https://github.com/HolyBugx/HolyTips.git"

CACHE_DIR = Path(__file__).resolve().parent.parent / "cache"

VULN_TAG_MAP_HOWTOHUNT = {
    "sqli": ["sqli"],
    "ssrf": ["ssrf"],
    "xxe": ["xxe"],
    "jwt": ["jwt"],
    "file_upload": ["file-upload"],
    "idor": ["idor"],
    "rce": ["rce"],
    "ssti": ["ssti"],
    "csrf": ["csrf"],
    "lfi_rfi": ["lfi", "rfi"],
    "race_condition": ["race-condition"],
    "account_takeovers_methodologies": ["account-takeover"],
    "api_testing": ["api"],
    "oauth": ["oauth"],
    "waf_bypasses": ["waf-bypass"],
    "cors": ["cors"],
    "open_redirection": ["open-redirect"],
    "graphql": ["graphql"],
    "broken_auth_and_session_management": ["auth-bypass", "session-management"],
    "brokenlinkhijacking": ["subdomain-takeover"],
    "application_level_dos": ["dos"],
    "cms": ["cms"],
    "cves": ["cve"],
    "websockets": ["websockets"],
    "parameter_pollution": ["hpp"],
    "host-header": ["host-header-injection"],
    "http_desync": ["http-desync", "request-smuggling"],
    "authentication_bypass": ["auth-bypass"],
    "tabnabbing": ["phishing"],
    "weak_password_policy": ["weak-credentials"]
}

VULN_TAG_MAP_HOLYTIPS_FILES = {
    "api security": ["api"],
    "authentication": ["auth-bypass"],
    "file upload": ["file-upload"],
    "oauth": ["oauth"],
    "middlewares": ["middleware"]
}

def extract_lang_tags(text: str) -> List[str]:
    """Extracts language/technology tags from title or content text."""
    if not text:
        return []
    text_lower = text.lower()
    tech_keywords = {
        "php": "php",
        "java": "java",
        "spring": "spring",
        "python": "python",
        "django": "django",
        "flask": "flask",
        "node": "node",
        "express": "express",
        "javascript": "js",
        "go": "go",
        "golang": "go",
        "ruby": "ruby",
        "rails": "rails",
        "wordpress": "wordpress",
        "laravel": "laravel",
        "asp": "asp",
        "csharp": "csharp",
        "aws": "aws",
        "docker": "docker",
        "graphql": "graphql",
        "nginx": "nginx",
        "apache": "apache"
    }
    found = []
    for kw, tag in tech_keywords.items():
        if re.search(r'\b' + re.escape(kw) + r'\b', text_lower) and tag not in found:
            found.append(tag)
    return found

def slugify(text: str) -> str:
    """Converts a string to a clean slug tag."""
    text = text.lower()
    text = re.sub(r'[^a-z0-9]+', '-', text)
    return text.strip('-')

class BugBountyWriteupsConnector(BaseConnector):
    source_name: str = "bugbounty_writeups"

    def _clone_or_update(self, repo_url: str, folder_name: str) -> Path:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        repo_dir = CACHE_DIR / folder_name

        if repo_dir.exists() and (repo_dir / ".git").exists():
            print(f"[*] Updating existing repo cache: {folder_name}...")
            try:
                subprocess.run(
                    ["git", "pull", "--rebase"],
                    cwd=repo_dir,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            except Exception as e:
                print(f"    [!] Warning: git pull failed for {folder_name}, using local cache. Error: {e}")
        else:
            print(f"[*] Cloning repository: {repo_url} -> {repo_dir}...")
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", repo_url, str(repo_dir)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            except Exception as e:
                print(f"    [!] Error cloning {repo_url}: {e}")
                raise e

        return repo_dir

    def _extract_title_and_summary(self, filepath: Path) -> tuple[str, str]:
        title = filepath.stem.replace("_", " ").replace("-", " ").title()
        summary = ""

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()
                lines = content.splitlines()

                for line in lines:
                    line_clean = line.strip()
                    if line_clean.startswith("# "):
                        title = line_clean[2:].strip()
                        break
                    elif line_clean.startswith("## "):
                        title = line_clean[3:].strip()
                        break

                clean_text = re.sub(r'#+\s*', '', content)
                clean_text = re.sub(r'```[\s\S]*?```', '', clean_text)
                clean_text = re.sub(r'\s+', ' ', clean_text).strip()
                summary = clean_text[:400]

        except Exception as e:
            print(f"    [!] Error reading {filepath}: {e}")

        return title, summary

    def fetch(self) -> List[Dict[str, Any]]:
        records = []

        # 1. Process HowToHunt Repo
        try:
            hth_dir = self._clone_or_update(HOWTOHUNT_REPO, "HowToHunt")
            for root, dirs, files in os.walk(hth_dir):
                if ".git" in root:
                    continue
                for file in files:
                    if not file.endswith(".md"):
                        continue
                    if file.lower() in ["readme.md", "code_of_conduct.md", "contributing.md"]:
                        continue

                    full_path = Path(root) / file
                    rel_path = full_path.relative_to(hth_dir)
                    parts = rel_path.parts

                    if len(parts) < 2:
                        continue

                    top_folder = parts[0]
                    top_folder_key = top_folder.lower()

                    vuln_tags = VULN_TAG_MAP_HOWTOHUNT.get(top_folder_key)
                    if not vuln_tags:
                        vuln_tags = [slugify(top_folder)]

                    title, summary = self._extract_title_and_summary(full_path)
                    lang_tags = extract_lang_tags(title + " " + summary)

                    source_id = f"HowToHunt/{rel_path}"
                    url = f"https://github.com/KathanP19/HowToHunt/blob/master/{rel_path}"

                    record = {
                        "source": self.source_name,
                        "source_id": source_id,
                        "title": f"HowToHunt - {title}",
                        "url": url,
                        "summary": summary,
                        "published_date": None,
                        "entry_type": "writeup",
                        "lang_tags": lang_tags,
                        "vuln_tags": vuln_tags,
                        "cvss_score": None,
                        "epss_score": None,
                        "in_kev": False,
                        "raw_data": {
                            "repo": "KathanP19/HowToHunt",
                            "folder": top_folder,
                            "relative_path": str(rel_path)
                        }
                    }
                    records.append(record)

        except Exception as e:
            print(f"[-] Error processing HowToHunt repo: {e}")

        # 2. Process HolyTips Repo
        try:
            htips_dir = self._clone_or_update(HOLYTIPS_REPO, "HolyTips")
            for root, dirs, files in os.walk(htips_dir):
                if ".git" in root:
                    continue
                for file in files:
                    if not file.endswith(".md"):
                        continue
                    if file.lower() == "readme.md":
                        continue

                    full_path = Path(root) / file
                    rel_path = full_path.relative_to(htips_dir)
                    stem_lower = full_path.stem.lower()

                    vuln_tags = VULN_TAG_MAP_HOLYTIPS_FILES.get(stem_lower)
                    if not vuln_tags:
                        vuln_tags = [slugify(full_path.stem)]

                    title, summary = self._extract_title_and_summary(full_path)
                    lang_tags = extract_lang_tags(title + " " + summary)

                    source_id = f"HolyTips/{rel_path}"
                    url = f"https://github.com/HolyBugx/HolyTips/blob/main/{rel_path}"

                    record = {
                        "source": self.source_name,
                        "source_id": source_id,
                        "title": f"HolyTips - {title}",
                        "url": url,
                        "summary": summary,
                        "published_date": None,
                        "entry_type": "writeup",
                        "lang_tags": lang_tags,
                        "vuln_tags": vuln_tags,
                        "cvss_score": None,
                        "epss_score": None,
                        "in_kev": False,
                        "raw_data": {
                            "repo": "HolyBugx/HolyTips",
                            "relative_path": str(rel_path)
                        }
                    }
                    records.append(record)

        except Exception as e:
            print(f"[-] Error processing HolyTips repo: {e}")

        return records
