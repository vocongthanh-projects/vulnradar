# VulnRadar

A local-first CLI that collects public vulnerability intelligence, deduplicates records across sources, and prioritizes what deserves attention.

VulnRadar currently supports the NVD and CISA Known Exploited Vulnerabilities feeds. Optional reference connectors index selected public security repositories without committing their content to this repository.

## What makes it useful

- Merges NVD and CISA records for the same CVE instead of creating duplicates.
- Preserves the CISA KEV signal when later sources update a record.
- Assigns an explainable priority score using KEV, CVSS, and EPSS signals.
- Searches a local SQLite database without requiring network access after ingest.
- Produces daily or weekly digests ordered by actionable risk.
- Optionally applies canonical technology and vulnerability tags with an LLM.

The priority score is a triage aid, not a substitute for asset context or a vulnerability-management decision.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
vulnradar init
vulnradar ingest nvd --days 7
vulnradar ingest cisa_kev
vulnradar search --kev
vulnradar digest --since 7d
```

An NVD API key is optional but improves rate limits. The CISA feed does not require a key.

## Sources

| Source | Purpose |
| --- | --- |
| NVD | CVE metadata and CVSS |
| CISA KEV | Evidence of known exploitation |
| PayloadsAllTheThings | Optional local reference index |
| HowToHunt / HolyTips | Optional public write-up index |

Third-party content is cloned into `vulnradar/cache/` at runtime and remains governed by its original license. It is never vendored into this repository.

## Priority model

The default deterministic score is deliberately simple and auditable:

- CISA KEV: 60 points
- CVSS: up to 30 points
- EPSS: up to 10 points

Levels are low, medium, high, and critical. Asset exposure and business context should be applied outside this generic score.

## Configuration

```env
VULNRADAR_DATABASE_URL=sqlite:///vulnradar/data/vulnradar.db
NVD_API_KEY=
ANTHROPIC_API_KEY=
VULNRADAR_TAG_MODEL=claude-haiku-4-5-20251001
```

Only `ANTHROPIC_API_KEY` and `VULNRADAR_TAG_MODEL` are needed for the optional `tag` command.

## Development

```bash
pytest
ruff check .
```

Fixtures use synthetic CVE identifiers and an in-memory database. Runtime databases, cloned caches, logs, and secrets are ignored by Git.

## License

VulnRadar source code is available under the MIT license. Data obtained from upstream sources remains subject to each source's terms and license.
