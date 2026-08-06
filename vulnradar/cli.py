import os
from typing import Optional

import typer
from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.table import Table
from sqlalchemy import func

from vulnradar.db.crud import upsert_entries
from vulnradar.db.models import Entry
from vulnradar.db.search import search_entries
from vulnradar.db.session import get_db, init_db

app = typer.Typer(
    name="vulnradar",
    help="VulnRadar — Personal Vulnerability Intelligence & Knowledge Base for Pentesters",
    add_completion=False
)
console = Console()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def clean_display_title(title: str, source: str) -> str:
    """Strip repetitive source prefixes for clean table display."""
    if source == "payloadsallthethings" and title.startswith("PayloadsAllTheThings - "):
        return title.replace("PayloadsAllTheThings - ", "", 1)
    if source == "bugbounty_writeups":
        if title.startswith("HowToHunt - "):
            return title.replace("HowToHunt - ", "HowToHunt: ", 1)
        if title.startswith("HolyTips - "):
            return title.replace("HolyTips - ", "HolyTips: ", 1)
    return title


def shorten_url(url: Optional[str]) -> str:
    """Shorten GitHub/NVD URLs intelligently for neat table display."""
    if not url:
        return "N/A"
    if "github.com/swisskyrepo/PayloadsAllTheThings/blob/master/" in url:
        return url.replace("https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/", "PATT/")
    if "github.com/KathanP19/HowToHunt/blob/master/" in url:
        return url.replace("https://github.com/KathanP19/HowToHunt/blob/master/", "HTH/")
    if "github.com/HolyBugx/HolyTips/blob/main/" in url:
        return url.replace("https://github.com/HolyBugx/HolyTips/blob/main/", "HTIPS/")
    if "nvd.nist.gov/vuln/detail/" in url:
        return url.replace("https://nvd.nist.gov/vuln/detail/", "NVD/")
    return url


# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────

@app.command()
def init():
    """Create the database and initialize the entries table."""
    try:
        init_db()
        console.print("[bold green]✓[/bold green] Database initialized successfully.")
    except Exception as e:
        console.print(f"[bold red]✗ Database initialization failed:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def status():
    """Count and display entries by source and entry type."""
    db = get_db()
    try:
        total_entries = db.query(func.count(Entry.id)).scalar() or 0

        source_counts = (
            db.query(Entry.source, func.count(Entry.id))
            .group_by(Entry.source)
            .all()
        )
        type_counts = (
            db.query(Entry.entry_type, func.count(Entry.id))
            .group_by(Entry.entry_type)
            .all()
        )

        console.print(f"\n[bold magenta]📊 VulnRadar Status Summary[/bold magenta] (Total: [bold yellow]{total_entries}[/bold yellow] entries)\n")

        source_table = Table(title="Entries by Source", show_header=True, header_style="bold blue", box=box.ROUNDED)
        source_table.add_column("Source", style="cyan")
        source_table.add_column("Count", justify="right", style="green")
        for source, count in (source_counts or [("(No sources yet)", 0)]):
            source_table.add_row(source, str(count))
        console.print(source_table)
        console.print()

        type_table = Table(title="Entries by Entry Type", show_header=True, header_style="bold blue", box=box.ROUNDED)
        type_table.add_column("Entry Type", style="yellow")
        type_table.add_column("Count", justify="right", style="green")
        for entry_type, count in (type_counts or [("(No entry types yet)", 0)]):
            type_table.add_row(entry_type, str(count))
        console.print(type_table)

    except Exception as e:
        console.print(f"[bold red]✗ Database query failed:[/bold red] {e}")
        console.print("[dim]Tip: Run 'python3 cli.py init' if the database has not been created.[/dim]")
        raise typer.Exit(code=1)
    finally:
        db.close()


@app.command()
def ingest(
    source: str = typer.Argument("all", help="Data source: payloadsallthethings | nvd | cisa_kev | bugbounty_writeups | all"),
    days: int = typer.Option(7, "--days", "-d", help="Number of recent days to fetch from NVD (default: 7)")
):
    """Collect data from the selected source and store it in the database."""
    db = get_db()
    source_lower = source.lower()

    tasks = []
    if source_lower == "payloadsallthethings":
        from vulnradar.connectors.payloadsallthethings import PayloadsAllTheThingsConnector
        conn = PayloadsAllTheThingsConnector()
        tasks.append(("payloadsallthethings", lambda: conn.fetch(), conn))
    elif source_lower == "nvd":
        from vulnradar.connectors.nvd import NVDConnector
        conn = NVDConnector()
        tasks.append(("nvd", lambda: conn.fetch(days=days), conn))
    elif source_lower == "cisa_kev":
        from vulnradar.connectors.cisa_kev import CISAKEVConnector
        conn = CISAKEVConnector()
        tasks.append(("cisa_kev", lambda: conn.fetch(), conn))
    elif source_lower in ["bugbounty_writeups", "writeups"]:
        from vulnradar.connectors.bugbounty_writeups import BugBountyWriteupsConnector
        conn = BugBountyWriteupsConnector()
        tasks.append(("bugbounty_writeups", lambda: conn.fetch(), conn))
    elif source_lower == "all":
        from vulnradar.connectors.bugbounty_writeups import BugBountyWriteupsConnector
        from vulnradar.connectors.cisa_kev import CISAKEVConnector
        from vulnradar.connectors.nvd import NVDConnector
        from vulnradar.connectors.payloadsallthethings import PayloadsAllTheThingsConnector
        c1 = PayloadsAllTheThingsConnector()
        c2 = NVDConnector()
        c3 = CISAKEVConnector()
        c4 = BugBountyWriteupsConnector()
        tasks.append(("payloadsallthethings", lambda: c1.fetch(), c1))
        tasks.append(("nvd", lambda: c2.fetch(days=days), c2))
        tasks.append(("cisa_kev", lambda: c3.fetch(), c3))
        tasks.append(("bugbounty_writeups", lambda: c4.fetch(), c4))
    else:
        console.print(f"[bold red]✗ Invalid data source: '{source}'.[/bold red]")
        raise typer.Exit(code=1)

    for source_name, fetch_fn, conn_obj in tasks:
        console.print(f"[bold blue][*][/bold blue] Ingesting from [bold cyan]{source_name}[/bold cyan]...")
        try:
            records = fetch_fn()
            console.print(f"    - Collected [bold yellow]{len(records)}[/bold yellow] records. Saving to the database...")
            inserted, updated = upsert_entries(db, records)

            is_complete = getattr(conn_obj, "is_complete", True)
            total_expected = getattr(conn_obj, "total_expected", len(records))
            failed_at_page = getattr(conn_obj, "failed_at_page", 0)

            if is_complete:
                if total_expected > 0 and source_name == "nvd":
                    console.print(f"[bold green]✓ Completed {source_name}:[/bold green] [{len(records)}/{total_expected}] CVEs (+{inserted} new, {updated} updated).\n")
                else:
                    console.print(f"[bold green]✓ Completed {source_name}:[/bold green] (+{inserted} new, {updated} updated).\n")
            else:
                console.print(f"[bold yellow]⚠ Partially completed {source_name}:[/bold yellow] [{len(records)}/{total_expected}] CVEs (stopped at page {failed_at_page}). Rerun to continue.\n")

        except Exception as e:
            console.print(f"[bold red]✗ Failed to ingest {source_name}:[/bold red] {e}\n")


@app.command()
def tag(
    missing_only: bool = typer.Option(True, "--missing-only", help="Tag only entries without tags or tagged 'general-cve'"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview results without writing to the database"),
    limit: int = typer.Option(100, "--limit", "-n", help="Maximum entries to tag (0 = unlimited)")
):
    """Automatically classify entry tags with Claude Haiku 4.5."""
    load_dotenv()
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()

    if not api_key:
        console.print("[bold red]✗ Error:[/bold red] ANTHROPIC_API_KEY is not configured in .env.")
        raise typer.Exit(code=1)

    import anthropic

    from vulnradar.tagging import (
        MODEL_NAME,
        get_target_entries,
        merge_entry_tags,
        process_tagging_batch,
    )

    db = get_db()
    try:
        targets = get_target_entries(db, missing_only=missing_only, limit=limit)

        mode_str = "[yellow]DRY RUN (no database writes)[/yellow]" if dry_run else "[green]REAL RUN (writes to database)[/green]"
        console.print(f"\n[bold magenta]🤖 VulnRadar LLM Auto-Tagging[/bold magenta] ({mode_str})")
        console.print(f"[*] Model: [cyan]{MODEL_NAME}[/cyan] | Targets: [bold yellow]{len(targets)}[/bold yellow] (limit {limit})\n")

        if not targets:
            console.print("[dim]No entries require tagging.[/dim]\n")
            return

        client = anthropic.Anthropic(api_key=api_key)
        batch_size = 15
        total_batches = (len(targets) + batch_size - 1) // batch_size

        total_input_tokens = 0
        total_output_tokens = 0
        tagged_success_count = 0
        failed_count = 0

        table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED, expand=True)
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Source / ID", style="cyan", width=22, no_wrap=True)
        table.add_column("Title", style="bold white", ratio=3, min_width=20, no_wrap=False)
        table.add_column("Old Tags", style="dim yellow", width=16, no_wrap=False)
        table.add_column("New Tags", style="bold magenta", ratio=2, min_width=18, no_wrap=False)

        for batch_idx in range(total_batches):
            batch = targets[batch_idx * batch_size : (batch_idx + 1) * batch_size]
            console.print(f"[*] Batch {batch_idx + 1}/{total_batches} ({len(batch)} entries)...")

            try:
                predicted_items, in_tok, out_tok = process_tagging_batch(client, batch)
                total_input_tokens += in_tok
                total_output_tokens += out_tok

                pred_map = {item.get("index"): item for item in predicted_items if isinstance(item, dict)}

                for idx, entry in enumerate(batch):
                    pred = pred_map.get(idx, {})
                    new_lang = pred.get("lang_tags", [])
                    new_vuln = pred.get("vuln_tags", [])

                    old_tags_disp = f"L:({','.join(entry.lang_tags or [])}) V:({','.join(entry.vuln_tags or [])})"

                    final_lang, final_vuln = merge_entry_tags(
                        entry_lang_tags=entry.lang_tags,
                        entry_vuln_tags=entry.vuln_tags,
                        predicted_lang=new_lang,
                        predicted_vuln=new_vuln
                    )

                    new_tags_disp = f"[yellow]L:({','.join(final_lang)})[/yellow] [magenta]V:({','.join(final_vuln)})[/magenta]"

                    if not dry_run:
                        entry.lang_tags = final_lang
                        entry.vuln_tags = final_vuln

                    tagged_success_count += 1
                    table.add_row(
                        str(batch_idx * batch_size + idx + 1),
                        f"{entry.source}:{entry.source_id[:14]}",
                        entry.title[:50] + ("..." if len(entry.title) > 50 else ""),
                        old_tags_disp,
                        new_tags_disp
                    )

            except Exception as e:
                console.print(f"[bold red]    [!] Batch {batch_idx + 1} failed:[/bold red] {e}")
                failed_count += len(batch)

        if not dry_run:
            db.commit()
            console.print("\n[bold green]✓ Database tags updated.[/bold green]\n")

        console.print(table)
        console.print()

        estimated_cost = (total_input_tokens * 0.25 / 1_000_000) + (total_output_tokens * 1.25 / 1_000_000)
        console.print("[bold cyan]📊 Tagging Summary:[/bold cyan]")
        console.print(f"  • Processed:        [bold yellow]{len(targets)}[/bold yellow]")
        console.print(f"  • Tagged OK:        [bold green]{tagged_success_count}[/bold green]")
        console.print(f"  • Failed:           [bold red]{failed_count}[/bold red]")
        console.print(f"  • Tokens:           Input [cyan]{total_input_tokens}[/cyan] / Output [cyan]{total_output_tokens}[/cyan]")
        console.print(f"  • Estimated Cost:   [bold yellow]${estimated_cost:.5f} USD[/bold yellow]\n")

    except Exception as e:
        console.print(f"[bold red]✗ Auto-tagging failed:[/bold red] {e}")
        raise typer.Exit(code=1)
    finally:
        db.close()


@app.command()
def search(
    keyword: Optional[str] = typer.Argument(None, help="Search titles and summaries for a keyword"),
    lang: Optional[str] = typer.Option(None, "--lang", "-l", help="Filter by language or technology, e.g. php, java, laravel"),
    type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by vulnerability type, e.g. sqli, ssrf, xss, rce"),
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Filter by source, e.g. nvd, bugbounty_writeups, payloadsallthethings"),
    kev: bool = typer.Option(False, "--kev", "-k", help="Show only actively exploited CISA KEV entries"),
    limit: int = typer.Option(20, "--limit", "-n", help="Maximum result count (default: 20)"),
    show_url: bool = typer.Option(False, "--show-url", "-u", help="Print the complete URL list below the table")
):
    """Search vulnerabilities, payloads, and write-ups in the knowledge base."""
    db = get_db()
    try:
        results = search_entries(
            db=db,
            keyword=keyword,
            lang=lang,
            vuln_type=type,
            source=source,
            in_kev=kev,
            limit=limit
        )

        filter_desc = []
        if keyword:
            filter_desc.append(f"keyword='[bold yellow]{keyword}[/bold yellow]'")
        if lang:
            filter_desc.append(f"lang='[bold cyan]{lang}[/bold cyan]'")
        if type:
            filter_desc.append(f"type='[bold magenta]{type}[/bold magenta]'")
        if source:
            filter_desc.append(f"source='[bold green]{source}[/bold green]'")
        if kev:
            filter_desc.append("[bold red]KEV Only[/bold red]")

        title_str = "🔍 VulnRadar Search Results"
        if filter_desc:
            title_str += " (" + ", ".join(filter_desc) + ")"
        console.print(f"\n{title_str} — [bold yellow]{len(results)}[/bold yellow] entries (limit {limit})\n")

        if not results:
            console.print("[dim]No matching results found.[/dim]\n")
            return

        table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED, expand=True)
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Title", style="bold white", ratio=4, min_width=25, no_wrap=False)
        table.add_column("Source", style="cyan", width=18, no_wrap=True)
        table.add_column("Type", style="green", width=12, no_wrap=True)
        table.add_column("Tags", style="magenta", width=14, no_wrap=False)
        table.add_column("Date / KEV", style="bold yellow", width=10, no_wrap=True)
        table.add_column("URL (Shortened)", style="blue underline", ratio=3, min_width=18, no_wrap=True, overflow="ellipsis")

        for idx, entry in enumerate(results, start=1):
            disp_title = clean_display_title(entry.title, entry.source)
            tag_parts = [f"[yellow]{t}[/yellow]" for t in (entry.lang_tags or [])]
            tag_parts += [f"[magenta]{t}[/magenta]" for t in (entry.vuln_tags or [])]
            tags_str = ", ".join(tag_parts) if tag_parts else "-"

            if entry.in_kev:
                date_kev_str = "[bold red]KEV[/bold red]"
            elif entry.published_date:
                date_kev_str = entry.published_date.strftime("%Y-%m-%d")
            else:
                date_kev_str = "[dim]N/A[/dim]"

            table.add_row(str(idx), disp_title, entry.source,
                          entry.entry_type.replace("_", " "), tags_str,
                          date_kev_str, shorten_url(entry.url))

        console.print(table)
        console.print()

        if show_url:
            console.print("[bold blue]🔗 Full URLs:[/bold blue]")
            for idx, entry in enumerate(results, start=1):
                if entry.url:
                    console.print(f"  [{idx}] [blue underline]{entry.url}[/blue underline]")
            console.print()

    except Exception as e:
        console.print(f"[bold red]✗ Search failed:[/bold red] {e}")
        raise typer.Exit(code=1)
    finally:
        db.close()


@app.command()
def digest(
    since: str = typer.Option("1d", "--since", "-t", help="Digest period, e.g. 1d, 7d, 24h, 48h"),
    lang: Optional[str] = typer.Option(None, "--lang", "-l", help="Comma-separated language or technology filter, e.g. php,java"),
    type: Optional[str] = typer.Option(None, "--type", help="Vulnerability-type filter, e.g. sqli, rce, ssrf"),
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Source filter, e.g. nvd, cisa_kev, bugbounty_writeups"),
    limit: int = typer.Option(50, "--limit", "-n", help="Maximum displayed entries (0 = unlimited)"),
    show_url: bool = typer.Option(False, "--show-url", "-u", help="Print the complete URL list below the table")
):
    """Create a periodic daily or weekly vulnerability digest."""
    from vulnradar.digest import get_digest_entries

    db = get_db()
    try:
        data = get_digest_entries(db=db, since_str=since, lang_str=lang,
                                   vuln_type=type, source=source, limit=limit)

        entries = data["entries"]
        total_count = data["total_count"]
        displayed_count = data["displayed_count"]
        kev_count = data["kev_count"]
        non_kev_count = data["non_kev_count"]
        period_desc = data["period_desc"]

        filter_desc = [f"period='[bold cyan]{period_desc}[/bold cyan]'"]
        if lang:
            filter_desc.append(f"lang='[bold cyan]{lang}[/bold cyan]'")
        if type:
            filter_desc.append(f"type='[bold magenta]{type}[/bold magenta]'")
        if source:
            filter_desc.append(f"source='[bold green]{source}[/bold green]'")

        console.print(f"\n📰 VulnRadar Security Digest ({', '.join(filter_desc)}) — [bold yellow]{len(entries)}[/bold yellow] entries (Total: [bold yellow]{total_count}[/bold yellow])\n")

        if not entries:
            console.print("[dim]No new entries were found in the selected period.[/dim]\n")
            return

        table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED, expand=True)
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Title", style="bold white", ratio=4, min_width=25, no_wrap=False)
        table.add_column("Source", style="cyan", width=18, no_wrap=True)
        table.add_column("Type", style="green", width=12, no_wrap=True)
        table.add_column("Tags", style="magenta", width=14, no_wrap=False)
        table.add_column("Date / KEV", style="bold yellow", width=10, no_wrap=True)
        table.add_column("URL (Shortened)", style="blue underline", ratio=3, min_width=18, no_wrap=True, overflow="ellipsis")

        for idx, entry in enumerate(entries, start=1):
            disp_title = clean_display_title(entry.title, entry.source)
            if entry.in_kev:
                disp_title = f"[bold red]🚨 [KEV][/bold red] {disp_title}"

            tag_parts = [f"[yellow]{t}[/yellow]" for t in (entry.lang_tags or [])]
            tag_parts += [f"[magenta]{t}[/magenta]" for t in (entry.vuln_tags or [])]
            tags_str = ", ".join(tag_parts) if tag_parts else "-"

            if entry.in_kev:
                date_kev_str = "[bold red]🔥 KEV[/bold red]"
            elif entry.published_date:
                date_kev_str = entry.published_date.strftime("%Y-%m-%d")
            else:
                date_kev_str = "[dim]N/A[/dim]"

            table.add_row(str(idx), disp_title, entry.source,
                          entry.entry_type.replace("_", " "), tags_str,
                          date_kev_str, shorten_url(entry.url))

        console.print(table)
        console.print()

        if show_url:
            console.print("[bold blue]🔗 Full URLs:[/bold blue]")
            for idx, entry in enumerate(entries, start=1):
                if entry.url:
                    console.print(f"  [{idx}] [blue underline]{entry.url}[/blue underline]")
            console.print()

        kev_str = f"[bold red]{kev_count}[/bold red]" if kev_count > 0 else "0"
        non_kev_str = f"[bold green]{non_kev_count}[/bold green]"

        if displayed_count < total_count:
            console.print(f"[bold cyan]📊 Digest Summary:[/bold cyan] {total_count} entries in {period_desc} ({kev_str} KEV + {non_kev_str} non-KEV). Showing {displayed_count}/{total_count}. Use `--limit 0` to show all.\n")
        else:
            console.print(f"[bold cyan]📊 Digest Summary:[/bold cyan] {total_count} entries trong {period_desc} ({kev_str} KEV + {non_kev_str} Non-KEV).\n")

    except Exception as e:
        console.print(f"[bold red]✗ Digest generation failed:[/bold red] {e}")
        raise typer.Exit(code=1)
    finally:
        db.close()


if __name__ == "__main__":
    app()
