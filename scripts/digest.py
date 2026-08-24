#!/usr/bin/env python3
"""Daily CISA KEV (Known Exploited Vulnerabilities) watcher.

Fetches the CISA KEV catalog, diffs it against the last known state, and
writes a dated digest entry with anything new. Run once a day by
.github/workflows/digest.yml.
"""
import datetime
import json
import pathlib
import sys
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE_FILE = ROOT / "data" / "seen_cves.json"
DIGEST_DIR = ROOT / "digest"
README_FILE = ROOT / "README.md"


def fetch_kev():
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "kev-digest/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def load_seen():
    if STATE_FILE.exists():
        return set(json.loads(STATE_FILE.read_text(encoding="utf-8")))
    return None  # None means "first run, no baseline yet"


def save_seen(cve_ids):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(
        json.dumps(sorted(cve_ids), indent=2), encoding="utf-8"
    )


def format_entry(vuln):
    return (
        f"- **{vuln['cveID']}** — {vuln['vendorProject']} {vuln['product']}\n"
        f"  {vuln['vulnerabilityName']}\n"
        f"  Añadida al catálogo: {vuln['dateAdded']} · "
        f"Plazo de mitigación: {vuln.get('dueDate', 'n/d')}\n"
        f"  {vuln.get('shortDescription', '').strip()}\n"
    )


def write_digest(date_str, new_vulns, total_tracked, first_run):
    DIGEST_DIR.mkdir(parents=True, exist_ok=True)
    path = DIGEST_DIR / f"{date_str}.md"

    if first_run:
        body = (
            f"# KEV digest — {date_str}\n\n"
            f"Primera ejecución: se establece la línea base con "
            f"**{total_tracked}** CVEs ya presentes en el catálogo CISA KEV. "
            "A partir de mañana este archivo solo listará entradas nuevas.\n"
        )
    elif new_vulns:
        body = (
            f"# KEV digest — {date_str}\n\n"
            f"**{len(new_vulns)}** entrada(s) nueva(s) en el catálogo CISA KEV "
            f"(total trackeado: {total_tracked}):\n\n"
            + "\n".join(format_entry(v) for v in new_vulns)
        )
    else:
        body = (
            f"# KEV digest — {date_str}\n\n"
            f"Sin entradas nuevas hoy. Total trackeado: {total_tracked}.\n"
        )

    path.write_text(body, encoding="utf-8")
    return path, body


def update_readme(date_str, new_count, total_tracked, first_run):
    lines = [
        "# KEV Digest",
        "",
        "Vigilancia diaria y automatizada del catálogo "
        "[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) "
        "(Known Exploited Vulnerabilities) vía GitHub Actions "
        "(`.github/workflows/digest.yml`, cron diario).",
        "",
        "Cada día el workflow descarga el catálogo, lo compara contra "
        "`data/seen_cves.json` (última foto conocida) y escribe un archivo en "
        "`digest/` con lo que ha cambiado. Sin intervención manual.",
        "",
        f"- **Última ejecución:** {date_str}",
        f"- **CVEs trackeados:** {total_tracked}",
        f"- **Nuevas hoy:** {new_count}"
        + (" (línea base inicial)" if first_run else ""),
        f"- **Último digest:** [`digest/{date_str}.md`](digest/{date_str}.md)",
        "",
        "## Por qué",
        "",
        "Registro personal de inteligencia de amenazas: entrar cada mañana a "
        "revisar qué vulnerabilidades explotadas activamente se han añadido "
        "al catálogo de CISA, sin tener que comprobarlo a mano.",
        "",
    ]
    README_FILE.write_text("\n".join(lines), encoding="utf-8")


def main():
    date_str = datetime.date.today().isoformat()
    try:
        catalog = fetch_kev()
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR fetching KEV catalog: {exc}", file=sys.stderr)
        return 1

    vulns = catalog.get("vulnerabilities", [])
    current_ids = {v["cveID"] for v in vulns}
    seen_ids = load_seen()
    first_run = seen_ids is None

    if first_run:
        new_vulns = []
    else:
        new_ids = current_ids - seen_ids
        new_vulns = [v for v in vulns if v["cveID"] in new_ids]
        new_vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)

    save_seen(current_ids)
    path, _ = write_digest(date_str, new_vulns, len(current_ids), first_run)
    update_readme(date_str, len(new_vulns), len(current_ids), first_run)

    print(f"Wrote {path} — {len(new_vulns)} new, {len(current_ids)} tracked total")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
