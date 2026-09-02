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

# Delimitan la única parte del README que este script reescribe.
STATS_START = "<!-- KEV-STATS:START -->"
STATS_END = "<!-- KEV-STATS:END -->"


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
    cve = vuln["cveID"]
    # El catálogo marca las CVE con uso conocido en campañas de ransomware.
    # Para un analista es lo primero que quiere ver, así que va en la cabecera.
    ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown").strip()
    flag = " · 🔴 **Ransomware conocido**" if ransomware.lower() == "known" else ""
    return (
        f"- **[{cve}](https://nvd.nist.gov/vuln/detail/{cve})** — "
        f"{vuln['vendorProject']} {vuln['product']}{flag}\n"
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


def update_readme(date_str, new_count, total_tracked, first_run, ransomware_count):
    """Refresca SOLO el bloque de estadísticas del README.

    El README lo escribe una persona; de aquí sale únicamente lo que hay entre
    los dos marcadores. Antes esta función reconstruía el archivo entero, así
    que cualquier cosa que se escribiera a mano (instalación, ejemplos,
    licencia...) desaparecía en la siguiente ejecución del cron.

    Si los marcadores no están, no se toca nada: es preferible un README con
    cifras viejas que un README machacado.
    """
    if not README_FILE.exists():
        print("README.md no existe; no se actualiza.", file=sys.stderr)
        return

    content = README_FILE.read_text(encoding="utf-8")
    if STATS_START not in content or STATS_END not in content:
        print(
            f"Marcadores {STATS_START} / {STATS_END} no encontrados en README.md; "
            "se deja intacto.",
            file=sys.stderr,
        )
        return

    nuevas = f"{new_count}" + (" (línea base inicial)" if first_run else "")
    bloque = "\n".join(
        [
            STATS_START,
            "<!-- Generado por scripts/digest.py. No editar a mano. -->",
            "",
            "| | |",
            "|---|---|",
            f"| **Última ejecución** | {date_str} |",
            f"| **CVEs en seguimiento** | {total_tracked} |",
            f"| **Nuevas en esta ejecución** | {nuevas} |",
            f"| **Con uso conocido en ransomware** | {ransomware_count} |",
            f"| **Último digest** | [`digest/{date_str}.md`](digest/{date_str}.md) |",
            "",
            STATS_END,
        ]
    )

    inicio = content.index(STATS_START)
    fin = content.index(STATS_END) + len(STATS_END)
    README_FILE.write_text(content[:inicio] + bloque + content[fin:], encoding="utf-8")


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

    ransomware_count = sum(
        1
        for v in vulns
        if v.get("knownRansomwareCampaignUse", "").strip().lower() == "known"
    )

    save_seen(current_ids)
    path, _ = write_digest(date_str, new_vulns, len(current_ids), first_run)
    update_readme(
        date_str, len(new_vulns), len(current_ids), first_run, ransomware_count
    )

    print(f"Wrote {path} — {len(new_vulns)} new, {len(current_ids)} tracked total")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
