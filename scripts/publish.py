#!/usr/bin/env python3
"""Artefactos publicables: historial, feed Atom y latest.json.

`data/latest.json` es la salida pública del proyecto: la consume el Blue Team
Hub (eduolihez.github.io) para su página KEV Watch. Los nombres de campo
`lastUpdated`, `totalTracked`, `newToday` y `recentAdditions` son contrato con
esa página, así que no se renombran sin tocar también el Hub.

Sin dependencias: solo biblioteca estándar.
"""
from __future__ import annotations

import datetime
import json
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
HISTORY_FILE = ROOT / "data" / "history.jsonl"
LATEST_FILE = ROOT / "data" / "latest.json"
FEED_FILE = ROOT / "digest" / "feed.xml"

REPO_URL = "https://github.com/eduolihez/kev-digest"
FEED_URL = "https://raw.githubusercontent.com/eduolihez/kev-digest/main/digest/feed.xml"
NVD = "https://nvd.nist.gov/vuln/detail/"

# Misma ventana que usaba el script del Hub, para que su página no cambie.
VENTANA_DIAS = 45
MAX_RECIENTES = 150
FEED_MAX = 50

LATEST_SCHEMA = 1


def append_history(eventos: list[dict]) -> None:
    """Añade eventos al log. Una línea por evento, nunca se reescribe.

    Sirve para responder "¿cuándo entró esta CVE?" sin arqueología de git, y
    es de donde sale el feed.
    """
    if not eventos:
        return
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(HISTORY_FILE, "a", encoding="utf-8", newline="\n") as fh:
        for evento in eventos:
            fh.write(json.dumps(evento, sort_keys=True, ensure_ascii=False) + "\n")


def read_history(limite: int | None = None) -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    lineas = HISTORY_FILE.read_text(encoding="utf-8").splitlines()
    if limite:
        lineas = lineas[-limite:]
    salida = []
    for linea in lineas:
        linea = linea.strip()
        if not linea:
            continue
        try:
            salida.append(json.loads(linea))
        except json.JSONDecodeError:
            continue
    return salida


def count_new_today(fecha: str) -> int:
    """Cuántas CVE nuevas se han encontrado hoy, sumando todas las pasadas.

    No es "las de esta pasada": con ocho al día, ese número bajaría a cero por
    la tarde y `latest.json` cambiaría sin que hubiera novedad, además de
    contradecir el nombre del campo que lee el Hub.
    """
    return sum(
        1 for e in read_history()
        if e.get("date") == fecha and e.get("event") == "new"
    )


def dias_desde(fecha: str, hoy: datetime.date) -> float:
    try:
        return (hoy - datetime.date.fromisoformat(fecha)).days
    except (ValueError, TypeError):
        return float("inf")


def dias_hasta(fecha: str, hoy: datetime.date) -> float:
    try:
        return (datetime.date.fromisoformat(fecha) - hoy).days
    except (ValueError, TypeError):
        return float("inf")


def entrada_publica(vuln: dict, extra: dict | None = None) -> dict:
    """Una CVE en el formato que consume el Hub, más el enriquecimiento."""
    salida = {
        "cveID": vuln["cveID"],
        "vendorProject": vuln.get("vendorProject", ""),
        "product": vuln.get("product", ""),
        "vulnerabilityName": vuln.get("vulnerabilityName", ""),
        "dateAdded": vuln.get("dateAdded", ""),
        "dueDate": vuln.get("dueDate") or None,
        "shortDescription": (vuln.get("shortDescription") or "").strip(),
        "knownRansomware": (vuln.get("knownRansomwareCampaignUse") or "").strip() == "Known",
    }
    if extra:
        salida.update(extra)
    return salida


def build_latest(
    *,
    vulns: list[dict],
    enriquecimiento: dict,
    nuevas_hoy: int,
    catalog: dict,
    hoy: datetime.date,
    ahora_iso: str,
    watchlist_hits: list[str],
    due_soon: list[dict],
) -> dict:
    recientes = sorted(
        (v for v in vulns if dias_desde(v.get("dateAdded", ""), hoy) <= VENTANA_DIAS),
        key=lambda v: v.get("dateAdded", ""),
        reverse=True,
    )[:MAX_RECIENTES]

    payload = {
        "schema": LATEST_SCHEMA,
        "source": REPO_URL,
        "generatedAt": normalizar_ts(ahora_iso),
        "catalogVersion": catalog.get("catalogVersion", ""),
        "dateReleased": catalog.get("dateReleased", ""),
        # A partir de aquí, contrato con la página KEV Watch del Blue Team Hub.
        "lastUpdated": hoy.isoformat(),
        "totalTracked": len(vulns),
        "newToday": nuevas_hoy,
        "recentAdditions": [
            entrada_publica(v, enriquecimiento.get(v["cveID"])) for v in recientes
        ],
        # Extras que el Hub aún no usa, pero que ya van publicados.
        "ransomwareTracked": sum(
            1 for v in vulns
            if (v.get("knownRansomwareCampaignUse") or "").strip() == "Known"
        ),
        "watchlistHits": watchlist_hits,
        "dueSoon": due_soon,
    }
    LATEST_FILE.parent.mkdir(parents=True, exist_ok=True)
    LATEST_FILE.write_text(
        json.dumps(payload, indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n",
    )
    return payload


def _entrada_atom(evento: dict) -> str:
    cve = evento.get("cve", "")
    tipo = {"new": "Nueva en KEV", "modified": "Modificada", "removed": "Retirada"}.get(
        evento.get("event", ""), "Cambio"
    )
    titulo = f"{tipo}: {cve}"
    if evento.get("vendor") or evento.get("product"):
        titulo += f" · {evento.get('vendor', '')} {evento.get('product', '')}".rstrip()
    if evento.get("ransomware"):
        titulo += " · Ransomware conocido"

    resumen = evento.get("summary") or evento.get("name") or ""
    # El id tiene que ser estable y único: misma CVE, distinto evento, distinta
    # marca de tiempo. Si se repitiera, los lectores colapsarían las entradas.
    ident = f"tag:eduolihez.github.io,2026:kev/{evento.get('event','x')}/{cve}/{evento.get('ts','')}"
    return "\n".join([
        "  <entry>",
        f"    <title>{escape(titulo)}</title>",
        f'    <link href="{escape(NVD + cve)}"/>',
        f"    <id>{escape(ident)}</id>",
        f"    <updated>{escape(evento.get('ts', ''))}</updated>",
        f"    <summary>{escape(resumen)}</summary>",
        "  </entry>",
    ])


def normalizar_ts(marca: str) -> str:
    """Pasa "2026-09-03 08:19 UTC" a "2026-09-03T08:19Z".

    `latest.json` es una salida pública que consume una web, así que la fecha
    va en ISO 8601 y no en el formato legible que se usa en el README.
    """
    limpio = marca.replace(" UTC", "").strip()
    if " " in limpio:
        fecha, _, hora = limpio.partition(" ")
        return f"{fecha}T{hora}Z"
    return limpio


def build_feed(ahora_iso: str) -> Path:
    """Feed Atom con los últimos eventos, para leerlo desde cualquier lector.

    Se escribe siempre, incluso sin eventos: un feed vacío sigue siendo válido,
    y quien se suscriba antes del primer cambio prefiere eso a un 404.
    """
    eventos = read_history()[-FEED_MAX:]
    eventos.reverse()  # lo más reciente primero
    cuerpo = "\n".join(_entrada_atom(e) for e in eventos) if eventos else ""

    # <updated> es cuándo cambió el feed, no cuándo se generó el archivo. Con
    # la hora de cada pasada, el XML era distinto ocho veces al día y provocaba
    # un commit vacío en cada una.
    actualizado = eventos[0].get("ts") if eventos else ahora_iso
    xml = "\n".join([
        '<?xml version="1.0" encoding="utf-8"?>',
        '<feed xmlns="http://www.w3.org/2005/Atom">',
        "  <title>KEV Digest</title>",
        "  <subtitle>Cambios en el catálogo CISA KEV</subtitle>",
        f'  <link href="{REPO_URL}"/>',
        f'  <link rel="self" href="{FEED_URL}"/>',
        f"  <id>{REPO_URL}</id>",
        f"  <updated>{escape(actualizado)}</updated>",
        "  <author><name>kev-digest</name></author>",
        cuerpo,
        "</feed>",
    ]) + "\n"
    FEED_FILE.parent.mkdir(parents=True, exist_ok=True)
    FEED_FILE.write_text(xml, encoding="utf-8", newline="\n")
    return FEED_FILE
