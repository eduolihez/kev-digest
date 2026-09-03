#!/usr/bin/env python3
"""Enriquecimiento de CVEs con EPSS y CVSS.

Que una CVE esté en KEV dice que se explota, pero no si es un 9.8 o un 5.4, ni
qué probabilidad de explotación tiene en los próximos 30 días. Eso lo dan dos
fuentes gratuitas:

- EPSS (FIRST.org): probabilidad de explotación. Admite consulta en bloque, así
  que todas las CVE nuevas de una pasada caben en una sola petición.
- NVD 2.0 (NIST): CVSS. Va de una en una y con un rate-limit bajo, así que se
  cachea en disco y se limita cuántas se piden por pasada.

Todo es opcional: si una fuente falla, el digest sale igual, solo que sin ese
dato. Nunca debe impedir que se registre una CVE nueva.

Sin dependencias: solo biblioteca estándar.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_FILE = ROOT / "data" / "enrichment.json"

EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

EPSS_CHUNK = 100  # la API acepta varias CVE separadas por coma
NVD_MAX_POR_PASADA = 20  # cota para que una pasada no se eternice
# Sin clave el NVD deja 5 peticiones cada 30 s; con clave gratuita, 50.
NVD_PAUSA_SIN_CLAVE = 6.5
NVD_PAUSA_CON_CLAVE = 0.7

TIMEOUT = 30
USER_AGENT = "kev-digest/3.0 (+https://github.com/eduolihez/kev-digest)"


def load_cache() -> dict:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print("Caché de enriquecimiento corrupta; se empieza de cero.", file=sys.stderr)
    return {}


def save_cache(cache: dict) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    lineas = [
        "  {}: {}".format(
            json.dumps(cve),
            json.dumps(cache[cve], sort_keys=True, separators=(", ", ": ")),
        )
        for cve in sorted(cache)
    ]
    # Una línea por CVE, igual que el estado: diffs de git legibles.
    texto = "\n".join(["{", ",\n".join(lineas), "}"]) + "\n" if lineas else "{}\n"
    tmp = CACHE_FILE.with_suffix(".json.tmp")
    tmp.write_text(texto, encoding="utf-8", newline="\n")
    tmp.replace(CACHE_FILE)


def _get(url: str, headers: dict | None = None) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.load(resp)


def fetch_epss(cves: list[str]) -> dict:
    """Probabilidad de explotación por CVE. Una petición por cada 100."""
    salida: dict[str, dict] = {}
    for i in range(0, len(cves), EPSS_CHUNK):
        lote = cves[i : i + EPSS_CHUNK]
        url = f"{EPSS_URL}?{urllib.parse.urlencode({'cve': ','.join(lote)})}"
        try:
            datos = _get(url)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            print(f"EPSS no disponible para {len(lote)} CVE(s): {exc}", file=sys.stderr)
            continue
        for fila in datos.get("data", []):
            cve = fila.get("cve")
            if not cve:
                continue
            try:
                salida[cve] = {
                    "epss": round(float(fila["epss"]), 5),
                    "epssPercentile": round(float(fila["percentile"]), 5),
                }
            except (KeyError, TypeError, ValueError):
                continue
    return salida


def fetch_cvss(cve: str, api_key: str | None) -> dict | None:
    """CVSS de una CVE desde el NVD. Prefiere v3.1, luego v3.0, luego v2."""
    headers = {"apiKey": api_key} if api_key else {}
    try:
        datos = _get(f"{NVD_URL}?cveId={urllib.parse.quote(cve)}", headers)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        print(f"NVD no disponible para {cve}: {exc}", file=sys.stderr)
        return None

    vulns = datos.get("vulnerabilities") or []
    if not vulns:
        return None
    metricas = (vulns[0].get("cve") or {}).get("metrics") or {}
    for clave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entrada in metricas.get(clave) or []:
            datos_cvss = entrada.get("cvssData") or {}
            score = datos_cvss.get("baseScore")
            if score is None:
                continue
            severidad = datos_cvss.get("baseSeverity") or entrada.get("baseSeverity") or ""
            return {
                "cvss": float(score),
                "cvssSeverity": severidad.capitalize(),
                "cvssVersion": datos_cvss.get("version", ""),
            }
    return None


def enrich(cves: list[str], *, network: bool = True, limite_nvd: int = NVD_MAX_POR_PASADA) -> dict:
    """Devuelve {cve: {epss, epssPercentile, cvss, cvssSeverity}} usando caché.

    Solo pide a la red lo que no esté cacheado. Los fallos se tragan: esto
    añade contexto, y no puede ser el motivo de que una CVE nueva no se
    registre.
    """
    cache = load_cache()
    if not network:
        return {c: cache[c] for c in cves if c in cache}

    pendientes = [c for c in cves if c not in cache]
    if not pendientes:
        return {c: cache[c] for c in cves if c in cache}

    epss = fetch_epss(pendientes)

    api_key = os.environ.get("NVD_API_KEY") or None
    pausa = NVD_PAUSA_CON_CLAVE if api_key else NVD_PAUSA_SIN_CLAVE
    for indice, cve in enumerate(pendientes[:limite_nvd]):
        if indice:
            time.sleep(pausa)
        cvss = fetch_cvss(cve, api_key)
        if cvss:
            epss.setdefault(cve, {}).update(cvss)

    for cve in pendientes:
        if cve in epss:
            cache[cve] = epss[cve]

    if epss:
        save_cache(cache)

    return {c: cache[c] for c in cves if c in cache}


def etiqueta(datos: dict | None) -> str:
    """Una línea corta para el digest. Vacía si no hay nada que decir."""
    if not datos:
        return ""
    partes = []
    if "cvss" in datos:
        sev = datos.get("cvssSeverity") or ""
        partes.append(f"CVSS {datos['cvss']}{f' ({sev})' if sev else ''}")
    if "epss" in datos:
        pct = datos["epss"] * 100
        percentil = datos.get("epssPercentile")
        texto = f"EPSS {pct:.1f}%"
        if percentil is not None:
            texto += f" (percentil {percentil * 100:.0f})"
        partes.append(texto)
    return " · ".join(partes)
