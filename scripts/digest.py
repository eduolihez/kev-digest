#!/usr/bin/env python3
"""Vigilante del catálogo CISA KEV (Known Exploited Vulnerabilities).

Descarga el catálogo, lo compara con la última foto conocida y añade al digest
del día lo que haya cambiado: entradas nuevas, entradas modificadas y entradas
retiradas. Pensado para correr varias veces al día desde
.github/workflows/digest.yml, así que cada pasada *añade* una sección al
archivo del día en vez de reescribirlo.

Sin dependencias: solo biblioteca estándar de Python 3.12.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = ROOT / "data" / "seen_cves.json"
DIGEST_DIR = ROOT / "digest"

SCHEMA = 2

# Delimitan la única parte de los README que este script reescribe.
STATS_START = "<!-- KEV-STATS:START -->"
STATS_END = "<!-- KEV-STATS:END -->"

# Campos cortos: se guardan tal cual, así el diff puede enseñar "antes -> después".
LITERAL_FIELDS = {
    "vendorProject": ("fabricante", "vendor"),
    "product": ("producto", "product"),
    "vulnerabilityName": ("nombre", "name"),
    "dateAdded": ("fecha de alta", "date added"),
    "dueDate": ("plazo de mitigación", "remediation deadline"),
    "knownRansomwareCampaignUse": ("uso en ransomware", "ransomware use"),
}
# Campos largos: guardamos solo una huella. Detectamos que cambian sin meter
# varios cientos de KB de prosa en el archivo de estado.
HASHED_FIELDS = {
    "shortDescription": ("descripción", "description"),
    "requiredAction": ("acción requerida", "required action"),
}

FETCH_ATTEMPTS = 3
FETCH_BACKOFF = 5  # segundos, se multiplica por el número de intento

# Si el catálogo encoge más de esto de golpe, casi seguro que la descarga vino
# mal (CDN a medias, mantenimiento, respuesta truncada). Abortamos antes de
# guardar el estado, porque machacarlo con datos malos perdería la línea base.
SHRINK_GUARD = 0.10


def fingerprint(text: str) -> str:
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()[:12]


def snapshot(vuln: dict) -> dict:
    """Los campos que vigilamos de una entrada, listos para guardar."""
    snap = {key: (vuln.get(key) or "").strip() for key in LITERAL_FIELDS}
    for key in HASHED_FIELDS:
        snap[key + "#"] = fingerprint(vuln.get(key) or "")
    return snap


def fetch_kev(attempts: int = FETCH_ATTEMPTS) -> dict:
    """Descarga el catálogo, reintentando los fallos de red transitorios."""
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            req = urllib.request.Request(
                KEV_URL, headers={"User-Agent": "kev-digest/2.0 (+https://github.com/eduolihez/kev-digest)"}
            )
            with urllib.request.urlopen(req, timeout=45) as resp:
                return json.load(resp)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            last_error = exc
            if attempt < attempts:
                pausa = FETCH_BACKOFF * attempt
                print(
                    f"Intento {attempt}/{attempts} fallido ({exc}); reintento en {pausa}s",
                    file=sys.stderr,
                )
                time.sleep(pausa)
    raise RuntimeError(f"no se pudo descargar el catálogo tras {attempts} intentos: {last_error}")


def load_state() -> tuple[dict | None, dict]:
    """Devuelve (entradas, meta).

    `entradas` es None en la primera ejecución absoluta. Acepta el formato
    antiguo (una lista plana de CVE IDs) y lo migra: en ese caso cada entrada
    vale None, que significa "sé que existe, pero no tengo foto de sus campos",
    y por tanto no se reporta como modificada en la pasada de migración.
    """
    if not STATE_FILE.exists():
        return None, {}
    raw = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return {cve: None for cve in raw}, {"schema": 1}
    meta = {k: v for k, v in raw.items() if k != "entries"}
    return raw.get("entries", {}), meta


def save_state(entries: dict, catalog: dict, last_change: str) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": SCHEMA,
        "catalog_version": catalog.get("catalogVersion", ""),
        "date_released": catalog.get("dateReleased", ""),
        "last_change": last_change,
        "count": len(entries),
        "entries": entries,
    }
    # Escritura atómica: si el runner muere a media escritura, no queremos
    # dejar un seen_cves.json truncado que rompa la ejecución siguiente.
    tmp = STATE_FILE.with_suffix(".json.tmp")
    tmp.write_text(serialize_state(payload), encoding="utf-8")
    tmp.replace(STATE_FILE)


def serialize_state(payload: dict) -> str:
    """JSON con una línea por CVE.

    Con indentación completa el archivo pasaba de 600 KB y cada cambio
    reescribía miles de líneas. Con una línea por entrada, el diff de git
    enseña exactamente qué CVEs se movieron y el archivo ocupa la mitad.
    """
    entries = payload["entries"]
    cabecera = [
        f" {json.dumps(k)}: {json.dumps(v, ensure_ascii=False)},"
        for k, v in payload.items()
        if k != "entries"
    ]
    filas = [
        "  {}: {}".format(
            json.dumps(cve),
            json.dumps(entries[cve], sort_keys=True, ensure_ascii=False, separators=(", ", ": ")),
        )
        for cve in sorted(entries)
    ]
    salto = "\n"
    cuerpo = ("," + salto).join(filas)
    return salto.join(["{", *cabecera, ' "entries": {', cuerpo, " }", "}"]) + salto


def diff_catalog(previous: dict, current: dict) -> tuple[list, list, list]:
    """Compara la foto anterior con la actual.

    Devuelve (nuevas, modificadas, retiradas). Cada modificada es
    (cveID, [(etiqueta_es, etiqueta_en, antes, después), ...]).
    """
    nuevas = sorted(set(current) - set(previous))
    retiradas = sorted(set(previous) - set(current))
    modificadas = []

    for cve in sorted(set(previous) & set(current)):
        antes = previous[cve]
        if antes is None:
            continue  # migración desde el formato v1: no hay foto con la que comparar
        ahora = current[cve]
        cambios = []
        for key, (es, en) in LITERAL_FIELDS.items():
            if antes.get(key, "") != ahora.get(key, ""):
                cambios.append((es, en, antes.get(key, ""), ahora.get(key, "")))
        for key, (es, en) in HASHED_FIELDS.items():
            if antes.get(key + "#", "") != ahora.get(key + "#", ""):
                cambios.append((es, en, None, None))  # solo tenemos la huella
        if cambios:
            modificadas.append((cve, cambios))

    return nuevas, modificadas, retiradas


def format_new(vuln: dict) -> str:
    cve = vuln["cveID"]
    # El catálogo marca las CVE con uso conocido en campañas de ransomware.
    # Para un analista es lo primero que quiere ver, así que va en la cabecera.
    ransomware = (vuln.get("knownRansomwareCampaignUse") or "Unknown").strip()
    flag = " · 🔴 **Ransomware conocido**" if ransomware.lower() == "known" else ""
    return (
        f"- **[{cve}](https://nvd.nist.gov/vuln/detail/{cve})** · "
        f"{vuln['vendorProject']} {vuln['product']}{flag}\n"
        f"  {vuln['vulnerabilityName']}\n"
        f"  Añadida al catálogo: {vuln['dateAdded']} · "
        f"Plazo de mitigación: {vuln.get('dueDate') or 'n/d'}\n"
        f"  {(vuln.get('shortDescription') or '').strip()}\n"
    )


def format_modified(cve: str, cambios: list) -> str:
    lineas = [f"- **[{cve}](https://nvd.nist.gov/vuln/detail/{cve})**"]
    for etiqueta_es, _en, antes, despues in cambios:
        if antes is None:
            lineas.append(f"  - {etiqueta_es}: actualizada")
        elif etiqueta_es == "uso en ransomware" and despues.lower() == "known":
            # Que una CVE ya catalogada pase a usarse en ransomware cambia su
            # prioridad de parcheo, así que se marca igual que en las nuevas.
            lineas.append(f"  - 🔴 **uso en ransomware: {antes or 'n/d'} → {despues}**")
        else:
            lineas.append(f"  - {etiqueta_es}: {antes or 'n/d'} → {despues or 'n/d'}")
    return "\n".join(lineas) + "\n"


def append_digest(
    fecha: str,
    hora: str,
    nuevas_v: list,
    modificadas: list,
    retiradas: list,
    total: int,
) -> Path:
    """Añade una sección al digest del día, creándolo si no existe.

    Se añade en vez de reescribir porque el script corre varias veces al día:
    reescribir haría que la pasada de las 18:00 borrase lo que encontró la de
    las 06:00.
    """
    DIGEST_DIR.mkdir(parents=True, exist_ok=True)
    path = DIGEST_DIR / f"{fecha}.md"

    titulares = []
    if nuevas_v:
        titulares.append(f"{len(nuevas_v)} nueva(s)")
    if modificadas:
        titulares.append(f"{len(modificadas)} modificada(s)")
    if retiradas:
        titulares.append(f"{len(retiradas)} retirada(s)")

    partes = [f"## {hora} · {' · '.join(titulares)}\n"]

    if nuevas_v:
        partes.append("### Entradas nuevas\n")
        partes.append("\n".join(format_new(v) for v in nuevas_v))
    if modificadas:
        partes.append("### Entradas modificadas\n")
        partes.append("\n".join(format_modified(cve, c) for cve, c in modificadas))
    if retiradas:
        partes.append("### Entradas retiradas del catálogo\n")
        partes.append(
            "\n".join(
                f"- [{cve}](https://nvd.nist.gov/vuln/detail/{cve})" for cve in retiradas
            )
            + "\n"
        )
    partes.append(f"_Total en seguimiento tras esta comprobación: {total}._\n")

    seccion = "\n".join(partes)

    if path.exists():
        contenido = path.read_text(encoding="utf-8").rstrip() + "\n\n" + seccion
    else:
        contenido = f"# KEV digest · {fecha}\n\n" + seccion

    path.write_text(contenido, encoding="utf-8")
    return path


def write_baseline(fecha: str, total: int) -> Path:
    DIGEST_DIR.mkdir(parents=True, exist_ok=True)
    path = DIGEST_DIR / f"{fecha}.md"
    path.write_text(
        f"# KEV digest · {fecha}\n\n"
        f"Primera ejecución: se establece la línea base con **{total}** CVEs ya "
        "presentes en el catálogo CISA KEV. A partir de la siguiente pasada, "
        "este archivo solo listará lo que cambie.\n",
        encoding="utf-8",
    )
    return path


def stats_block(labels: dict, meta: dict, ultimo_digest: str | None) -> str:
    filas = [
        f"| **{labels['tracked']}** | {meta['total']} |",
        f"| **{labels['ransomware']}** | {meta['ransomware']} |",
        f"| **{labels['version']}** | {meta['catalog_version'] or 'n/d'} |",
        f"| **{labels['released']}** | {meta['date_released'] or 'n/d'} |",
        f"| **{labels['change']}** | {meta['last_change']} |",
    ]
    if ultimo_digest:
        filas.append(
            f"| **{labels['digest']}** | "
            f"[`digest/{ultimo_digest}.md`](digest/{ultimo_digest}.md) |"
        )
    return "\n".join(
        [STATS_START, f"<!-- {labels['generated']} -->", "", "| | |", "|---|---|", *filas, "", STATS_END]
    )


ES_LABELS = {
    "tracked": "CVEs en seguimiento",
    "ransomware": "Con uso conocido en ransomware",
    "version": "Versión del catálogo",
    "released": "Publicado por CISA",
    "change": "Último cambio detectado",
    "digest": "Último digest",
    "generated": "Generado por scripts/digest.py. No editar a mano.",
}
EN_LABELS = {
    "tracked": "CVEs tracked",
    "ransomware": "Known ransomware use",
    "version": "Catalog version",
    "released": "Published by CISA",
    "change": "Last change detected",
    "digest": "Latest digest",
    "generated": "Generated by scripts/digest.py. Do not edit by hand.",
}


def update_readmes(meta: dict, ultimo_digest: str | None) -> list[str]:
    """Refresca SOLO el bloque de estadísticas de cada README.

    Los README los escribe una persona; de aquí sale únicamente lo que hay
    entre los dos marcadores. Si los marcadores no están, no se toca el
    archivo: es preferible un README con cifras viejas que un README
    machacado.
    """
    tocados = []
    for nombre, labels in (("README.md", ES_LABELS), ("README.en.md", EN_LABELS)):
        ruta = ROOT / nombre
        if not ruta.exists():
            continue
        contenido = ruta.read_text(encoding="utf-8")
        if STATS_START not in contenido or STATS_END not in contenido:
            print(f"{nombre}: marcadores no encontrados, se deja intacto.", file=sys.stderr)
            continue
        inicio = contenido.index(STATS_START)
        fin = contenido.index(STATS_END) + len(STATS_END)
        nuevo = contenido[:inicio] + stats_block(labels, meta, ultimo_digest) + contenido[fin:]
        if nuevo != contenido:
            ruta.write_text(nuevo, encoding="utf-8")
            tocados.append(nombre)
    return tocados


def emit_outputs(**kwargs) -> None:
    """Publica el resultado para el workflow.

    Antes el mensaje de commit salía de un grep sobre el Markdown del digest,
    que se rompía cada vez que cambiaba el formato de una línea. Ahora las
    cifras salen de aquí, que es donde se calculan.
    """
    destino = os.environ.get("GITHUB_OUTPUT")
    if not destino:
        return
    with open(destino, "a", encoding="utf-8") as fh:
        for clave, valor in kwargs.items():
            fh.write(f"{clave}={valor}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run", action="store_true", help="no escribe nada, solo informa de lo que cambiaría"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="procesa aunque el catálogo haya encogido más de lo razonable",
    )
    args = parser.parse_args()

    ahora = datetime.datetime.now(datetime.UTC)
    fecha = ahora.date().isoformat()
    hora = ahora.strftime("%H:%M UTC")

    try:
        catalog = fetch_kev()
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    vulns = [v for v in catalog.get("vulnerabilities", []) if v.get("cveID")]
    if not vulns:
        print("ERROR: el catálogo vino vacío o sin cveID; no se toca el estado.", file=sys.stderr)
        return 1

    previous, prev_meta = load_state()
    first_run = previous is None

    if not first_run and previous:
        caida = (len(previous) - len(vulns)) / len(previous)
        if caida > SHRINK_GUARD and not args.force:
            print(
                f"ERROR: el catálogo ha pasado de {len(previous)} a {len(vulns)} entradas "
                f"({caida:.1%} menos). Parece una descarga incompleta, así que no se "
                "guarda el estado. Usa --force si el cambio es real.",
                file=sys.stderr,
            )
            return 1

    current = {v["cveID"]: snapshot(v) for v in vulns}
    por_id = {v["cveID"]: v for v in vulns}
    ransomware = sum(
        1
        for v in vulns
        if (v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
    )

    if first_run:
        nuevas, modificadas, retiradas = [], [], []
    else:
        nuevas, modificadas, retiradas = diff_catalog(previous, current)

    nuevas_v = sorted(
        (por_id[c] for c in nuevas), key=lambda v: v.get("dateAdded", ""), reverse=True
    )
    hay_cambios = bool(nuevas or modificadas or retiradas)
    migracion = prev_meta.get("schema") == 1

    resumen = (
        f"digest: {len(nuevas)} nuevas, {len(modificadas)} modificadas, "
        f"{len(retiradas)} retiradas ({fecha} {hora})"
    )
    if first_run:
        resumen = f"digest: línea base con {len(current)} CVEs ({fecha})"
    elif migracion and not hay_cambios:
        resumen = f"digest: estado migrado al formato v{SCHEMA} ({fecha})"

    if args.dry_run:
        print(resumen)
        for cve, cambios in modificadas:
            print(f"  ~ {cve}: " + ", ".join(c[0] for c in cambios))
        for cve in nuevas:
            print(f"  + {cve}")
        for cve in retiradas:
            print(f"  - {cve}")
        return 0

    ultimo_digest = None
    if first_run:
        ultimo_digest = fecha
        write_baseline(fecha, len(current))
    elif hay_cambios:
        ultimo_digest = fecha
        append_digest(fecha, hora, nuevas_v, modificadas, retiradas, len(current))
    else:
        # Sin novedades no se escribe digest ni se toca el README: con 8 pasadas
        # al día, hacerlo llenaría el historial de commits vacíos.
        existentes = sorted(p.stem for p in DIGEST_DIR.glob("*.md")) if DIGEST_DIR.exists() else []
        ultimo_digest = existentes[-1] if existentes else None

    if hay_cambios or first_run:
        last_change = f"{fecha} {hora}"
    else:
        # Al migrar desde el formato v1 no hay fecha previa que conservar, así
        # que se siembra con la de ahora: es cuando se fija la foto de campos.
        last_change = prev_meta.get("last_change") or f"{fecha} {hora}"

    if hay_cambios or first_run or migracion:
        save_state(current, catalog, last_change)
        update_readmes(
            {
                "total": len(current),
                "ransomware": ransomware,
                "catalog_version": catalog.get("catalogVersion", ""),
                "date_released": catalog.get("dateReleased", ""),
                "last_change": last_change,
            },
            ultimo_digest,
        )

    emit_outputs(
        changed=str(hay_cambios or first_run or migracion).lower(),
        new=len(nuevas),
        modified=len(modificadas),
        removed=len(retiradas),
        total=len(current),
        date=fecha,
        summary=resumen,
    )

    print(resumen)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
