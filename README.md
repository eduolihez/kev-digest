# KEV Digest

[![Daily KEV digest](https://github.com/eduolihez/kev-digest/actions/workflows/digest.yml/badge.svg)](https://github.com/eduolihez/kev-digest/actions/workflows/digest.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Fuente: CISA KEV](https://img.shields.io/badge/fuente-CISA%20KEV-005288.svg)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
[![Sin dependencias](https://img.shields.io/badge/dependencias-0-brightgreen.svg)](scripts/digest.py)

Vigilancia diaria y automatizada del catálogo [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(*Known Exploited Vulnerabilities*): el registro oficial de vulnerabilidades que
**se están explotando de verdad, ahora mismo**, publicado por la agencia de
ciberseguridad estadounidense.

Cada mañana un workflow descarga el catálogo, lo compara con la última foto
conocida y deja un archivo fechado en [`digest/`](digest/) con lo que ha
cambiado. Sin intervención manual y sin servidor: todo ocurre en GitHub Actions.

---

## Estado actual

<!-- KEV-STATS:START -->
<!-- Generado por scripts/digest.py. No editar a mano. -->

| | |
|---|---|
| **Última ejecución** | 2026-08-24 |
| **CVEs en seguimiento** | 1674 |
| **Nuevas en esta ejecución** | 0 |
| **Con uso conocido en ransomware** | — |
| **Último digest** | [`digest/2026-08-24.md`](digest/2026-08-24.md) |

<!-- KEV-STATS:END -->

---

## Por qué existe

El catálogo KEV es una de las pocas fuentes que responde a la pregunta que
importa en un SOC: *de todas las vulnerabilidades publicadas, ¿cuáles se están
explotando en la práctica?* Es el criterio que ordena la cola de parcheo.

El problema es que CISA lo actualiza sin previo aviso y consultarlo a mano cada
mañana no escala. Esto lo convierte en un registro histórico, versionado y
consultable: cada día queda un commit con lo que entró, y `git log` sirve de
línea temporal de la explotación activa.

## Cómo funciona

```
cron diario (06:00 UTC)
        │
        ▼
 descarga known_exploited_vulnerabilities.json  ← CISA
        │
        ▼
 compara los cveID con data/seen_cves.json      ← última foto conocida
        │
        ├── entradas nuevas ──► digest/AAAA-MM-DD.md
        │
        ├── actualiza data/seen_cves.json
        │
        └── refresca el bloque de estado del README
        │
        ▼
 commit + push (solo si algo cambió)
```

Detalles que importan:

- **Sin dependencias.** Sólo la biblioteca estándar de Python 3.12
  (`urllib`, `json`, `pathlib`). No hay `requirements.txt` que mantener ni
  cadena de suministro que auditar.
- **El estado vive en el repositorio.** `data/seen_cves.json` es la única
  fuente de verdad: no hay base de datos ni almacenamiento externo.
- **Idempotente.** Si el workflow se ejecuta dos veces el mismo día, el
  segundo pase no encuentra diferencias y no genera commit.
- **La primera ejecución sólo fija la línea base.** No inunda el primer digest
  con las ~1.700 CVE que ya estaban en el catálogo.

## Estructura

```
scripts/digest.py     Toda la lógica: descarga, diff y escritura
data/seen_cves.json   Última foto conocida del catálogo (estado)
digest/               Un archivo Markdown por día con los cambios
.github/workflows/
  digest.yml          Cron diario + commit automático
  dependabot-auto-merge.yml
```

## Qué hay en cada digest

Cada entrada nueva se registra con lo necesario para decidir si actuar:

- **CVE** con enlace a su ficha en el NVD
- Fabricante y producto afectados
- Nombre de la vulnerabilidad
- Fecha de incorporación al catálogo y **plazo de mitigación** fijado por CISA
- Descripción breve
- Aviso destacado si consta **uso conocido en campañas de ransomware**

## Ejecutarlo en local

No necesita instalación:

```bash
git clone https://github.com/eduolihez/kev-digest.git
cd kev-digest
python scripts/digest.py
```

Escribirá el digest de hoy en `digest/` y actualizará `data/seen_cves.json`.
Para probar desde cero sin línea base previa, borra el archivo de estado antes
de ejecutarlo (`rm data/seen_cves.json`): el script detectará que es la primera
ejecución y sólo fijará la referencia.

## Sobre los datos

Los datos proceden del [catálogo KEV de CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
publicado por la *Cybersecurity and Infrastructure Security Agency* de EE. UU.
como obra del gobierno federal en dominio público. Este repositorio no está
afiliado a CISA ni respaldado por ella.

Los archivos de `digest/` son una vista derivada y automatizada: **para
decisiones operativas, consulta siempre el catálogo original**, que es la
fuente autoritativa.

## Licencia

[MIT](LICENSE) para el código de este repositorio. Los datos del catálogo KEV
son de dominio público, según lo indicado arriba.
