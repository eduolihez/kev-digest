# KEV Digest

[![KEV watch](https://github.com/eduolihez/kev-digest/actions/workflows/digest.yml/badge.svg)](https://github.com/eduolihez/kev-digest/actions/workflows/digest.yml)
[![Tests](https://github.com/eduolihez/kev-digest/actions/workflows/tests.yml/badge.svg)](https://github.com/eduolihez/kev-digest/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Fuente: CISA KEV](https://img.shields.io/badge/fuente-CISA%20KEV-005288.svg)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
[![Sin dependencias](https://img.shields.io/badge/dependencias-0-brightgreen.svg)](scripts/digest.py)

### **[Versión en Español](README.md)** · [English version](README.en.md)

Vigilancia automatizada del catálogo [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(*Known Exploited Vulnerabilities*): el registro oficial de vulnerabilidades que
se están explotando de verdad, ahora mismo, publicado por la agencia de
ciberseguridad estadounidense.

Cada tres horas un workflow descarga el catálogo, lo compara con la última foto
conocida y añade al archivo del día en [`digest/`](digest/) lo que haya
cambiado. Sin intervención manual y sin servidor: todo ocurre en GitHub Actions.

---

## Estado actual

<!-- KEV-STATS:START -->
<!-- Generado por scripts/digest.py. No editar a mano. -->

| | |
|---|---|
| **CVEs en seguimiento** | 1694 |
| **Con uso conocido en ransomware** | 352 |
| **Versión del catálogo** | 2026.09.02 |
| **Publicado por CISA** | 2026-09-02T16:54:39.8321Z |
| **Último cambio detectado** | 2026-09-03 08:01 UTC |
| **Último digest** | [`digest/2026-09-03.md`](digest/2026-09-03.md) |

<!-- KEV-STATS:END -->

---

## Por qué existe

El catálogo KEV es una de las pocas fuentes que responde a la pregunta que
importa en un SOC: *de todas las vulnerabilidades publicadas, ¿cuáles se están
explotando en la práctica?* Es el criterio que ordena la cola de parcheo.

El problema es que CISA lo actualiza sin previo aviso y consultarlo a mano cada
mañana no escala. Esto lo convierte en un registro histórico, versionado y
consultable: cada cambio deja un commit, y `git log` sirve de línea temporal de
la explotación activa.

## Qué detecta

Al principio esto solo miraba si aparecían CVEs nuevas. Pero una entrada ya
catalogada también cambia, y esos cambios mueven la prioridad de parcheo tanto
como una entrada nueva. Ahora se vigilan tres cosas:

- **Entradas nuevas.** Lo que CISA acaba de añadir al catálogo.
- **Entradas modificadas.** Cambios en el nombre, el fabricante, el producto, la
  fecha de alta, el plazo de mitigación, la descripción o la acción requerida.
  El que más importa: cuando `knownRansomwareCampaignUse` pasa a `Known`, que es
  una CVE que llevaba meses catalogada y de repente se usa en campañas de
  ransomware. Sale marcada en rojo, igual que en las nuevas.
- **Entradas retiradas.** CISA saca entradas del catálogo de vez en cuando. Antes
  desaparecían en silencio.

## Cómo funciona

```
cron cada 3 h
        │
        ▼
 descarga known_exploited_vulnerabilities.json  ← CISA (3 reintentos con backoff)
        │
        ▼
 valida: ¿no viene vacío? ¿no ha encogido más de un 10%?
        │
        ▼
 compara con data/seen_cves.json                ← última foto conocida
        │
        ├── nuevas ────────┐
        ├── modificadas ───┼──► añade una sección a digest/AAAA-MM-DD.md
        ├── retiradas ─────┘
        │
        ├── actualiza data/seen_cves.json
        │
        └── refresca el bloque de estado de los dos README
        │
        ▼
 commit + push (solo si algo cambió)
```

Detalles que importan:

- No tiene dependencias. Sólo la biblioteca estándar de Python 3.12 (`urllib`,
  `json`, `hashlib`, `pathlib`). No hay `requirements.txt` que mantener ni
  cadena de suministro que auditar.
- El estado vive en el repositorio. `data/seen_cves.json` es la única fuente de
  verdad: no hay base de datos ni almacenamiento externo.
- Cada pasada **añade** una sección al archivo del día en vez de reescribirlo,
  con la hora UTC en la cabecera. Así ocho pasadas diarias no se pisan entre
  ellas.
- Si no hay novedades, no se escribe nada y no hay commit. Con ocho pasadas al
  día, escribir siempre llenaría el historial de commits vacíos.
- Si el catálogo llega vacío, o con un 10% menos de entradas que la última vez,
  el script aborta sin guardar. Una descarga a medias marcaría cientos de CVEs
  como retiradas y guardaría esa foto como buena, destruyendo la línea base.
  Cuando el encogimiento sea real, se lanza a mano con `--force`.
- El estado se guarda *después* de escribir el digest, no antes. Si falla la
  escritura, la pasada siguiente vuelve a ver esas entradas como nuevas en vez
  de perderlas.

### Formato del estado

`data/seen_cves.json` guarda, por cada CVE, los campos que se vigilan. De los
dos campos largos (`shortDescription` y `requiredAction`) solo se guarda una
huella SHA-256 truncada: así se detecta que cambian sin meter varios cientos de
KB de prosa en el repositorio. El precio es que el digest dice "descripción:
actualizada" en vez de enseñar el antes y el después.

El formato anterior era una lista plana de IDs. El script lo detecta y lo migra
solo. En esa primera pasada no se reporta ninguna modificación, porque no hay
foto anterior de los campos con la que comparar.

## Estructura

```
scripts/digest.py     Toda la lógica: descarga, diff y escritura
tests/test_digest.py  Pruebas con catálogos inventados (unittest, sin red)
data/seen_cves.json   Última foto conocida del catálogo (estado)
digest/               Un archivo Markdown por día con los cambios
.github/workflows/
  digest.yml          Cron cada 3 h + commit automático
  tests.yml           Pruebas en cada push y PR
  dependabot-auto-merge.yml
```

## Qué hay en cada digest

Cada entrada nueva se registra con lo necesario para decidir si actuar:

- El CVE, con enlace a su ficha en el NVD
- Fabricante y producto afectados
- Nombre de la vulnerabilidad
- Fecha de incorporación al catálogo y plazo de mitigación fijado por CISA
- Descripción breve
- Un aviso destacado si consta uso conocido en campañas de ransomware

Las modificadas listan qué campo cambió y su valor anterior y nuevo. Las
retiradas, solo el CVE con su enlace.

## Ejecutarlo en local

No necesita instalación:

```bash
git clone https://github.com/eduolihez/kev-digest.git
cd kev-digest
python scripts/digest.py
```

Escribirá el digest de hoy en `digest/` y actualizará `data/seen_cves.json`.

| Flag | Para qué |
|---|---|
| `--dry-run` | Dice qué cambiaría sin tocar ningún archivo. Lo cómodo para mirar rápido |
| `--force` | Salta el guardia de encogimiento, cuando el catálogo ha menguado de verdad |

Para probar desde cero sin línea base previa, borra el archivo de estado antes
de ejecutarlo (`rm data/seen_cves.json`): el script detectará que es la primera
ejecución y sólo fijará la referencia.

Las pruebas no tocan la red, ni `data/`, ni `digest/`: trabajan sobre una copia
temporal del repositorio con catálogos inventados.

```bash
python -m unittest discover -s tests
```

## Sobre los datos

Los datos proceden del [catálogo KEV de CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
publicado por la *Cybersecurity and Infrastructure Security Agency* de EE. UU.
como obra del gobierno federal en dominio público. Este repositorio no está
afiliado a CISA ni respaldado por ella.

Los archivos de `digest/` son una vista derivada y automatizada. Para decisiones
operativas, consulta siempre el catálogo original, que es la fuente autoritativa.

## Licencia

[MIT](LICENSE) para el código de este repositorio. Los datos del catálogo KEV
son de dominio público, según lo indicado arriba.
