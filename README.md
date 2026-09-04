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
| **CVEs en seguimiento** | 1695 |
| **Con uso conocido en ransomware** | 354 |
| **Versión del catálogo** | 2026.09.04 |
| **Publicado por CISA** | 2026-09-04T16:47:03.5197Z |
| **Último cambio detectado** | 2026-09-04 18:06 UTC |
| **Plazos que vencen en 7 días** | 10 |
| **Último digest** | [`digest/2026-09-04.md`](digest/2026-09-04.md) |

<!-- KEV-STATS:END -->

---

## Cómo enterarte

El proyecto no sirve de nada si hay que entrar al repositorio a mirar. Hay tres
formas de que te llegue:

- **Feed Atom** en [`digest/feed.xml`](digest/feed.xml), con los últimos 50
  eventos. Se lee desde cualquier cliente de RSS, sin cuenta ni permisos.
- **Un issue por día** con novedades. GitHub ya notifica de los issues, así que
  no hace falta ni webhook ni secreto, y queda un hilo donde anotar qué hiciste
  con cada CVE. Las pasadas siguientes del mismo día comentan en ese issue en
  vez de abrir otro.
- **Telegram**, si defines los secretos `TELEGRAM_BOT_TOKEN` y
  `TELEGRAM_CHAT_ID`. Sin ellos, ese paso se salta.

## Por qué existe

El catálogo KEV es una de las pocas fuentes que responde a la pregunta que
importa en un SOC: *de todas las vulnerabilidades publicadas, ¿cuáles se están
explotando en la práctica?* Es el criterio que ordena la cola de parcheo.

El problema es que CISA lo actualiza sin previo aviso y consultarlo a mano cada
mañana no escala. Esto lo convierte en un registro histórico, versionado y
consultable: cada cambio deja un commit, y `git log` sirve de línea temporal de
la explotación activa.

## Qué detecta

- **Entradas nuevas.** Lo que CISA acaba de añadir al catálogo.
- **Entradas modificadas.** Cambios en el nombre, el fabricante, el producto, la
  fecha de alta, el plazo de mitigación, la descripción o la acción requerida.
  El que más importa: cuando `knownRansomwareCampaignUse` pasa a `Known`, que es
  una CVE que llevaba meses catalogada y de repente se usa en campañas de
  ransomware. Sale marcada en rojo, igual que en las nuevas.
- **Entradas retiradas.** CISA saca entradas del catálogo de vez en cuando.
- **Plazos a punto de vencer.** CISA fija una fecha límite de mitigación por
  entrada. Se avisa de las que vencen en 7 días o menos, y solo la primera vez
  que entran en esa ventana: repetirlo en las ocho pasadas diarias durante una
  semana sería insufrible.

## Tu inventario

De 1.694 CVEs, a un analista le importan las de los productos que tiene
delante. Con una watchlist, el digest abre con un bloque **"Afecta a tu
inventario"** antes del listado general, y esas entradas van marcadas con ⭐.

```json
{
  "vendors": ["Fortinet", "Microsoft"],
  "products": ["FortiGate", "Exchange"],
  "cves": ["CVE-2026-12345"]
}
```

El match es por subcadena e insensible a mayúsculas, así que `fortinet` casa
con `Fortinet FortiOS`. Es deliberadamente laxo: más vale un falso positivo que
perderse una entrada de algo que sí tienes desplegado.

> **Dónde ponerla.** En un repositorio público, la lista de fabricantes y
> productos de tu organización es un inventario de su stack al alcance de
> cualquiera. Por eso se lee primero del secreto `KEV_WATCHLIST` del
> repositorio, y solo si no está, de `config/watchlist.json`, que está en el
> `.gitignore`. Tienes una plantilla en
> [`config/watchlist.example.json`](config/watchlist.example.json).

## Contexto de cada CVE

Estar en KEV dice que se explota, pero no si es un 9.8 o un 5.4. Cada entrada
nueva se enriquece con dos fuentes gratuitas:

- **EPSS** (FIRST.org): probabilidad de explotación en los próximos 30 días.
  Admite consulta en bloque, así que todas las CVE de una pasada caben en una
  petición.
- **NVD 2.0** (NIST): CVSS y severidad. Va de una en una y con rate-limit, así
  que se cachea en `data/enrichment.json` y se limita cuántas se piden por
  pasada.

Solo se enriquecen las entradas nuevas: pedir el CVSS de las 1.694 en cada
pasada no tendría sentido. Si una fuente falla, el digest sale igual, sin ese
dato. El secreto opcional `NVD_API_KEY` sube el rate-limit del NVD de 5 a 50
peticiones cada 30 s.

## Salida pública

[`data/latest.json`](data/latest.json) es el artefacto que consume la página
[KEV Watch](https://eduolihez.github.io/tools/kev-watch) del Blue Team Hub. El
cálculo del diff vive solo aquí, y el Hub se limita a descargar el resultado
cada 3 horas.

Los campos `lastUpdated`, `totalTracked`, `newToday` y `recentAdditions` son
contrato con esa página: renombrarlos la rompe, y hay una prueba que lo vigila.
Lleva además `ransomwareTracked`, `dueSoon` y `watchlistHits`.

`data/history.jsonl` es un registro de solo-añadir con un evento por línea.
Sirve para responder "¿cuándo entró esta CVE?" sin arqueología de `git log`, y
es de donde sale el feed.

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
        ├── modificadas ───┤
        ├── retiradas ─────┼──► añade una sección a digest/AAAA-MM-DD.md
        ├── plazos ────────┘
        │
        ├── enriquece las nuevas con EPSS y NVD (con caché)
        ├── actualiza data/seen_cves.json y data/history.jsonl
        ├── publica data/latest.json y digest/feed.xml
        └── refresca el bloque de estado de los dos README
        │
        ▼
 commit + push + aviso (solo si algo cambió)
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
- Las actions van fijadas por SHA, no por tag: un tag se puede mover, y este
  workflow tiene permiso de escritura sobre el repositorio.

### Formato del estado

`data/seen_cves.json` guarda, por cada CVE, los campos que se vigilan. De los
dos campos largos (`shortDescription` y `requiredAction`) solo se guarda una
huella SHA-256 truncada: así se detecta que cambian sin meter varios cientos de
KB de prosa en el repositorio. El precio es que el digest dice "descripción:
actualizada" en vez de enseñar el antes y el después.

Los formatos anteriores se migran solos, y esa primera pasada no reporta
modificaciones, porque no hay foto de los campos con la que comparar.

## Estructura

```
scripts/digest.py     Descarga, diff y escritura del digest
scripts/enrich.py     EPSS y CVSS, con caché en disco
scripts/publish.py    latest.json, feed Atom e historial
tests/test_digest.py  Pruebas con catálogos inventados (unittest, sin red)
config/               Plantilla de la watchlist (la real no se versiona)
data/seen_cves.json   Última foto conocida del catálogo (estado)
data/enrichment.json  Caché de EPSS y CVSS
data/history.jsonl    Un evento por línea, solo-añadir
data/latest.json      Salida pública que consume el Blue Team Hub
digest/               Un archivo Markdown por día, más feed.xml
.github/workflows/
  digest.yml          Cron cada 3 h, commit y aviso
  tests.yml           Pruebas en cada push y PR
  dependabot-auto-merge.yml
```

## Qué hay en cada digest

Cada entrada nueva se registra con lo necesario para decidir si actuar:

- El CVE, con enlace a su ficha en el NVD
- Fabricante y producto afectados
- Nombre de la vulnerabilidad
- Fecha de incorporación al catálogo y plazo de mitigación fijado por CISA
- CVSS y EPSS, cuando se han podido obtener
- Descripción breve
- Un aviso destacado si consta uso conocido en campañas de ransomware, y una
  estrella si está en tu inventario

Las modificadas listan qué campo cambió y su valor anterior y nuevo. Las
retiradas, solo el CVE con su enlace.

## Ejecutarlo en local

No necesita instalación:

```bash
git clone https://github.com/eduolihez/kev-digest.git
cd kev-digest
python scripts/digest.py
```

| Flag | Para qué |
|---|---|
| `--dry-run` | Dice qué cambiaría sin tocar ningún archivo |
| `--force` | Salta el guardia de encogimiento, cuando el catálogo ha menguado de verdad |
| `--no-enrich` | No consulta EPSS ni NVD; usa solo lo ya cacheado |

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
como obra del gobierno federal en dominio público. El enriquecimiento viene del
[NVD](https://nvd.nist.gov/) y de [EPSS](https://www.first.org/epss/). Este
repositorio no está afiliado a ninguno de los tres ni respaldado por ellos.

Los archivos de `digest/` son una vista derivada y automatizada. Para decisiones
operativas, consulta siempre el catálogo original, que es la fuente autoritativa.

## Licencia

[MIT](LICENSE) para el código de este repositorio. Los datos del catálogo KEV
son de dominio público, según lo indicado arriba.
