# KEV Digest

[![Daily KEV digest](https://github.com/eduolihez/kev-digest/actions/workflows/digest.yml/badge.svg)](https://github.com/eduolihez/kev-digest/actions/workflows/digest.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Source: CISA KEV](https://img.shields.io/badge/fuente-CISA%20KEV-005288.svg)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
[![No dependencies](https://img.shields.io/badge/dependencias-0-brightgreen.svg)](scripts/digest.py)

### [Versión en Español](README.md) · **[English version](README.en.md)**

Automated daily watch over the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalog (*Known Exploited Vulnerabilities*): the official record of
vulnerabilities that are genuinely being exploited right now, published by the
US cybersecurity agency.

Every morning a workflow downloads the catalog, compares it against the last
known snapshot, and leaves a dated file in [`digest/`](digest/) with whatever
changed. No manual work and no server: it all happens on GitHub Actions.

---

## Current status

The live counters (CVEs tracked, new entries in the last run, ransomware
overlap) are kept up to date in the Spanish
[README](README.md#estado-actual), which is the file `scripts/digest.py`
rewrites on every run. The newest report is always the last file in
[`digest/`](digest/).

---

## Why it exists

The KEV catalog is one of the few sources that answers the question that
matters in a SOC: *of all the published vulnerabilities, which ones are
actually being exploited?* That is the criterion that orders the patching
queue.

The problem is that CISA updates it without warning, and checking it by hand
every morning doesn't scale. This turns it into a historical record that is
versioned and searchable: every day leaves a commit with what came in, and
`git log` becomes a timeline of active exploitation.

## How it works

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

Details that matter:

- It has no dependencies. Only the Python 3.12 standard library (`urllib`,
  `json`, `pathlib`). There is no `requirements.txt` to maintain and no supply
  chain to audit.
- The state lives in the repository. `data/seen_cves.json` is the single source
  of truth: no database, no external storage.
- It is idempotent. If the workflow runs twice on the same day, the second pass
  finds no differences and produces no commit.
- The first run only sets the baseline, so the first digest isn't flooded with
  the ~1,700 CVEs that were already in the catalog.

## Structure

```
scripts/digest.py     Toda la lógica: descarga, diff y escritura
data/seen_cves.json   Última foto conocida del catálogo (estado)
digest/               Un archivo Markdown por día con los cambios
.github/workflows/
  digest.yml          Cron diario + commit automático
  dependabot-auto-merge.yml
```

## What goes into each digest

Every new entry is recorded with what you need to decide whether to act:

- The CVE, linked to its NVD entry
- Affected vendor and product
- Name of the vulnerability
- Date it entered the catalog, and the remediation deadline set by CISA
- A short description
- A highlighted notice if there is known use in ransomware campaigns

## Running it locally

Nothing to install:

```bash
git clone https://github.com/eduolihez/kev-digest.git
cd kev-digest
python scripts/digest.py
```

It writes today's digest into `digest/` and updates `data/seen_cves.json`. To
test from scratch with no previous baseline, delete the state file before
running it (`rm data/seen_cves.json`): the script will detect that this is the
first run and only set the reference point.

## About the data

The data comes from the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
published by the US *Cybersecurity and Infrastructure Security Agency* as a
federal government work in the public domain. This repository is not affiliated
with CISA, nor endorsed by it.

The files in `digest/` are a derived, automated view. For operational
decisions, always check the original catalog, which is the authoritative
source.

## License

[MIT](LICENSE) for this repository's code. The KEV catalog data is public
domain, as noted above.
