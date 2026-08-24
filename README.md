# KEV Digest

Vigilancia diaria y automatizada del catálogo [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (Known Exploited Vulnerabilities) vía GitHub Actions (`.github/workflows/digest.yml`, cron diario).

Cada día el workflow descarga el catálogo, lo compara contra `data/seen_cves.json` (última foto conocida) y escribe un archivo en `digest/` con lo que ha cambiado. Sin intervención manual.

- **Última ejecución:** 2026-08-24
- **CVEs trackeados:** 1674
- **Nuevas hoy:** 0 (línea base inicial)
- **Último digest:** [`digest/2026-08-24.md`](digest/2026-08-24.md)

## Por qué

Registro personal de inteligencia de amenazas: entrar cada mañana a revisar qué vulnerabilidades explotadas activamente se han añadido al catálogo de CISA, sin tener que comprobarlo a mano.
