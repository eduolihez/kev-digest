# Política de seguridad

## Qué es y qué no es este repositorio

KEV Digest es una **herramienta de lectura**: descarga el catálogo público
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), lo
compara con la copia anterior y escribe archivos Markdown. No expone ningún
servicio, no recibe entradas de usuarios, no almacena credenciales y no
requiere secretos más allá del `GITHUB_TOKEN` que GitHub Actions inyecta
automáticamente en cada ejecución.

Los archivos de `digest/` son una vista derivada. **Para decisiones
operativas, la fuente autoritativa es siempre el catálogo original de CISA.**

## Reportar una vulnerabilidad

Si encuentras un problema de seguridad en este repositorio, ábrelo como
[Security Advisory privado](https://github.com/eduolihez/kev-digest/security/advisories/new)
en lugar de como issue pública.

Ejemplos de lo que interesa:

- Ejecución de código a través del contenido del catálogo descargado
- Un workflow que pueda ser manipulado para escribir fuera de este repositorio
- Escalada de privilegios mediante los permisos de GitHub Actions

Respondo en cuanto lo vea. Es un proyecto personal, así que no hay un
compromiso formal de plazos.

## Vulnerabilidades del propio catálogo KEV

Este repositorio **sólo refleja** el contenido de CISA. Si detectas un error
en los datos —una CVE mal clasificada, una fecha incorrecta— repórtalo a CISA
directamente en <central@cisa.dhs.gov>; aquí no se puede corregir.
