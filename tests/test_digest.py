#!/usr/bin/env python3
"""Pruebas de scripts/digest.py, sin dependencias: solo unittest.

Cada prueba trabaja sobre una copia temporal del repositorio y con un catálogo
inventado, así que nunca toca `data/`, `digest/` ni la red. Ejecutar con:

    python -m unittest discover -s tests
"""
from __future__ import annotations

import datetime
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_SRC = Path(__file__).resolve().parent.parent


def cargar_digest(repo: Path):
    """Importa el digest.py de una copia del repo, apuntando a sus rutas."""
    spec = importlib.util.spec_from_file_location(
        f"digest_{repo.name}", repo / "scripts" / "digest.py"
    )
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def entrada(cve, *, vendor="Acme", product="Widget", added="2026-09-01",
            due="2026-09-15", ransom="Unknown", desc="Descripción base",
            action="Aplicar el parche"):
    return {
        "cveID": cve, "vendorProject": vendor, "product": product,
        "vulnerabilityName": f"{product} RCE", "dateAdded": added, "dueDate": due,
        "knownRansomwareCampaignUse": ransom, "shortDescription": desc,
        "requiredAction": action,
    }


def catalogo(entradas, version="2026.09.03"):
    return {
        "catalogVersion": version, "dateReleased": "2026-09-03T13:00:00.0000Z",
        "count": len(entradas), "vulnerabilities": entradas,
    }


BASE = [entrada("CVE-1000-0001"), entrada("CVE-1000-0002"), entrada("CVE-1000-0003")]
# Relleno para que quitar una entrada quede por debajo del guardia de encogimiento,
# como pasa en el catalogo real (1 de ~1.700 es un 0,06%).
RELLENO = [entrada(f"CVE-9000-{i:04d}") for i in range(20)]
GRANDE = BASE + RELLENO


class DigestTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="kev-test-"))
        self.repo = self.tmp / "repo"
        shutil.copytree(
            REPO_SRC, self.repo,
            ignore=shutil.ignore_patterns(".git", "digest", "data", "__pycache__"),
        )
        (self.repo / "digest").mkdir(exist_ok=True)
        (self.repo / "data").mkdir(exist_ok=True)
        self.d = cargar_digest(self.repo)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def estado_v1(self, ids):
        """Deja el archivo de estado en el formato antiguo: lista plana de IDs."""
        (self.repo / "data" / "seen_cves.json").write_text(
            json.dumps(sorted(ids)), encoding="utf-8"
        )

    def correr(self, cat, hora=(6, 0), argv=()):
        self.d.fetch_kev = lambda attempts=3, _c=cat: _c
        real = datetime.datetime

        class Congelado(real):
            @classmethod
            def now(cls, tz=None):
                return real(2026, 9, 3, *hora, tzinfo=tz)

        self.d.datetime.datetime = Congelado
        argv_previo = sys.argv
        sys.argv = ["digest.py", *argv]
        try:
            return self.d.main()
        finally:
            sys.argv = argv_previo
            self.d.datetime.datetime = real

    @property
    def digest_hoy(self):
        ruta = self.repo / "digest" / "2026-09-03.md"
        return ruta.read_text(encoding="utf-8") if ruta.exists() else ""

    @property
    def estado(self):
        return json.loads((self.repo / "data" / "seen_cves.json").read_text(encoding="utf-8"))


class TestMigracion(DigestTestCase):
    def test_estado_v1_migra_sin_inventar_modificaciones(self):
        """El formato viejo no guarda los campos, solo los IDs.

        Al migrar no hay foto anterior con la que comparar, así que las 1.694
        entradas existentes no deben salir como "modificadas".
        """
        self.estado_v1([e["cveID"] for e in BASE])
        self.assertEqual(self.correr(catalogo(BASE)), 0)
        self.assertEqual(self.estado["schema"], 2)
        self.assertEqual(self.digest_hoy, "", "la migración no debe generar digest")

    def test_primera_ejecucion_fija_linea_base(self):
        self.assertEqual(self.correr(catalogo(BASE)), 0)
        self.assertIn("línea base", self.digest_hoy)
        self.assertNotIn("CVE-1000-0001", self.digest_hoy)


class TestVariasPasadasAlDia(DigestTestCase):
    def setUp(self):
        super().setUp()
        self.estado_v1([e["cveID"] for e in BASE])
        self.correr(catalogo(BASE))  # migración

    def test_la_segunda_pasada_no_borra_la_primera(self):
        """La razón de ser de la versión 2: correr 8 veces al día es seguro.

        La versión anterior reescribía el archivo del día entero, así que la
        pasada de la tarde habría borrado los hallazgos de la mañana.
        """
        manana = BASE + [entrada("CVE-2000-0001", added="2026-09-03")]
        self.correr(catalogo(manana), hora=(6, 0))
        self.assertIn("CVE-2000-0001", self.digest_hoy)

        tarde = manana + [entrada("CVE-3000-0001", added="2026-09-03")]
        self.correr(catalogo(tarde), hora=(18, 0))

        texto = self.digest_hoy
        self.assertIn("CVE-2000-0001", texto, "se perdió lo que encontró la pasada de la mañana")
        self.assertIn("CVE-3000-0001", texto)
        self.assertIn("## 06:00 UTC", texto)
        self.assertIn("## 18:00 UTC", texto)

    def test_pasada_sin_novedades_no_escribe_nada(self):
        """Con 8 pasadas diarias, escribir siempre llenaría el log de commits vacíos."""
        self.correr(catalogo(BASE + [entrada("CVE-2000-0001")]), hora=(6, 0))
        digest_antes, estado_antes = self.digest_hoy, self.estado
        self.correr(catalogo(BASE + [entrada("CVE-2000-0001")]), hora=(9, 0))
        self.assertEqual(self.digest_hoy, digest_antes)
        self.assertEqual(self.estado, estado_antes)


class TestDeteccionDeCambios(DigestTestCase):
    def setUp(self):
        super().setUp()
        self.estado_v1([e["cveID"] for e in GRANDE])
        self.correr(catalogo(GRANDE))
        # Una pasada más para tener foto completa de los campos de todas.
        self.correr(catalogo(GRANDE + [entrada("CVE-2000-0001")]), hora=(6, 0))

    def test_detecta_flip_a_ransomware(self):
        catalogo_nuevo = [
            entrada("CVE-1000-0001"),
            entrada("CVE-1000-0002", ransom="Known"),
            entrada("CVE-1000-0003"),
            entrada("CVE-2000-0001"),
        ] + RELLENO
        self.correr(catalogo(catalogo_nuevo), hora=(12, 0))
        texto = self.digest_hoy
        self.assertIn("Entradas modificadas", texto)
        self.assertIn("CVE-1000-0002", texto)
        self.assertIn("uso en ransomware", texto)
        self.assertIn("Known", texto)

    def test_detecta_cambio_de_plazo(self):
        catalogo_nuevo = [
            entrada("CVE-1000-0001", due="2026-10-01"),
            entrada("CVE-1000-0002"), entrada("CVE-1000-0003"), entrada("CVE-2000-0001"),
        ] + RELLENO
        self.correr(catalogo(catalogo_nuevo), hora=(12, 0))
        self.assertIn("plazo de mitigación: 2026-09-15 → 2026-10-01", self.digest_hoy)

    def test_detecta_descripcion_actualizada_sin_guardar_la_prosa(self):
        catalogo_nuevo = [
            entrada("CVE-1000-0001", desc="Texto corregido por CISA"),
            entrada("CVE-1000-0002"), entrada("CVE-1000-0003"), entrada("CVE-2000-0001"),
        ] + RELLENO
        self.correr(catalogo(catalogo_nuevo), hora=(12, 0))
        self.assertIn("descripción: actualizada", self.digest_hoy)
        # De los campos largos solo se guarda la huella, no el texto.
        guardado = self.estado["entries"]["CVE-1000-0001"]
        self.assertIn("shortDescription#", guardado)
        self.assertNotIn("shortDescription", guardado)

    def test_detecta_entradas_retiradas(self):
        self.correr(catalogo(GRANDE), hora=(12, 0))  # se cae CVE-2000-0001
        self.assertIn("Entradas retiradas", self.digest_hoy)
        self.assertIn("CVE-2000-0001", self.digest_hoy)


class TestProteccionDelEstado(DigestTestCase):
    def setUp(self):
        super().setUp()
        self.estado_v1([e["cveID"] for e in BASE])
        self.correr(catalogo(BASE))

    def test_catalogo_truncado_no_machaca_el_estado(self):
        """Una descarga a medias no puede cargarse la línea base.

        Sin este guardia, un CDN devolviendo 3 entradas de 1.694 marcaría 1.691
        como retiradas y guardaría esa foto como buena.
        """
        estado_antes = self.estado
        self.assertEqual(self.correr(catalogo(BASE[:1]), hora=(12, 0)), 1)
        self.assertEqual(self.estado, estado_antes)

    def test_force_permite_un_encogimiento_real(self):
        self.assertEqual(self.correr(catalogo(BASE[:1]), hora=(12, 0), argv=["--force"]), 0)

    def test_catalogo_vacio_se_rechaza(self):
        estado_antes = self.estado
        self.assertEqual(self.correr(catalogo([]), hora=(12, 0)), 1)
        self.assertEqual(self.estado, estado_antes)

    def test_entradas_sin_cveid_se_ignoran(self):
        sucio = BASE + [{"vendorProject": "Roto", "product": "Sin ID"}]
        self.assertEqual(self.correr(catalogo(sucio), hora=(12, 0)), 0)
        self.assertEqual(self.estado["count"], len(BASE))


class TestSerializacionDelEstado(DigestTestCase):
    def test_una_linea_por_cve_y_json_valido(self):
        """El estado se escribe a mano para que el diff sea legible.

        Una línea por CVE significa que cambiar una entrada cambia una línea,
        en vez de las nueve que salían con indentación completa. Sigue teniendo
        que ser JSON válido, que es lo que puede romper al serializar a mano.
        """
        self.estado_v1([e["cveID"] for e in GRANDE])
        self.correr(catalogo(GRANDE))
        texto = (self.repo / "data" / "seen_cves.json").read_text(encoding="utf-8")
        json.loads(texto)  # revienta si la serialización manual produce JSON roto
        lineas_cve = [ln for ln in texto.splitlines() if ln.startswith('  "CVE-')]
        self.assertEqual(len(lineas_cve), len(GRANDE))

    def test_cambiar_una_entrada_cambia_una_sola_linea(self):
        self.estado_v1([e["cveID"] for e in GRANDE])
        self.correr(catalogo(GRANDE))
        antes = (self.repo / "data" / "seen_cves.json").read_text(encoding="utf-8").splitlines()
        modificado = [entrada("CVE-1000-0001", due="2026-12-31")] + GRANDE[1:]
        self.correr(catalogo(modificado), hora=(12, 0))
        despues = (self.repo / "data" / "seen_cves.json").read_text(encoding="utf-8").splitlines()
        distintas = [a for a, b in zip(antes, despues) if a != b]
        # Solo la línea de esa CVE y las de cabecera (last_change, versión...).
        self.assertLessEqual(len(distintas), 4, f"demasiadas líneas movidas: {distintas}")


class TestDryRun(DigestTestCase):
    def test_dry_run_no_toca_disco(self):
        self.estado_v1([e["cveID"] for e in BASE])
        antes = (self.repo / "data" / "seen_cves.json").read_text(encoding="utf-8")
        rc = self.correr(catalogo(BASE + [entrada("CVE-2000-0001")]), argv=["--dry-run"])
        self.assertEqual(rc, 0)
        self.assertEqual((self.repo / "data" / "seen_cves.json").read_text(encoding="utf-8"), antes)
        self.assertEqual(self.digest_hoy, "")


class TestBloqueReadme(DigestTestCase):
    def test_solo_reescribe_entre_marcadores(self):
        readme = self.repo / "README.md"
        readme.write_text(
            "# Mi README\n\nTexto escrito a mano que no se debe perder.\n\n"
            f"{self.d.STATS_START}\nviejo\n{self.d.STATS_END}\n\nMás texto a mano.\n",
            encoding="utf-8",
        )
        self.estado_v1([e["cveID"] for e in BASE])
        self.correr(catalogo(BASE + [entrada("CVE-2000-0001")]))
        texto = readme.read_text(encoding="utf-8")
        self.assertIn("Texto escrito a mano que no se debe perder.", texto)
        self.assertIn("Más texto a mano.", texto)
        self.assertNotIn("viejo", texto)
        self.assertIn("CVEs en seguimiento", texto)

    def test_sin_marcadores_no_se_toca_el_archivo(self):
        readme = self.repo / "README.md"
        readme.write_text("# README sin marcadores\n", encoding="utf-8")
        self.estado_v1([e["cveID"] for e in BASE])
        self.correr(catalogo(BASE + [entrada("CVE-2000-0001")]))
        self.assertEqual(readme.read_text(encoding="utf-8"), "# README sin marcadores\n")


if __name__ == "__main__":
    unittest.main()
