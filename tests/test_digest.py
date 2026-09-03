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
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_SRC = Path(__file__).resolve().parent.parent


def cargar_digest(repo: Path):
    """Importa el digest.py de una copia del repo, apuntando a sus rutas.

    `enrich` y `publish` se importan por nombre, así que hay que sacarlos de
    sys.modules entre pruebas: si no, la segunda prueba se quedaría con los
    módulos de la copia temporal de la primera y escribiría en el directorio
    equivocado.
    """
    for nombre in ("enrich", "publish"):
        sys.modules.pop(nombre, None)
    sys.path.insert(0, str(repo / "scripts"))
    try:
        spec = importlib.util.spec_from_file_location(
            f"digest_{repo.parent.name}", repo / "scripts" / "digest.py"
        )
        modulo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(modulo)
        return modulo
    finally:
        sys.path.remove(str(repo / "scripts"))


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
        # Ninguna prueba toca la red: el enriquecimiento se pide siempre en
        # modo cacheado, y la caché de la copia temporal está vacía.
        os.environ.pop("KEV_WATCHLIST", None)
        self.d = cargar_digest(self.repo)
        self.d.enrich_mod.enrich = lambda cves, network=True, limite_nvd=20: {}
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.addCleanup(os.environ.pop, "KEV_WATCHLIST", None)

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
        self.assertEqual(self.estado["schema"], self.d.SCHEMA)
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


class TestWatchlist(DigestTestCase):
    def setUp(self):
        super().setUp()
        self.estado_v1([e["cveID"] for e in GRANDE])
        self.correr(catalogo(GRANDE))

    def usar_watchlist(self, datos):
        os.environ["KEV_WATCHLIST"] = json.dumps(datos)

    def test_marca_las_cve_del_inventario(self):
        self.usar_watchlist({"vendors": ["fortinet"], "products": [], "cves": []})
        nuevo = GRANDE + [
            entrada("CVE-2000-0001", vendor="Fortinet", product="FortiOS", added="2026-09-03"),
            entrada("CVE-2000-0002", vendor="Otra", product="Cosa", added="2026-09-03"),
        ]
        self.correr(catalogo(nuevo), hora=(6, 0))
        texto = self.digest_hoy
        self.assertIn("Afecta a tu inventario", texto)
        # La seccion destacada lista la del inventario y no la otra.
        destacado = texto.split("Afecta a tu inventario")[1].split("###")[0]
        self.assertIn("CVE-2000-0001", destacado)
        self.assertNotIn("CVE-2000-0002", destacado)

    def test_coincide_por_subcadena_y_sin_distinguir_mayusculas(self):
        self.usar_watchlist({"vendors": ["FORTINET"], "products": [], "cves": []})
        nuevo = GRANDE + [
            entrada("CVE-2000-0001", vendor="Fortinet Inc.", product="FortiOS", added="2026-09-03")
        ]
        self.correr(catalogo(nuevo), hora=(6, 0))
        self.assertIn("Afecta a tu inventario", self.digest_hoy)

    def test_watchlist_por_cve_concreta(self):
        self.usar_watchlist({"vendors": [], "products": [], "cves": ["CVE-2000-0001"]})
        nuevo = GRANDE + [entrada("CVE-2000-0001", added="2026-09-03")]
        self.correr(catalogo(nuevo), hora=(6, 0))
        self.assertIn("Afecta a tu inventario", self.digest_hoy)

    def test_sin_watchlist_no_hay_seccion(self):
        nuevo = GRANDE + [entrada("CVE-2000-0001", added="2026-09-03")]
        self.correr(catalogo(nuevo), hora=(6, 0))
        self.assertNotIn("Afecta a tu inventario", self.digest_hoy)

    def test_watchlist_invalida_no_rompe_la_ejecucion(self):
        os.environ["KEV_WATCHLIST"] = "{esto no es json"
        nuevo = GRANDE + [entrada("CVE-2000-0001", added="2026-09-03")]
        self.assertEqual(self.correr(catalogo(nuevo), hora=(6, 0)), 0)
        self.assertIn("CVE-2000-0001", self.digest_hoy)


class TestPlazos(DigestTestCase):
    def setUp(self):
        super().setUp()
        self.estado_v1([e["cveID"] for e in GRANDE])
        self.correr(catalogo(GRANDE))

    def test_avisa_de_plazos_que_vencen_pronto(self):
        # Hoy congelado en 2026-09-03; vence en 3 días.
        pronto = [entrada("CVE-1000-0001", due="2026-09-06")] + GRANDE[1:]
        self.correr(catalogo(pronto), hora=(6, 0))
        texto = self.digest_hoy
        self.assertIn("Plazos de CISA que vencen", texto)
        self.assertIn("CVE-1000-0001", texto)
        self.assertIn("en 3 días", texto)

    def test_no_repite_el_mismo_aviso_de_plazo(self):
        """Con 8 pasadas al día, avisar cada vez del mismo plazo sería insufrible."""
        pronto = [entrada("CVE-1000-0001", due="2026-09-06")] + GRANDE[1:]
        self.correr(catalogo(pronto), hora=(6, 0))
        antes = self.digest_hoy
        self.correr(catalogo(pronto), hora=(9, 0))
        self.assertEqual(self.digest_hoy, antes, "el aviso de plazo se repitió")

    def test_plazo_ya_vencido_no_avisa(self):
        vencido = [entrada("CVE-1000-0001", due="2026-08-01")] + GRANDE[1:]
        self.correr(catalogo(vencido), hora=(6, 0))
        self.assertNotIn("Plazos de CISA que vencen", self.digest_hoy)

    def test_plazo_lejano_no_avisa(self):
        lejano = [entrada("CVE-1000-0001", due="2026-12-01")] + GRANDE[1:]
        self.correr(catalogo(lejano), hora=(6, 0))
        self.assertNotIn("Plazos de CISA que vencen", self.digest_hoy)


class TestLatestJson(DigestTestCase):
    """latest.json es contrato con la pagina KEV Watch del Blue Team Hub."""

    def setUp(self):
        super().setUp()
        self.estado_v1([e["cveID"] for e in GRANDE])
        self.correr(catalogo(GRANDE))

    @property
    def latest(self):
        return json.loads((self.repo / "data" / "latest.json").read_text(encoding="utf-8"))

    def test_lleva_los_campos_que_consume_el_hub(self):
        d = self.latest
        for campo in ("lastUpdated", "totalTracked", "newToday", "recentAdditions"):
            self.assertIn(campo, d, f"el Hub dejaria de funcionar sin {campo}")
        self.assertIsInstance(d["recentAdditions"], list)

    def test_forma_de_cada_entrada_reciente(self):
        reciente = [entrada("CVE-2000-0001", added="2026-09-02")] + GRANDE
        self.correr(catalogo(reciente), hora=(6, 0))
        fila = next(e for e in self.latest["recentAdditions"] if e["cveID"] == "CVE-2000-0001")
        for campo in ("cveID", "vendorProject", "product", "vulnerabilityName",
                      "dateAdded", "dueDate", "shortDescription", "knownRansomware"):
            self.assertIn(campo, fila)
        self.assertIsInstance(fila["knownRansomware"], bool)

    def test_solo_incluye_altas_dentro_de_la_ventana(self):
        viejo = entrada("CVE-1900-0001", added="2020-01-01")
        self.correr(catalogo(GRANDE + [viejo]), hora=(6, 0))
        ids = [e["cveID"] for e in self.latest["recentAdditions"]]
        self.assertNotIn("CVE-1900-0001", ids)

    def test_no_cambia_entre_pasadas_sin_novedades(self):
        """Si generatedAt llevara la hora de cada pasada, commitearia 8 veces al dia."""
        reciente = GRANDE + [entrada("CVE-2000-0001", added="2026-09-03")]
        self.correr(catalogo(reciente), hora=(6, 0))
        antes = (self.repo / "data" / "latest.json").read_text(encoding="utf-8")
        self.correr(catalogo(reciente), hora=(15, 0))
        self.assertEqual((self.repo / "data" / "latest.json").read_text(encoding="utf-8"), antes)


class TestHistorialYFeed(DigestTestCase):
    def setUp(self):
        super().setUp()
        self.estado_v1([e["cveID"] for e in GRANDE])
        self.correr(catalogo(GRANDE))

    def test_historial_registra_un_evento_por_linea(self):
        nuevo = GRANDE + [entrada("CVE-2000-0001", added="2026-09-03")]
        self.correr(catalogo(nuevo), hora=(6, 0))
        lineas = (self.repo / "data" / "history.jsonl").read_text(encoding="utf-8").strip().splitlines()
        eventos = [json.loads(l) for l in lineas]
        self.assertEqual(len(eventos), 1)
        self.assertEqual(eventos[0]["event"], "new")
        self.assertEqual(eventos[0]["cve"], "CVE-2000-0001")

    def test_historial_solo_anade(self):
        self.correr(catalogo(GRANDE + [entrada("CVE-2000-0001")]), hora=(6, 0))
        self.correr(catalogo(GRANDE + [entrada("CVE-2000-0001"), entrada("CVE-3000-0001")]), hora=(12, 0))
        lineas = (self.repo / "data" / "history.jsonl").read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lineas), 2)
        self.assertIn("CVE-2000-0001", lineas[0])

    def test_feed_es_xml_valido_y_lista_los_eventos(self):
        import xml.etree.ElementTree as ET
        self.correr(catalogo(GRANDE + [entrada("CVE-2000-0001", added="2026-09-03")]), hora=(6, 0))
        ruta = self.repo / "digest" / "feed.xml"
        self.assertTrue(ruta.exists())
        raiz = ET.fromstring(ruta.read_text(encoding="utf-8"))
        ns = "{http://www.w3.org/2005/Atom}"
        entradas = raiz.findall(f"{ns}entry")
        self.assertEqual(len(entradas), 1)
        self.assertIn("CVE-2000-0001", entradas[0].find(f"{ns}title").text)

    def test_feed_escapa_caracteres_especiales(self):
        """Un & o un < sin escapar en una descripcion de CISA romperia el XML."""
        import xml.etree.ElementTree as ET
        sucio = entrada("CVE-2000-0001", added="2026-09-03",
                        vendor="A & B", desc="Rompe con <script> y & suelto")
        self.correr(catalogo(GRANDE + [sucio]), hora=(6, 0))
        ET.fromstring((self.repo / "digest" / "feed.xml").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
