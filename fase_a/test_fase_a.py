"""Pruebas comparativas reproducibles de la fase A."""

import unittest

from login_sga_refactorizado import (
    LimitadorIntentos,
    autenticar_seguro,
    crear_base_segura,
)
from login_sga_vulnerable import autenticar_vulnerable, crear_base_vulnerable


USUARIOS_PRUEBA = [
    ("ana.estudiante", "Manabi2026", "estudiante"),
    ("luis.docente", "Software6*", "docente"),
]


def crear_base_segura_de_prueba():
    return crear_base_segura(USUARIOS_PRUEBA)


class FaseATest(unittest.TestCase):
    def test_credenciales_correctas_funcionan_en_ambas_versiones(self) -> None:
        self.assertEqual(
            autenticar_vulnerable(
                crear_base_vulnerable(),
                "ana.estudiante",
                "Manabi2026",
            ),
            "estudiante",
        )
        self.assertEqual(
            autenticar_seguro(
                crear_base_segura_de_prueba(),
                "ana.estudiante",
                "Manabi2026",
            ),
            "estudiante",
        )

    def test_inyeccion_funciona_antes_y_falla_despues(self) -> None:
        carga = "' OR '1'='1' --"
        self.assertEqual(
            autenticar_vulnerable(crear_base_vulnerable(), carga, "x"),
            "estudiante",
        )
        self.assertIsNone(
            autenticar_seguro(crear_base_segura_de_prueba(), carga, "x")
        )

    def test_la_base_segura_no_guarda_la_clave_en_texto_claro(self) -> None:
        fila = crear_base_segura_de_prueba().execute(
            "SELECT clave_hash FROM usuarios WHERE login = ?",
            ("ana.estudiante",),
        ).fetchone()
        self.assertIsNotNone(fila)
        self.assertNotEqual(fila[0], "Manabi2026")
        self.assertTrue(fila[0].startswith("$2"))

    def test_el_limitador_bloquea_despues_de_cinco_fallos(self) -> None:
        base = crear_base_segura_de_prueba()
        control = LimitadorIntentos()
        for _ in range(5):
            self.assertIsNone(
                autenticar_seguro(base, "ana.estudiante", "incorrecta", control)
            )
        self.assertTrue(control.bloqueado("ana.estudiante"))
        self.assertIsNone(
            autenticar_seguro(base, "ana.estudiante", "Manabi2026", control)
        )


if __name__ == "__main__":
    unittest.main()
