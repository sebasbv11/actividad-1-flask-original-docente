"""Laboratorio SAST: autenticacion deliberadamente vulnerable.

Este archivo existe solo para demostrar los casos 1 y 3 de la guia.
No debe reutilizarse en una aplicacion real.
"""

from __future__ import annotations

import sqlite3


# CASO 3 / CWE-798, CWE-259 y CWE-256: secretos incrustados en el codigo.
PASSWORD_ESTUDIANTE = "Manabi2026"
PASSWORD_DOCENTE = "Software6*"


def crear_base_vulnerable() -> sqlite3.Connection:
    """Crea una base temporal con credenciales sinteticas en texto claro."""
    conexion = sqlite3.connect(":memory:")
    conexion.execute(
        """
        CREATE TABLE usuarios (
            login TEXT PRIMARY KEY,
            clave TEXT NOT NULL,
            rol TEXT NOT NULL
        )
        """
    )

    # Las claves se almacenan ademas en texto claro dentro de la tabla.
    usuarios = [
        ("ana.estudiante", PASSWORD_ESTUDIANTE, "estudiante"),
        ("luis.docente", PASSWORD_DOCENTE, "docente"),
    ]
    conexion.executemany(
        "INSERT INTO usuarios(login, clave, rol) VALUES (?, ?, ?)",
        usuarios,
    )
    conexion.commit()
    return conexion


def autenticar_vulnerable(
    conexion: sqlite3.Connection,
    usuario: str,
    clave: str,
) -> str | None:
    """Autentica concatenando entradas externas: ejemplo intencionalmente inseguro."""
    cursor = conexion.cursor()

    # CASO 1 / CWE-89: los valores externos alteran la consulta SQL.
    consulta = (
        "SELECT rol FROM usuarios "
        "WHERE login='" + usuario + "' AND clave='" + clave + "'"
    )

    try:
        fila = cursor.execute(consulta).fetchone()
    except sqlite3.Error as error:
        # CWE-209: fuga adicional incluida para mostrar el efecto del error.
        print(f"[ERROR] Consulta={consulta}; detalle={error}")
        return None

    return fila[0] if fila else None


if __name__ == "__main__":
    base = crear_base_vulnerable()
    print(autenticar_vulnerable(base, "ana.estudiante", "Manabi2026"))
