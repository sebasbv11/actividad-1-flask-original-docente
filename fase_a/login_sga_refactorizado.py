"""Version segura del laboratorio de autenticacion para la fase A."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from collections.abc import Iterable

import bcrypt


@dataclass
class LimitadorIntentos:
    """Control local sencillo para reducir intentos automatizados."""

    maximo: int = 5
    fallos: dict[str, int] = field(default_factory=dict)

    def bloqueado(self, usuario: str) -> bool:
        return self.fallos.get(usuario, 0) >= self.maximo

    def registrar_fallo(self, usuario: str) -> None:
        self.fallos[usuario] = self.fallos.get(usuario, 0) + 1

    def limpiar(self, usuario: str) -> None:
        self.fallos.pop(usuario, None)


def generar_hash(clave: str) -> str:
    """Genera un hash bcrypt con sal aleatoria y costo 12."""
    return bcrypt.hashpw(
        clave.encode("utf-8"),
        bcrypt.gensalt(rounds=12),
    ).decode("utf-8")


def crear_base_segura(
    usuarios: Iterable[tuple[str, str, str]],
) -> sqlite3.Connection:
    """Crea la base recibiendo las credenciales desde una fuente externa."""
    conexion = sqlite3.connect(":memory:")
    conexion.execute(
        """
        CREATE TABLE usuarios (
            login TEXT PRIMARY KEY,
            clave_hash TEXT NOT NULL,
            rol TEXT NOT NULL
        )
        """
    )
    usuarios_con_hash = [
        (login, generar_hash(clave), rol) for login, clave, rol in usuarios
    ]
    conexion.executemany(
        "INSERT INTO usuarios(login, clave_hash, rol) VALUES (?, ?, ?)",
        usuarios_con_hash,
    )
    conexion.commit()
    return conexion


def autenticar_seguro(
    conexion: sqlite3.Connection,
    usuario: str,
    clave: str,
    limitador: LimitadorIntentos | None = None,
) -> str | None:
    """Autentica con consulta parametrizada y verificacion bcrypt."""
    control = limitador or LimitadorIntentos()
    if control.bloqueado(usuario):
        return None

    # La estructura SQL y los datos viajan separados.
    fila = conexion.execute(
        "SELECT clave_hash, rol FROM usuarios WHERE login = ?",
        (usuario,),
    ).fetchone()

    credencial_valida = bool(
        fila
        and bcrypt.checkpw(
            clave.encode("utf-8"),
            fila[0].encode("utf-8"),
        )
    )
    if not credencial_valida:
        control.registrar_fallo(usuario)
        return None

    control.limpiar(usuario)
    return fila[1]
