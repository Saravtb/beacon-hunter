"""Gravação das detecções em banco de dados.

--db beacons.db                     -> SQLite (padrão, não precisa instalar nada)
--db mysql://127.0.0.1:3306/banco   -> MySQL (pip install mysql-connector-python)

Credenciais do MySQL nunca vão na URL nem no código: vêm das variáveis de
ambiente MYSQL_USER e MYSQL_PASSWORD ou são pedidas no terminal.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from getpass import getpass
from typing import Optional
from urllib.parse import urlparse

from .detector import Event

COLUMNS = (
    "detected_at, src_ip, src_port, dst_ip, dst_port, sequence, "
    "interval_s, mean_s, stdev_s, cv, periodic, payload_bytes, cleartext, payload"
)

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    detected_at    TEXT    NOT NULL,
    src_ip         TEXT    NOT NULL,
    src_port       INTEGER NOT NULL,
    dst_ip         TEXT    NOT NULL,
    dst_port       INTEGER NOT NULL,
    sequence       INTEGER NOT NULL,
    interval_s     REAL,
    mean_s         REAL,
    stdev_s        REAL,
    cv             REAL,
    periodic       INTEGER NOT NULL DEFAULT 0,
    payload_bytes  INTEGER NOT NULL DEFAULT 0,
    cleartext      INTEGER,
    payload        TEXT
);
"""

MYSQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    detected_at    DATETIME(3)  NOT NULL,
    src_ip         VARCHAR(45)  NOT NULL,
    src_port       INT          NOT NULL,
    dst_ip         VARCHAR(45)  NOT NULL,
    dst_port       INT          NOT NULL,
    sequence       INT          NOT NULL,
    interval_s     DOUBLE,
    mean_s         DOUBLE,
    stdev_s        DOUBLE,
    cv             DOUBLE,
    periodic       TINYINT(1)   NOT NULL DEFAULT 0,
    payload_bytes  INT          NOT NULL DEFAULT 0,
    cleartext      TINYINT(1),
    payload        TEXT
)
"""


def _ask(prompt: str) -> str:
    print(prompt, end="", file=sys.stderr, flush=True)
    return sys.stdin.readline().strip()


class Storage:
    """Interface comum: abre o banco, grava cada evento e atualiza o payload."""

    def save(self, event: Event) -> None:
        raise NotImplementedError

    def update_payload(self, event: Event) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass

    @staticmethod
    def _row(event: Event) -> tuple:
        clear = event.cleartext
        return (
            event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            event.src_ip,
            event.src_port,
            event.dst_ip,
            event.dst_port,
            event.sequence,
            event.interval,
            event.mean,
            event.stdev,
            event.cv,
            int(event.periodic),
            len(event.payload),
            None if clear is None else int(clear),
            event.payload_text if clear else None,
        )


class SQLiteStorage(Storage):
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SQLITE_SCHEMA)
        self._ids = {}
        self.label = f"SQLite ({path})"

    def save(self, event: Event) -> None:
        marks = ", ".join("?" * 14)
        cur = self.conn.execute(f"INSERT INTO detections ({COLUMNS}) VALUES ({marks})", self._row(event))
        self._ids[id(event)] = cur.lastrowid
        self.conn.commit()

    def update_payload(self, event: Event) -> None:
        row_id = self._ids.get(id(event))
        if row_id is None:
            return
        row = self._row(event)
        self.conn.execute(
            "UPDATE detections SET payload_bytes = ?, cleartext = ?, payload = ? WHERE id = ?",
            (row[11], row[12], row[13], row_id),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


class MySQLStorage(Storage):
    def __init__(self, host: str, port: int, database: str):
        try:
            import mysql.connector
        except ImportError as exc:
            raise SystemExit("MySQL requer: pip install mysql-connector-python") from exc

        user = os.environ.get("MYSQL_USER") or _ask("Usuário do MySQL: ")
        password = os.environ.get("MYSQL_PASSWORD") or getpass("Senha do MySQL (não aparece na tela): ")
        self.conn = mysql.connector.connect(host=host, port=port, user=user, password=password, database=database)
        cur = self.conn.cursor()
        cur.execute(MYSQL_SCHEMA)
        cur.close()
        self._ids = {}
        self.label = f"MySQL ({host}:{port}/{database})"

    def save(self, event: Event) -> None:
        marks = ", ".join(["%s"] * 14)
        cur = self.conn.cursor()
        cur.execute(f"INSERT INTO detections ({COLUMNS}) VALUES ({marks})", self._row(event))
        self._ids[id(event)] = cur.lastrowid
        self.conn.commit()
        cur.close()

    def update_payload(self, event: Event) -> None:
        row_id = self._ids.get(id(event))
        if row_id is None:
            return
        row = self._row(event)
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE detections SET payload_bytes = %s, cleartext = %s, payload = %s WHERE id = %s",
            (row[11], row[12], row[13], row_id),
        )
        self.conn.commit()
        cur.close()

    def close(self) -> None:
        self.conn.close()


def open_storage(target: Optional[str]) -> Optional[Storage]:
    if not target:
        return None
    if target.startswith("mysql://"):
        url = urlparse(target)
        if url.username or url.password:
            raise SystemExit(
                "Não coloque usuário ou senha na URL. Use MYSQL_USER e MYSQL_PASSWORD "
                "ou deixe o beacon-hunter perguntar no terminal."
            )
        database = url.path.lstrip("/")
        if not database:
            raise SystemExit("Informe o banco na URL, por exemplo mysql://127.0.0.1:3306/seguranca_lab")
        return MySQLStorage(url.hostname or "127.0.0.1", url.port or 3306, database)
    return SQLiteStorage(target)
