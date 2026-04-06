#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Migración SQLite (moviles.db) -> SQL Server (SQL_DATABASE_NAME)
- Inserta/actualiza dbo.lineas y dbo.asignaciones (y opcionalmente dbo.usuarios / dbo.auditoria si existen en SQLite).
- Resistente a diferencias de nombres de columnas: intenta autodetectar.
- No borra nada.
- Re-ejecutable (upsert): NO machaca valores existentes con NULL.

Uso (PowerShell):
  py -m pip install pyodbc
  py migrar_moviles_sqlite_a_sqlserver.py --sqlite "C:\\ruta\\moviles.db" --server "SQL_SERVER_HOST" --database "SQL_DATABASE_NAME" --user "SQL_USER"
  # pedirá password por consola

Notas:
- Ejecuta con la app cerrada para que moviles.db no esté bloqueado.
- Requiere ODBC Driver 17/18 + pyodbc.
"""

from __future__ import annotations

import argparse
import getpass
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import pyodbc


# -----------------------------
# Utilidades
# -----------------------------
def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def norm_txt(x: Any) -> Optional[str]:
    if x is None:
        return None
    s = str(x).strip()
    return s if s else None


def normalize_phone(raw: Any) -> Optional[str]:
    """
    Normaliza un 'numero' para que sea estable:
    - mantiene '+' inicial si existe
    - elimina espacios, guiones, paréntesis, puntos
    - deja solo dígitos y '+' inicial
    """
    s = norm_txt(raw)
    if not s:
        return None
    s = s.replace(" ", "").replace("-", "").replace("(", "").replace(")", "").replace(".", "")
    if s.startswith("00"):
        s = "+" + s[2:]
    if s.startswith("+"):
        digits = re.sub(r"\D", "", s[1:])
        return ("+" + digits) if digits else None
    digits = re.sub(r"\D", "", s)
    return digits if digits else None


def to_bit(x: Any) -> int:
    if x in (True, 1, "1", "true", "True", "TRUE", "yes", "Y", "y", "si", "SI"):
        return 1
    return 0


def parse_dt_utc(x: Any) -> Optional[datetime]:
    """
    Intenta parsear timestamps que vengan de SQLite:
    - ISO 8601
    - 'YYYY-MM-DD HH:MM:SS'
    Devuelve datetime con tz UTC.
    """
    s = norm_txt(x)
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        return None


def ci_map(keys: Iterable[str]) -> Dict[str, str]:
    """mapa case-insensitive: lower->original"""
    out: Dict[str, str] = {}
    for k in keys:
        out[k.lower()] = k
    return out


def pick_col(cols_ci: Dict[str, str], candidates: Sequence[str]) -> Optional[str]:
    for c in candidates:
        k = c.lower()
        if k in cols_ci:
            return cols_ci[k]
    return None


def sqlite_table_names(conn: sqlite3.Connection) -> List[str]:
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;")
    return [r[0] for r in cur.fetchall()]


def sqlite_table_cols(conn: sqlite3.Connection, table: str) -> List[str]:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table});")
    return [r[1] for r in cur.fetchall()]


def sqlite_fetch_all(conn: sqlite3.Connection, table: str) -> Tuple[List[str], List[Tuple[Any, ...]]]:
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {table};")
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]
    return cols, rows


# -----------------------------
# Detección de tablas origen
# -----------------------------
@dataclass(frozen=True)
class SourceTable:
    name: str
    cols: List[str]


def find_best_table(conn: sqlite3.Connection, kind: str) -> Optional[SourceTable]:
    """
    kind: 'lineas' | 'asignaciones' | 'usuarios' | 'auditoria'
    Selecciona la tabla más probable por:
    - nombre (heurística)
    - presencia de columna 'numero' o equivalente
    """
    names = sqlite_table_names(conn)
    candidates: List[SourceTable] = []
    for t in names:
        cols = sqlite_table_cols(conn, t)
        candidates.append(SourceTable(t, cols))

    def score(st: SourceTable) -> int:
        n = st.name.lower()
        cols_ci = ci_map(st.cols)
        s = 0
        if kind == "lineas":
            if any(x in n for x in ("linea", "pinpuk", "puk", "sim", "numer", "telefono", "msisdn")):
                s += 10
            if pick_col(cols_ci, ("numero", "msisdn", "telefono", "tel", "linea", "phone")):
                s += 20
            if any(c.lower() in cols_ci for c in ("pin1", "puk1", "iccid", "sim")):
                s += 5
        elif kind == "asignaciones":
            if any(x in n for x in ("asign", "device", "emple", "usuario", "movil")):
                s += 10
            if pick_col(cols_ci, ("numero", "msisdn", "telefono", "tel", "linea", "phone")):
                s += 20
            if any(c.lower() in cols_ci for c in ("empleado", "nombre", "email", "grupo", "responsable")):
                s += 5
        elif kind == "usuarios":
            if any(x in n for x in ("user", "usuario", "usuarios", "login")):
                s += 10
            if pick_col(cols_ci, ("username", "user", "usuario", "login")):
                s += 20
            if any(c.lower() in cols_ci for c in ("password_hash", "hash", "salt", "iterations", "role")):
                s += 5
        elif kind == "auditoria":
            if any(x in n for x in ("audit", "auditoria", "log", "hist")):
                s += 10
            if any(c.lower() in cols_ci for c in ("tabla", "accion", "usuario", "fecha")):
                s += 10
        return s

    ranked = sorted(candidates, key=score, reverse=True)
    best = ranked[0] if ranked else None
    if best and score(best) >= 20:
        return best
    return None


# -----------------------------
# Conexión SQL Server
# -----------------------------
def detect_driver(preferred: Optional[str] = None) -> str:
    drivers = set(pyodbc.drivers())
    if preferred and preferred in drivers:
        return preferred
    if "ODBC Driver 18 for SQL Server" in drivers:
        return "ODBC Driver 18 for SQL Server"
    if "ODBC Driver 17 for SQL Server" in drivers:
        return "ODBC Driver 17 for SQL Server"
    raise RuntimeError("No se detecta ODBC Driver 17/18 for SQL Server en el equipo.")


def sql_connect(server: str, database: str, user: str, password: str, driver: str, encrypt: str) -> pyodbc.Connection:
    encrypt = (encrypt or "no").lower()
    if encrypt not in ("yes", "no"):
        encrypt = "no"

    conn_str = (
        f"DRIVER={{{driver}}};"
        f"SERVER={server};"
        f"DATABASE={database};"
        f"User ID={user};"
        f"Password={password};"
        f"Encrypt={encrypt};"
        "TrustServerCertificate=yes;"
        "Connection Timeout=30;"
    )
    return pyodbc.connect(conn_str, autocommit=False)


# -----------------------------
# Migración: lineas
# -----------------------------
def build_lineas_rows(src_cols: List[str], src_rows: List[Tuple[Any, ...]]) -> List[Dict[str, Any]]:
    cols_ci = ci_map(src_cols)

    c_numero = pick_col(cols_ci, ("numero", "msisdn", "telefono", "tel", "linea", "phone"))
    if not c_numero:
        raise RuntimeError("No se detecta columna de número en la tabla origen de líneas.")

    c_sim  = pick_col(cols_ci, ("sim", "iccid", "sim_iccid"))
    c_pin1 = pick_col(cols_ci, ("pin1", "pin_1", "pin", "pin_principal"))
    c_pin2 = pick_col(cols_ci, ("pin2", "pin_2", "pin_secundario"))
    c_puk1 = pick_col(cols_ci, ("puk1", "puk_1", "puk"))
    c_puk2 = pick_col(cols_ci, ("puk2", "puk_2"))
    c_ext  = pick_col(cols_ci, ("extension_vpn", "extension", "ext", "vpn", "extensionvpn"))
    c_cif  = pick_col(cols_ci, ("cif", "cif_cliente", "nif", "dni_cif"))
    c_cta  = pick_col(cols_ci, ("cuenta", "account", "cuenta_vodafone"))
    c_not  = pick_col(cols_ci, ("txt_notas", "notas", "nota", "observaciones", "comentario", "comentarios"))
    c_ts_a = pick_col(cols_ci, ("ts_alta_utc", "created_at", "created", "fecha_alta", "alta"))
    c_ts_u = pick_col(cols_ci, ("ts_update_utc", "updated_at", "updated", "fecha_update", "modificado", "modified"))

    idx = {c: src_cols.index(c) for c in src_cols}

    out: List[Dict[str, Any]] = []
    for r in src_rows:
        numero = normalize_phone(r[idx[c_numero]])
        if not numero:
            continue

        sim = norm_txt(r[idx[c_sim]]) if c_sim else None
        pin1 = norm_txt(r[idx[c_pin1]]) if c_pin1 else None
        pin2 = norm_txt(r[idx[c_pin2]]) if c_pin2 else None
        puk1 = norm_txt(r[idx[c_puk1]]) if c_puk1 else None
        puk2 = norm_txt(r[idx[c_puk2]]) if c_puk2 else None
        ext  = norm_txt(r[idx[c_ext]]) if c_ext else None
        cif  = norm_txt(r[idx[c_cif]]) if c_cif else None
        cta  = norm_txt(r[idx[c_cta]]) if c_cta else None
        notas = norm_txt(r[idx[c_not]]) if c_not else None

        dt_alta = parse_dt_utc(r[idx[c_ts_a]]) if c_ts_a else None
        dt_upd  = parse_dt_utc(r[idx[c_ts_u]]) if c_ts_u else None

        flg_pend = 1 if (not pin1 and not puk1 and not pin2 and not puk2) else 0

        out.append({
            "numero": numero,
            "sim": sim,
            "pin1": pin1,
            "pin2": pin2,
            "puk1": puk1,
            "puk2": puk2,
            "extension_vpn": ext,
            "cif": cif,
            "cuenta": cta,
            "cod_origen": "sqlite",
            "flg_no_borrar_por_csv": 1,       # proteger histórico por defecto
            "flg_pendiente_pinpuk": flg_pend,
            "txt_notas": notas,
            "ts_alta_utc": (dt_alta or utc_now()),
            "ts_update_utc": (dt_upd or utc_now()),
        })
    return out


def merge_lineas(cn: pyodbc.Connection, rows: List[Dict[str, Any]], batch_size: int = 5000) -> int:
    if not rows:
        return 0

    cur = cn.cursor()
    cur.execute("SET NOCOUNT ON; SET XACT_ABORT ON;")

    cur.execute("""
IF OBJECT_ID('tempdb..#stg_lineas') IS NOT NULL DROP TABLE #stg_lineas;
CREATE TABLE #stg_lineas(
    numero NVARCHAR(32) NOT NULL,
    sim NVARCHAR(64) NULL,
    pin1 NVARCHAR(32) NULL,
    pin2 NVARCHAR(32) NULL,
    puk1 NVARCHAR(32) NULL,
    puk2 NVARCHAR(32) NULL,
    extension_vpn NVARCHAR(64) NULL,
    cif NVARCHAR(32) NULL,
    cuenta NVARCHAR(32) NULL,
    cod_origen NVARCHAR(16) NOT NULL,
    flg_no_borrar_por_csv BIT NOT NULL,
    flg_pendiente_pinpuk BIT NOT NULL,
    txt_notas NVARCHAR(4000) NULL,
    ts_alta_utc DATETIME2(0) NOT NULL,
    ts_update_utc DATETIME2(0) NOT NULL
);
""")

    insert_sql = """
INSERT INTO #stg_lineas(
    numero, sim, pin1, pin2, puk1, puk2, extension_vpn, cif, cuenta,
    cod_origen, flg_no_borrar_por_csv, flg_pendiente_pinpuk, txt_notas, ts_alta_utc, ts_update_utc
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
"""
    cur.fast_executemany = True

    def row_to_tuple(d: Dict[str, Any]) -> Tuple[Any, ...]:
        return (
            d["numero"], d["sim"], d["pin1"], d["pin2"], d["puk1"], d["puk2"],
            d["extension_vpn"], d["cif"], d["cuenta"],
            d["cod_origen"], int(d["flg_no_borrar_por_csv"]), int(d["flg_pendiente_pinpuk"]),
            d["txt_notas"],
            d["ts_alta_utc"].replace(tzinfo=None), d["ts_update_utc"].replace(tzinfo=None),
        )

    tuples = [row_to_tuple(r) for r in rows]
    for i in range(0, len(tuples), batch_size):
        cur.executemany(insert_sql, tuples[i:i + batch_size])

    cur.execute("""
MERGE dbo.lineas AS tgt
USING #stg_lineas AS src
ON tgt.numero = src.numero
WHEN MATCHED THEN
    UPDATE SET
        tgt.sim = COALESCE(src.sim, tgt.sim),
        tgt.pin1 = COALESCE(src.pin1, tgt.pin1),
        tgt.pin2 = COALESCE(src.pin2, tgt.pin2),
        tgt.puk1 = COALESCE(src.puk1, tgt.puk1),
        tgt.puk2 = COALESCE(src.puk2, tgt.puk2),
        tgt.extension_vpn = COALESCE(src.extension_vpn, tgt.extension_vpn),
        tgt.cif = COALESCE(src.cif, tgt.cif),
        tgt.cuenta = COALESCE(src.cuenta, tgt.cuenta),
        tgt.txt_notas = COALESCE(src.txt_notas, tgt.txt_notas),

        -- No desprotege nunca:
        tgt.flg_no_borrar_por_csv = CASE WHEN tgt.flg_no_borrar_por_csv = 1 THEN 1 ELSE src.flg_no_borrar_por_csv END,

        -- pending: si ya hay algún PIN/PUK tras merge => 0
        tgt.flg_pendiente_pinpuk = CASE
            WHEN (COALESCE(src.pin1, tgt.pin1) IS NOT NULL OR COALESCE(src.puk1, tgt.puk1) IS NOT NULL
               OR COALESCE(src.pin2, tgt.pin2) IS NOT NULL OR COALESCE(src.puk2, tgt.puk2) IS NOT NULL) THEN 0
            ELSE 1
        END,

        tgt.ts_update_utc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN
    INSERT(
        numero, sim, pin1, pin2, puk1, puk2, extension_vpn, cif, cuenta,
        cod_origen, flg_no_borrar_por_csv, flg_pendiente_pinpuk, txt_notas, ts_alta_utc, ts_update_utc
    )
    VALUES(
        src.numero, src.sim, src.pin1, src.pin2, src.puk1, src.puk2, src.extension_vpn, src.cif, src.cuenta,
        src.cod_origen, src.flg_no_borrar_por_csv, src.flg_pendiente_pinpuk, src.txt_notas, src.ts_alta_utc, SYSUTCDATETIME()
    );
""")

    return len(rows)


# -----------------------------
# Migración: asignaciones
# -----------------------------
def build_asignaciones_rows(src_cols: List[str], src_rows: List[Tuple[Any, ...]]) -> List[Dict[str, Any]]:
    cols_ci = ci_map(src_cols)

    c_numero = pick_col(cols_ci, ("numero", "msisdn", "telefono", "tel", "linea", "phone"))
    if not c_numero:
        raise RuntimeError("No se detecta columna de número en la tabla origen de asignaciones.")

    c_emp = pick_col(cols_ci, ("empleado", "nombre", "usuario", "employee", "responsable_linea"))
    c_email = pick_col(cols_ci, ("email", "correo", "mail"))
    c_grupo = pick_col(cols_ci, ("grupo", "departamento", "area", "team"))
    c_dname = pick_col(cols_ci, ("device_name", "device", "nombre_dispositivo"))
    c_dmodel = pick_col(cols_ci, ("device_model", "modelo", "model"))
    c_cambio = pick_col(cols_ci, ("cambio_telefono", "cambio", "swap", "cambio_terminal"))
    c_motivo = pick_col(cols_ci, ("motivo_cambio", "motivo", "reason"))
    c_hist = pick_col(cols_ci, ("historial_cambios", "historial", "log", "history"))
    c_generic = pick_col(cols_ci, ("is_generic", "generic", "flg_generic", "es_generico"))
    c_resp = pick_col(cols_ci, ("responsable", "owner", "responsable_area", "manager"))
    c_ts_a = pick_col(cols_ci, ("ts_alta_utc", "created_at", "created", "fecha_alta", "alta"))
    c_ts_u = pick_col(cols_ci, ("ts_update_utc", "updated_at", "updated", "fecha_update", "modificado", "modified"))

    idx = {c: src_cols.index(c) for c in src_cols}

    out: List[Dict[str, Any]] = []
    for r in src_rows:
        numero = normalize_phone(r[idx[c_numero]])
        if not numero:
            continue

        dt_alta = parse_dt_utc(r[idx[c_ts_a]]) if c_ts_a else None
        dt_upd  = parse_dt_utc(r[idx[c_ts_u]]) if c_ts_u else None

        out.append({
            "numero": numero,
            "empleado": norm_txt(r[idx[c_emp]]) if c_emp else None,
            "email": norm_txt(r[idx[c_email]]) if c_email else None,
            "grupo": norm_txt(r[idx[c_grupo]]) if c_grupo else None,
            "device_name": norm_txt(r[idx[c_dname]]) if c_dname else None,
            "device_model": norm_txt(r[idx[c_dmodel]]) if c_dmodel else None,
            "cambio_telefono": norm_txt(r[idx[c_cambio]]) if c_cambio else None,
            "motivo_cambio": norm_txt(r[idx[c_motivo]]) if c_motivo else None,
            "historial_cambios": norm_txt(r[idx[c_hist]]) if c_hist else None,
            "is_generic": to_bit(r[idx[c_generic]]) if c_generic else 0,
            "responsable": norm_txt(r[idx[c_resp]]) if c_resp else None,
            "ts_alta_utc": (dt_alta or utc_now()),
            "ts_update_utc": (dt_upd or utc_now()),
        })
    return out


def merge_asignaciones(cn: pyodbc.Connection, rows: List[Dict[str, Any]], batch_size: int = 5000) -> int:
    if not rows:
        return 0

    cur = cn.cursor()
    cur.execute("SET NOCOUNT ON; SET XACT_ABORT ON;")

    cur.execute("""
IF OBJECT_ID('tempdb..#stg_asignaciones') IS NOT NULL DROP TABLE #stg_asignaciones;
CREATE TABLE #stg_asignaciones(
    numero NVARCHAR(32) NOT NULL,
    empleado NVARCHAR(200) NULL,
    email NVARCHAR(200) NULL,
    grupo NVARCHAR(200) NULL,
    device_name NVARCHAR(200) NULL,
    device_model NVARCHAR(200) NULL,
    cambio_telefono NVARCHAR(10) NULL,
    motivo_cambio NVARCHAR(400) NULL,
    historial_cambios NVARCHAR(MAX) NULL,
    is_generic BIT NOT NULL,
    responsable NVARCHAR(200) NULL,
    ts_alta_utc DATETIME2(0) NOT NULL,
    ts_update_utc DATETIME2(0) NOT NULL
);
""")

    insert_sql = """
INSERT INTO #stg_asignaciones(
    numero, empleado, email, grupo, device_name, device_model,
    cambio_telefono, motivo_cambio, historial_cambios, is_generic, responsable,
    ts_alta_utc, ts_update_utc
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);
"""
    cur.fast_executemany = True

    tuples: List[Tuple[Any, ...]] = []
    for d in rows:
        tuples.append((
            d["numero"], d["empleado"], d["email"], d["grupo"], d["device_name"], d["device_model"],
            d["cambio_telefono"], d["motivo_cambio"], d["historial_cambios"], int(d["is_generic"]), d["responsable"],
            d["ts_alta_utc"].replace(tzinfo=None), d["ts_update_utc"].replace(tzinfo=None),
        ))

    for i in range(0, len(tuples), batch_size):
        cur.executemany(insert_sql, tuples[i:i + batch_size])

    # Asegurar existencia en dbo.lineas para cumplir FK (placeholder protegido)
    cur.execute("""
INSERT INTO dbo.lineas(numero, cod_origen, flg_no_borrar_por_csv, flg_pendiente_pinpuk, ts_alta_utc, ts_update_utc)
SELECT DISTINCT s.numero, 'sqlite', 1, 1, SYSUTCDATETIME(), SYSUTCDATETIME()
FROM #stg_asignaciones s
LEFT JOIN dbo.lineas l ON l.numero = s.numero
WHERE l.numero IS NULL;
""")

    cur.execute("""
MERGE dbo.asignaciones AS tgt
USING #stg_asignaciones AS src
ON tgt.numero = src.numero
WHEN MATCHED THEN
    UPDATE SET
        tgt.empleado = COALESCE(src.empleado, tgt.empleado),
        tgt.email = COALESCE(src.email, tgt.email),
        tgt.grupo = COALESCE(src.grupo, tgt.grupo),
        tgt.device_name = COALESCE(src.device_name, tgt.device_name),
        tgt.device_model = COALESCE(src.device_model, tgt.device_model),
        tgt.cambio_telefono = COALESCE(src.cambio_telefono, tgt.cambio_telefono),
        tgt.motivo_cambio = COALESCE(src.motivo_cambio, tgt.motivo_cambio),
        tgt.historial_cambios = COALESCE(src.historial_cambios, tgt.historial_cambios),
        tgt.is_generic = CASE WHEN tgt.is_generic = 1 THEN 1 ELSE src.is_generic END,
        tgt.responsable = COALESCE(src.responsable, tgt.responsable),
        tgt.ts_update_utc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN
    INSERT(
        numero, empleado, email, grupo, device_name, device_model,
        cambio_telefono, motivo_cambio, historial_cambios, is_generic, responsable,
        ts_alta_utc, ts_update_utc
    )
    VALUES(
        src.numero, src.empleado, src.email, src.grupo, src.device_name, src.device_model,
        src.cambio_telefono, src.motivo_cambio, src.historial_cambios, src.is_generic, src.responsable,
        src.ts_alta_utc, SYSUTCDATETIME()
    );
""")

    return len(rows)


# -----------------------------
# Migración opcional: usuarios / auditoria
# -----------------------------
def migrate_usuarios_if_possible(sqlite_conn: sqlite3.Connection, cn: pyodbc.Connection) -> int:
    st = find_best_table(sqlite_conn, "usuarios")
    if not st:
        return 0

    cols, rows = sqlite_fetch_all(sqlite_conn, st.name)
    cols_ci = ci_map(cols)
    needed = ("username", "role", "password_hash", "salt", "iterations")
    if not all(k in cols_ci for k in needed):
        return 0

    idx = {c: cols.index(c) for c in cols}
    payload = []
    for r in rows:
        username = norm_txt(r[idx[cols_ci["username"]]])
        if not username:
            continue
        payload.append((
            username,
            norm_txt(r[idx[cols_ci["role"]]]) or "user",
            norm_txt(r[idx[cols_ci["password_hash"]]]) or "",
            norm_txt(r[idx[cols_ci["salt"]]]) or "",
            int(r[idx[cols_ci["iterations"]]]) if r[idx[cols_ci["iterations"]]] is not None else 0,
        ))

    if not payload:
        return 0

    cur = cn.cursor()
    cur.execute("SET NOCOUNT ON; SET XACT_ABORT ON;")
    cur.fast_executemany = True

    cur.executemany("""
MERGE dbo.usuarios AS tgt
USING (SELECT ? AS username, ? AS role, ? AS password_hash, ? AS salt, ? AS iterations) AS src
ON tgt.username = src.username
WHEN MATCHED THEN UPDATE SET
    role = src.role, password_hash = src.password_hash, salt = src.salt, iterations = src.iterations
WHEN NOT MATCHED THEN
    INSERT(username, role, password_hash, salt, iterations)
    VALUES(src.username, src.role, src.password_hash, src.salt, src.iterations);
""", payload)

    return len(payload)


def migrate_auditoria_if_possible(sqlite_conn: sqlite3.Connection, cn: pyodbc.Connection, max_rows: Optional[int] = None) -> int:
    st = find_best_table(sqlite_conn, "auditoria")
    if not st:
        return 0

    cols, rows = sqlite_fetch_all(sqlite_conn, st.name)
    cols_ci = ci_m


