# -*- coding: utf-8 -*-
"""
GESTOR DE MÓVILES EMPRESARIAL (SQL Server)
- Backend: SQL Server (DB: SQL_DATABASE_NAME) con tablas dbo.usuarios, dbo.lineas, dbo.asignaciones, dbo.auditoria
- UI: Tkinter (desktop)
- Funcionalidades principales:
  * Login/roles (admin/soporte)
  * Buscar/Gestionar + Consulta rápida
  * Emparejar/Editar asignación (sin borrar)
  * Editar línea (sin borrar)
  * Alta manual de línea (para líneas nuevas sin PIN/PUK)
  * Importación/sincronización desde CSVs PINPUK (upsert seguro; no borra por defecto)
  * Auditoría (últimos cambios)
  * Exportación a Excel/CSV

NOTA: Este script incluye valores por defecto de conexión que el usuario proporcionó. Se pueden sobreescribir
con variables de entorno: GM_SQL_SERVER, GM_SQL_DB, GM_SQL_USER, GM_SQL_PASSWORD.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import pandas as pd

try:
    import pyodbc  # type: ignore
except Exception as e:
    pyodbc = None  # type: ignore

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, scrolledtext, filedialog

# openpyxl se usa para exportar
try:
    import openpyxl  # noqa: F401
except Exception:
    openpyxl = None  # type: ignore


# =============================================================================
# CONFIG
# =============================================================================

APP_VERSION = "3.0-sqlserver"
APP_TITLE = f"📲 GESTOR DE MÓVILES EMPRESARIAL v{APP_VERSION}"

# Carpeta del script: aquí se esperan por defecto los CSVs PINPUK y DeviceList
APP_DIR = Path(__file__).resolve().parent

# CSVs típicos (se pueden ajustar poniendo los ficheros en APP_DIR)
PINPUK_CSV_FILES = ["PINPUK.csv", "PINPUK1.csv", "PINPUK2.csv", "PINPUK3.csv"]
DEVICELIST_CSV_FILE = "DeviceList2.csv"

# SQL Server defaults (pueden sobreescribirse vía env)
SQL_SERVER = os.getenv("GM_SQL_SERVER", "")
SQL_DB = os.getenv("GM_SQL_DB", "")
SQL_USER = os.getenv("GM_SQL_USER", "")
SQL_PASSWORD = os.getenv("GM_SQL_PASSWORD", "")

# Auth defaults: se insertan si la tabla dbo.usuarios está vacía
DEFAULT_USERS = {
    "admin": {"role": "admin", "password": "change_me_admin"},
    "soporte": {"role": "soporte", "password": "change_me_support"},
}

# Seguridad PBKDF2
PBKDF2_ITERATIONS = 160_000
PBKDF2_SALT_BYTES = 16
PBKDF2_ALG = "sha256"
PBKDF2_DKLEN = 32

# Logging
LOG_DIR = APP_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / f"moviles_{datetime.now().strftime('%Y%m%d')}.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)

# =============================================================================
# UI (colores y fuentes)
# =============================================================================

COLOR_BG = "#0f172a"
COLOR_PANEL = "#ffffff"
COLOR_PRIMARY = "#2563eb"
COLOR_TXT = "#0b1220"
COLOR_TXT_SECONDARY = "#334155"
COLOR_DANGER = "#dc2626"
COLOR_WARNING = "#d97706"

FONT_TITLE = ("Segoe UI", 18, "bold")
FONT_SUBTITLE = ("Segoe UI", 12, "bold")
FONT_TEXT = ("Segoe UI", 11)
FONT_BUTTON = ("Segoe UI", 10, "bold")

BUTTON_WIDTH = 22

# =============================================================================
# Globals
# =============================================================================

CURRENT_USER: Optional[str] = None
CURRENT_ROLE: Optional[str] = None
LAST_NUMERO_CONTEXT: Optional[str] = None  # último número con resultado único

root: tk.Tk  # se inicializa más abajo
text_box: scrolledtext.ScrolledText
entry: ttk.Entry

# =============================================================================
# Utilidades
# =============================================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)  # naive UTC (para SQL Server)


def clean_invisibles(s: str) -> str:
    # Limpia NBSP, \n, \r, tabs, etc.
    return (
        (s or "")
        .replace("\xa0", "")
        .replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .strip()
    )


def clean_numero_pk(numero: str) -> str:
    """
    Normaliza el número para usarlo como PK estable.
    - Quita espacios, separadores, invisibles.
    - Mantiene '+' al inicio si existe, y el resto dígitos.
    - Si no hay dígitos suficientes, devuelve el texto limpio en mayúsculas.
    """
    raw = clean_invisibles(numero)
    if not raw:
        return ""
    raw = raw.upper()
    # Conservar '+' inicial
    plus = "+" if raw.startswith("+") else ""
    digits = re.sub(r"\D+", "", raw)
    if len(digits) >= 6:
        return plus + digits
    # fallback: texto sin separadores típicos
    return re.sub(r"[.\-_\s]+", "", raw)


def numero_key(numero: str) -> str:
    """Clave de comparación (solo dígitos, o texto limpio si no hay)."""
    n = clean_numero_pk(numero)
    digits = re.sub(r"\D+", "", n)
    return digits if digits else n


def _new_salt_hex() -> str:
    return os.urandom(PBKDF2_SALT_BYTES).hex()


def _pbkdf2_hash_hex(password: str, salt_hex: str, iterations: int) -> str:
    dk = hashlib.pbkdf2_hmac(
        PBKDF2_ALG,
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        iterations,
        dklen=PBKDF2_DKLEN,
    )
    return dk.hex()


def _verify_password(password: str, stored_hash_hex: str, salt_hex: str, iterations: int) -> bool:
    candidate = _pbkdf2_hash_hex(password, salt_hex, iterations)
    return hmac.compare_digest(candidate, stored_hash_hex)


def center_window(win: tk.Toplevel | tk.Tk, width: int, height: int):
    win.update_idletasks()
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    win.geometry(f"{width}x{height}+{x}+{y}")


def showinfo_centered(title: str, message: str, parent=None):
    messagebox.showinfo(title, message, parent=parent)


def showwarning_centered(title: str, message: str, parent=None):
    messagebox.showwarning(title, message, parent=parent)


def showerror_centered(title: str, message: str, parent=None):
    messagebox.showerror(title, message, parent=parent)


def askyesno_centered(title: str, message: str, parent=None) -> bool:
    return messagebox.askyesno(title, message, parent=parent)


def askstring_centered(title: str, prompt: str, parent=None) -> Optional[str]:
    return simpledialog.askstring(title, prompt, parent=parent)


# =============================================================================
# SQL Server DAL
# =============================================================================

class DbError(RuntimeError):
    pass


@dataclass(frozen=True)
class DbConfig:
    server: str
    database: str
    user: str
    password: str


class Db:
    """
    Capa de acceso a datos:
    - Una sola conexión global (desktop app). Reintenta si se cae.
    - Queries parametrizadas (pyodbc).
    """

    def __init__(self, cfg: DbConfig):
        if pyodbc is None:
            raise DbError("Falta dependencia pyodbc. Instala: pip install pyodbc")
        self.cfg = cfg
        self.conn = self._connect()

    def _connect(self):
        # Driver preferente: 18, fallback: 17
        drivers = [d for d in pyodbc.drivers()]
        driver = None
        for cand in ["ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server"]:
            if cand in drivers:
                driver = cand
                break
        if not driver:
            # fallback: el primero que contenga "SQL Server"
            for d in drivers:
                if "SQL Server" in d:
                    driver = d
                    break
        if not driver:
            raise DbError("No se encontró un driver ODBC de SQL Server (instala ODBC Driver 17/18).")

        # Importante: Driver 18 fuerza Encrypt=yes por defecto. Para entornos on-prem sin TLS correcto:
        # Encrypt=no; TrustServerCertificate=yes
        conn_str = (
            f"DRIVER={{{driver}}};"
            f"SERVER={self.cfg.server};"
            f"DATABASE={self.cfg.database};"
            f"User ID={self.cfg.user};"
            f"Password={self.cfg.password};"
            "Encrypt=no;"
            "TrustServerCertificate=yes;"
            "ApplicationIntent=ReadWrite;"
        )
        logging.info(f"Conectando a SQL Server {self.cfg.server} / DB {self.cfg.database} (driver: {driver})")
        conn = pyodbc.connect(conn_str, autocommit=False)
        conn.timeout = 30
        return conn

    def ensure_connected(self):
        try:
            self.conn.cursor().execute("SELECT 1")
        except Exception:
            logging.warning("Conexión SQL caída. Reintentando...")
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = self._connect()

    def execute(self, sql: str, params: Sequence[Any] = ()):
        self.ensure_connected()
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur

    def executemany(self, sql: str, rows: Sequence[Sequence[Any]], fast: bool = True):
        self.ensure_connected()
        cur = self.conn.cursor()
        if fast:
            try:
                cur.fast_executemany = True
            except Exception:
                pass
        cur.executemany(sql, rows)
        return cur

    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> Optional[Tuple]:
        cur = self.execute(sql, params)
        return cur.fetchone()

    def fetchall(self, sql: str, params: Sequence[Any] = ()) -> List[Tuple]:
        cur = self.execute(sql, params)
        return cur.fetchall()

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()


DB = Db(DbConfig(SQL_SERVER, SQL_DB, SQL_USER, SQL_PASSWORD))


# =============================================================================
# DB Schema bootstrap (idempotente)
# =============================================================================

def init_schema_if_needed():
    """
    Crea las tablas si no existen (idéntico a lo que el usuario ejecutó),
    y añade columnas si faltan (compatibilidad).
    """
    sql = r"""
    SET NOCOUNT ON;

    IF OBJECT_ID('dbo.usuarios','U') IS NULL
    BEGIN
        CREATE TABLE dbo.usuarios (
            username       NVARCHAR(100) NOT NULL PRIMARY KEY,
            role           NVARCHAR(50)  NOT NULL,
            password_hash  NVARCHAR(128) NOT NULL,
            salt           NVARCHAR(64)  NOT NULL,
            iterations     INT           NOT NULL
        );
    END;

    IF OBJECT_ID('dbo.lineas','U') IS NULL
    BEGIN
        CREATE TABLE dbo.lineas (
            numero NVARCHAR(32) NOT NULL PRIMARY KEY,
            sim NVARCHAR(64) NULL,
            pin1 NVARCHAR(32) NULL,
            pin2 NVARCHAR(32) NULL,
            puk1 NVARCHAR(32) NULL,
            puk2 NVARCHAR(32) NULL,
            extension_vpn NVARCHAR(64) NULL,
            cif NVARCHAR(32) NULL,
            cuenta NVARCHAR(32) NULL,

            cod_origen NVARCHAR(16) NOT NULL CONSTRAINT DF_lineas_cod_origen DEFAULT ('csv'),
            flg_no_borrar_por_csv BIT NOT NULL CONSTRAINT DF_lineas_no_borrar DEFAULT (0),
            flg_pendiente_pinpuk BIT NOT NULL CONSTRAINT DF_lineas_pendiente DEFAULT (0),
            txt_notas NVARCHAR(4000) NULL,

            ts_alta_utc DATETIME2(0) NOT NULL CONSTRAINT DF_lineas_alta DEFAULT (SYSUTCDATETIME()),
            ts_update_utc DATETIME2(0) NOT NULL CONSTRAINT DF_lineas_upd DEFAULT (SYSUTCDATETIME())
        );
    END;

    IF COL_LENGTH('dbo.lineas','cod_origen') IS NULL
        ALTER TABLE dbo.lineas ADD cod_origen NVARCHAR(16) NOT NULL CONSTRAINT DF_lineas_cod_origen2 DEFAULT('csv');
    IF COL_LENGTH('dbo.lineas','flg_no_borrar_por_csv') IS NULL
        ALTER TABLE dbo.lineas ADD flg_no_borrar_por_csv BIT NOT NULL CONSTRAINT DF_lineas_no_borrar2 DEFAULT(0);
    IF COL_LENGTH('dbo.lineas','flg_pendiente_pinpuk') IS NULL
        ALTER TABLE dbo.lineas ADD flg_pendiente_pinpuk BIT NOT NULL CONSTRAINT DF_lineas_pendiente2 DEFAULT(0);
    IF COL_LENGTH('dbo.lineas','txt_notas') IS NULL
        ALTER TABLE dbo.lineas ADD txt_notas NVARCHAR(4000) NULL;
    IF COL_LENGTH('dbo.lineas','ts_alta_utc') IS NULL
        ALTER TABLE dbo.lineas ADD ts_alta_utc DATETIME2(0) NOT NULL CONSTRAINT DF_lineas_alta2 DEFAULT(SYSUTCDATETIME());
    IF COL_LENGTH('dbo.lineas','ts_update_utc') IS NULL
        ALTER TABLE dbo.lineas ADD ts_update_utc DATETIME2(0) NOT NULL CONSTRAINT DF_lineas_upd2 DEFAULT(SYSUTCDATETIME());

    IF OBJECT_ID('dbo.asignaciones','U') IS NULL
    BEGIN
        CREATE TABLE dbo.asignaciones (
            numero NVARCHAR(32) NOT NULL PRIMARY KEY,
            empleado NVARCHAR(200) NULL,
            email NVARCHAR(200) NULL,
            grupo NVARCHAR(200) NULL,
            device_name NVARCHAR(200) NULL,
            device_model NVARCHAR(200) NULL,
            cambio_telefono NVARCHAR(10) NULL,
            motivo_cambio NVARCHAR(400) NULL,
            historial_cambios NVARCHAR(MAX) NULL,
            is_generic BIT NOT NULL CONSTRAINT DF_asg_is_generic DEFAULT (0),
            responsable NVARCHAR(200) NULL,

            ts_alta_utc DATETIME2(0) NOT NULL CONSTRAINT DF_asg_alta DEFAULT (SYSUTCDATETIME()),
            ts_update_utc DATETIME2(0) NOT NULL CONSTRAINT DF_asg_upd DEFAULT (SYSUTCDATETIME())
        );
    END;

    IF COL_LENGTH('dbo.asignaciones','ts_alta_utc') IS NULL
        ALTER TABLE dbo.asignaciones ADD ts_alta_utc DATETIME2(0) NOT NULL CONSTRAINT DF_asg_alta2 DEFAULT(SYSUTCDATETIME());
    IF COL_LENGTH('dbo.asignaciones','ts_update_utc') IS NULL
        ALTER TABLE dbo.asignaciones ADD ts_update_utc DATETIME2(0) NOT NULL CONSTRAINT DF_asg_upd2 DEFAULT(SYSUTCDATETIME());

    IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name='FK_asignaciones_lineas_numero')
    BEGIN
        ALTER TABLE dbo.asignaciones WITH CHECK
        ADD CONSTRAINT FK_asignaciones_lineas_numero
        FOREIGN KEY(numero) REFERENCES dbo.lineas(numero) ON DELETE CASCADE;
    END;

    IF OBJECT_ID('dbo.auditoria','U') IS NULL
    BEGIN
        CREATE TABLE dbo.auditoria (
            id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
            tabla NVARCHAR(50) NOT NULL,
            registro_id NVARCHAR(100) NOT NULL,
            accion NVARCHAR(20) NOT NULL,
            usuario NVARCHAR(100) NOT NULL CONSTRAINT DF_aud_usuario DEFAULT ('sistema'),
            fecha DATETIME2(0) NOT NULL CONSTRAINT DF_aud_fecha DEFAULT (SYSUTCDATETIME()),
            datos_anteriores NVARCHAR(MAX) NULL,
            datos_nuevos NVARCHAR(MAX) NULL,
            descripcion NVARCHAR(4000) NULL
        );
        CREATE INDEX IX_auditoria_fecha ON dbo.auditoria(fecha DESC);
    END;
    """
    DB.execute(sql)
    DB.commit()


# =============================================================================
# Auditoría
# =============================================================================

def log_audit(
    tabla: str,
    registro_id: str,
    accion: str,
    usuario: str,
    datos_anteriores: Optional[Dict[str, Any]] = None,
    datos_nuevos: Optional[Dict[str, Any]] = None,
    descripcion: Optional[str] = None,
):
    try:
        DB.execute(
            """
            INSERT INTO dbo.auditoria(tabla, registro_id, accion, usuario, fecha, datos_anteriores, datos_nuevos, descripcion)
            VALUES(?, ?, ?, ?, SYSUTCDATETIME(), ?, ?, ?)
            """,
            (
                tabla,
                registro_id,
                accion,
                usuario or "sistema",
                json.dumps(datos_anteriores, ensure_ascii=False) if datos_anteriores else None,
                json.dumps(datos_nuevos, ensure_ascii=False) if datos_nuevos else None,
                descripcion,
            ),
        )
        DB.commit()
    except Exception as e:
        # No bloquear la app por fallos de auditoría
        logging.error(f"Fallo auditoría: {e}")


# =============================================================================
# Auth / permisos
# =============================================================================

def init_auth():
    """Asegura que existen usuarios por defecto si la tabla está vacía."""
    row = DB.fetchone("SELECT COUNT(1) FROM dbo.usuarios")
    n = int(row[0]) if row else 0
    if n > 0:
        return

    for username, meta in DEFAULT_USERS.items():
        role = meta["role"]
        password = meta["password"]
        salt_hex = _new_salt_hex()
        ph = _pbkdf2_hash_hex(password, salt_hex, PBKDF2_ITERATIONS)
        DB.execute(
            "INSERT INTO dbo.usuarios(username, role, password_hash, salt, iterations) VALUES(?, ?, ?, ?, ?)",
            (username, role, ph, salt_hex, PBKDF2_ITERATIONS),
        )
    DB.commit()
    logging.warning("Tabla dbo.usuarios estaba vacía: se crearon usuarios por defecto (admin/soporte). Cambia passwords.")


def authenticate(username: str, password: str) -> Tuple[bool, Optional[str]]:
    row = DB.fetchone(
        "SELECT role, password_hash, salt, iterations FROM dbo.usuarios WHERE username = ?",
        (username,),
    )
    if not row:
        return False, None
    role, ph, salt_hex, it_ = row
    try:
        ok = _verify_password(password, ph, salt_hex, int(it_))
    except Exception:
        ok = False
    return ok, str(role) if ok else None


def is_admin() -> bool:
    return (CURRENT_ROLE or "").lower() == "admin"


def has_permission(action_key: str) -> bool:
    """
    Permisos por rol.
    - admin: todo
    - soporte: lectura + operaciones seguras (no borrar masivo)
    """
    if is_admin():
        return True
    if (CURRENT_ROLE or "").lower() == "soporte":
        allowed = {
            "buscar_gestionar",
            "consulta_rapida",
            "buscar_por_empresa",
            "buscar_por_departamento",
            "buscar_por_responsable",
            "mostrar_estadisticas",
            "mostrar_auditoria",
            "menu_exportacion",
            "alta_manual",
            "editar_ficha",
            "emparejar",
            "import_email",
            # recarga csvs solo si se hace en modo seguro (sin borrar)
            "reload_csvs_safe",
        }
        return action_key in allowed
    return False


def deny_if_not_allowed(action_key: str, action_name: str) -> bool:
    if not has_permission(action_key):
        showwarning_centered("Sin permisos", f"No tiene permisos para esta acción: {action_name}.")
        return True
    return False


def deny_if_not_admin(feature_name: str) -> bool:
    if not is_admin():
        showerror_centered("Acceso denegado", f"{feature_name} solo está disponible para el usuario administrador.")
        return True
    return False


# =============================================================================
# Lectura CSVs / DeviceList
# =============================================================================

def _safe_read_csv(path: Path) -> pd.DataFrame:
    # Vodafone suele venir en ; y latin1. PINPUK también.
    encs = ["utf-8", "utf-8-sig", "latin1", "cp1252"]
    seps = [";", ",", "\t"]
    last_err = None
    for enc in encs:
        for sep in seps:
            try:
                df = pd.read_csv(path, encoding=enc, sep=sep, dtype=str)
                return df
            except Exception as e:
                last_err = e
                continue
    raise RuntimeError(f"No se pudo leer CSV {path.name}: {last_err}")


def load_pinpuk_sources(data_dir: Path) -> pd.DataFrame:
    dfs: List[pd.DataFrame] = []
    for fn in PINPUK_CSV_FILES:
        p = data_dir / fn
        if p.exists():
            try:
                dfs.append(_safe_read_csv(p))
            except Exception as e:
                logging.warning(f"No se pudo leer {p}: {e}")
    if not dfs:
        return pd.DataFrame()
    df = pd.concat(dfs, ignore_index=True)
    # Normalizar nombres de columnas: intenta mapear variantes comunes
    cols = {c.strip().lower(): c for c in df.columns}
    def pick(*names):
        for n in names:
            if n in cols:
                return cols[n]
        return None

    col_num = pick("numero", "número", "telefono", "teléfono", "línea", "linea", "msisdn")
    col_sim = pick("sim", "iccid", "numero sim", "número sim")
    col_pin1 = pick("pin1", "pin 1", "pin")
    col_pin2 = pick("pin2", "pin 2")
    col_puk1 = pick("puk1", "puk 1", "puk")
    col_puk2 = pick("puk2", "puk 2")
    col_ext = pick("extension_vpn", "extensión vpn", "extension", "extensión")
    col_cif = pick("cif")
    col_cta = pick("cuenta", "account")

    keep_map = {
        "numero": col_num,
        "sim": col_sim,
        "pin1": col_pin1,
        "pin2": col_pin2,
        "puk1": col_puk1,
        "puk2": col_puk2,
        "extension_vpn": col_ext,
        "cif": col_cif,
        "cuenta": col_cta,
    }
    for k,v in keep_map.items():
        if v is None:
            df[k] = None
        else:
            df[k] = df[v]
    df = df[list(keep_map.keys())]

    # Limpiezas
    for c in df.columns:
        df[c] = df[c].astype(str).where(df[c].notna(), None)
        df[c] = df[c].map(lambda x: clean_invisibles(x) if isinstance(x, str) else x)

    # Filtrar vacíos
    df["numero"] = df["numero"].map(clean_numero_pk)
    df = df[df["numero"].astype(str).str.len() > 0].copy()

    # Dedup: mejor fila = más campos informados (no null/empty)
    def row_score(r):
        score = 0
        for c in ["sim","pin1","pin2","puk1","puk2","extension_vpn","cif","cuenta"]:
            v = r.get(c)
            if v and str(v).strip():
                score += 1
        # preferimos números más cortos (limpios)
        return (score, -len(str(r.get("numero",""))))

    df["_score"] = df.apply(row_score, axis=1)
    df = df.sort_values(by=["numero", "_score"], ascending=[True, False])
    df = df.drop_duplicates(subset=["numero"], keep="first").drop(columns=["_score"])
    return df


def load_devicelist(data_dir: Path) -> pd.DataFrame:
    p = data_dir / DEVICELIST_CSV_FILE
    if not p.exists():
        return pd.DataFrame(columns=["Device Name", "Email", "Groups", "Description", "Device Model"])
    try:
        df = _safe_read_csv(p)
    except Exception:
        try:
            df = pd.read_csv(p, encoding="latin1", delimiter=";", dtype=str)
        except Exception:
            return pd.DataFrame(columns=["Device Name", "Email", "Groups", "Description", "Device Model"])
    # Asegurar columnas
    for c in ["Device Name", "Email", "Groups", "Description", "Device Model"]:
        if c not in df.columns:
            df[c] = None
    return df


# =============================================================================
# Operaciones DB: líneas y asignaciones
# =============================================================================

def get_linea_y_asignacion(numero: str) -> Optional[Dict[str, Any]]:
    n = clean_numero_pk(numero)
    if not n:
        return None
    row = DB.fetchone(
        """
        SELECT
            l.numero, l.sim, l.pin1, l.pin2, l.puk1, l.puk2, l.extension_vpn, l.cif, l.cuenta,
            l.cod_origen, l.flg_no_borrar_por_csv, l.flg_pendiente_pinpuk, l.txt_notas, l.ts_alta_utc, l.ts_update_utc,
            a.empleado, a.email, a.grupo, a.device_name, a.device_model, a.cambio_telefono, a.motivo_cambio, a.historial_cambios,
            a.is_generic, a.responsable, a.ts_alta_utc, a.ts_update_utc
        FROM dbo.lineas l
        LEFT JOIN dbo.asignaciones a ON l.numero = a.numero
        WHERE l.numero = ?
        """,
        (n,),
    )
    if not row:
        return None
    (
        numero_db, sim, pin1, pin2, puk1, puk2, extension_vpn, cif, cuenta,
        cod_origen, flg_no_borrar, flg_pendiente, txt_notas, ts_alta, ts_upd,
        empleado, email, grupo, device_name, device_model, cambio_tel, motivo, historial,
        is_generic, responsable, ts_asg_alta, ts_asg_upd,
    ) = row
    return {
        "linea": {
            "numero": numero_db,
            "sim": sim,
            "pin1": pin1,
            "pin2": pin2,
            "puk1": puk1,
            "puk2": puk2,
            "extension_vpn": extension_vpn,
            "cif": cif,
            "cuenta": cuenta,
            "cod_origen": cod_origen,
            "flg_no_borrar_por_csv": bool(flg_no_borrar),
            "flg_pendiente_pinpuk": bool(flg_pendiente),
            "txt_notas": txt_notas,
            "ts_alta_utc": ts_alta,
            "ts_update_utc": ts_upd,
        },
        "asignacion": {
            "numero": numero_db,
            "empleado": empleado,
            "email": email,
            "grupo": grupo,
            "device_name": device_name,
            "device_model": device_model,
            "cambio_telefono": cambio_tel,
            "motivo_cambio": motivo,
            "historial_cambios": historial,
            "is_generic": bool(is_generic) if is_generic is not None else False,
            "responsable": responsable,
            "ts_alta_utc": ts_asg_alta,
            "ts_update_utc": ts_asg_upd,
        } if empleado is not None or email is not None or grupo is not None or device_name is not None or device_model is not None else None,
    }


def upsert_linea(
    numero: str,
    sim: Optional[str] = None,
    pin1: Optional[str] = None,
    pin2: Optional[str] = None,
    puk1: Optional[str] = None,
    puk2: Optional[str] = None,
    extension_vpn: Optional[str] = None,
    cif: Optional[str] = None,
    cuenta: Optional[str] = None,
    cod_origen: str = "manual",
    flg_no_borrar_por_csv: bool = True,
    flg_pendiente_pinpuk: bool = False,
    txt_notas: Optional[str] = None,
) -> str:
    n = clean_numero_pk(numero)
    if not n:
        raise ValueError("Número vacío")
    before = get_linea_y_asignacion(n)
    DB.execute(
        """
        MERGE dbo.lineas WITH (HOLDLOCK) AS tgt
        USING (SELECT ? AS numero) AS src
        ON tgt.numero = src.numero
        WHEN MATCHED THEN
            UPDATE SET
                sim = COALESCE(?, tgt.sim),
                pin1 = COALESCE(?, tgt.pin1),
                pin2 = COALESCE(?, tgt.pin2),
                puk1 = COALESCE(?, tgt.puk1),
                puk2 = COALESCE(?, tgt.puk2),
                extension_vpn = COALESCE(?, tgt.extension_vpn),
                cif = COALESCE(?, tgt.cif),
                cuenta = COALESCE(?, tgt.cuenta),
                cod_origen = ?,
                flg_no_borrar_por_csv = ?,
                flg_pendiente_pinpuk = ?,
                txt_notas = COALESCE(?, tgt.txt_notas),
                ts_update_utc = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN
            INSERT (numero, sim, pin1, pin2, puk1, puk2, extension_vpn, cif, cuenta,
                    cod_origen, flg_no_borrar_por_csv, flg_pendiente_pinpuk, txt_notas, ts_alta_utc, ts_update_utc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, SYSUTCDATETIME(), SYSUTCDATETIME());
        """,
        (
            n,
            sim, pin1, pin2, puk1, puk2, extension_vpn, cif, cuenta,
            cod_origen, 1 if flg_no_borrar_por_csv else 0, 1 if flg_pendiente_pinpuk else 0, txt_notas,
            n, sim, pin1, pin2, puk1, puk2, extension_vpn, cif, cuenta,
            cod_origen, 1 if flg_no_borrar_por_csv else 0, 1 if flg_pendiente_pinpuk else 0, txt_notas,
        ),
    )
    DB.commit()

    after = get_linea_y_asignacion(n)
    log_audit(
        "lineas",
        n,
        "UPSERT",
        CURRENT_USER or "sistema",
        datos_anteriores=before["linea"] if before else None,
        datos_nuevos=after["linea"] if after else None,
        descripcion=f"Upsert línea ({cod_origen}).",
    )
    return n


def update_linea_fields(numero: str, updates: Dict[str, Any]) -> None:
    n = clean_numero_pk(numero)
    if not n:
        raise ValueError("Número vacío")
    before = get_linea_y_asignacion(n)

    allowed = {
        "sim","pin1","pin2","puk1","puk2","extension_vpn","cif","cuenta",
        "cod_origen","flg_no_borrar_por_csv","flg_pendiente_pinpuk","txt_notas",
    }
    set_parts = []
    params: List[Any] = []
    for k,v in updates.items():
        if k not in allowed:
            continue
        if k in {"flg_no_borrar_por_csv","flg_pendiente_pinpuk"}:
            set_parts.append(f"{k} = ?")
            params.append(1 if bool(v) else 0)
        else:
            set_parts.append(f"{k} = ?")
            params.append(v)
    if not set_parts:
        return

    sql = f"UPDATE dbo.lineas SET {', '.join(set_parts)}, ts_update_utc = SYSUTCDATETIME() WHERE numero = ?"
    params.append(n)
    DB.execute(sql, params)
    DB.commit()

    after = get_linea_y_asignacion(n)
    log_audit(
        "lineas",
        n,
        "UPDATE",
        CURRENT_USER or "sistema",
        datos_anteriores=before["linea"] if before else None,
        datos_nuevos=after["linea"] if after else None,
        descripcion="Edición de campos de línea.",
    )


def upsert_asignacion(numero: str, fields: Dict[str, Any], registrar_historial: bool = True) -> None:
    n = clean_numero_pk(numero)
    if not n:
        raise ValueError("Número vacío")

    # Asegurar que la línea existe (si no, crear como manual pendiente)
    if not DB.fetchone("SELECT 1 FROM dbo.lineas WHERE numero = ?", (n,)):
        upsert_linea(n, cod_origen="manual", flg_no_borrar_por_csv=True, flg_pendiente_pinpuk=True, txt_notas="Alta automática al emparejar.")

    before = get_linea_y_asignacion(n)
    existing_hist = None
    if before and before.get("asignacion"):
        existing_hist = before["asignacion"].get("historial_cambios")

    # Historial: append si registrar_historial y hay cambio_telefono=Sí o motivo
    historial = existing_hist or ""
    if registrar_historial and fields.get("cambio_telefono") in ("Sí", "SI", "SÍ", True, 1):
        motivo = fields.get("motivo_cambio") or "Cambio / asignación"
        dev = fields.get("device_model") or ""
        fecha = datetime.now().strftime("%d/%m/%Y %H:%M")
        entry_h = f"[{fecha}] Dispositivo: {dev}, motivo: {motivo}"
        historial = (historial + "\n" + entry_h).strip() if historial else entry_h

    # Preparar valores
    empleado = fields.get("empleado")
    email = fields.get("email")
    grupo = fields.get("grupo")
    device_name = fields.get("device_name")
    device_model = fields.get("device_model")
    cambio_telefono = fields.get("cambio_telefono")
    motivo_cambio = fields.get("motivo_cambio")
    is_generic = 1 if bool(fields.get("is_generic")) else 0
    responsable = fields.get("responsable")

    # Normalizar grupo (upper)
    if isinstance(grupo, str):
        grupo = clean_invisibles(grupo).upper() or None

    DB.execute(
        """
        MERGE dbo.asignaciones WITH (HOLDLOCK) AS tgt
        USING (SELECT ? AS numero) AS src
        ON tgt.numero = src.numero
        WHEN MATCHED THEN
            UPDATE SET
                empleado = ?,
                email = ?,
                grupo = ?,
                device_name = ?,
                device_model = ?,
                cambio_telefono = ?,
                motivo_cambio = ?,
                historial_cambios = ?,
                is_generic = ?,
                responsable = ?,
                ts_update_utc = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN
            INSERT (numero, empleado, email, grupo, device_name, device_model,
                    cambio_telefono, motivo_cambio, historial_cambios, is_generic, responsable, ts_alta_utc, ts_update_utc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, SYSUTCDATETIME(), SYSUTCDATETIME());
        """,
        (
            n,
            empleado, email, grupo, device_name, device_model, cambio_telefono, motivo_cambio, historial, is_generic, responsable,
            n, empleado, email, grupo, device_name, device_model, cambio_telefono, motivo_cambio, historial, is_generic, responsable,
        ),
    )
    DB.commit()

    after = get_linea_y_asignacion(n)
    log_audit(
        "asignaciones",
        n,
        "UPSERT",
        CURRENT_USER or "sistema",
        datos_anteriores=before["asignacion"] if before else None,
        datos_nuevos=after["asignacion"] if after else None,
        descripcion="Upsert asignación.",
    )


def delete_asignacion(numero: str) -> bool:
    n = clean_numero_pk(numero)
    if not n:
        return False
    before = get_linea_y_asignacion(n)
    if not before or not before.get("asignacion"):
        return False
    DB.execute("DELETE FROM dbo.asignaciones WHERE numero = ?", (n,))
    DB.commit()
    log_audit(
        "asignaciones",
        n,
        "DELETE",
        CURRENT_USER or "sistema",
        datos_anteriores=before["asignacion"],
        datos_nuevos=None,
        descripcion="Borrado asignación.",
    )
    return True


def get_unique_grupos() -> List[str]:
    rows = DB.fetchall(
        """
        SELECT DISTINCT UPPER(LTRIM(RTRIM(ISNULL(grupo,'')))) AS grupo
        FROM dbo.asignaciones
        WHERE ISNULL(LTRIM(RTRIM(grupo)),'') <> ''
        ORDER BY UPPER(LTRIM(RTRIM(grupo)))
        """
    )
    return [r[0] for r in rows if r and r[0]]


# =============================================================================
# Búsquedas
# =============================================================================

def _normalized_like_sql(expr: str) -> str:
    """
    Genera una expresión SQL que:
    - UPPER
    - TRIM
    - elimina . - _ espacios y NBSP y saltos
    """
    # NBSP, LF, CR, TAB: dejamos como literales Unicode; SQL Server los soporta.
    e = f"UPPER(LTRIM(RTRIM(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(ISNULL({expr},''), '\xa0',''), CHAR(10),''), CHAR(13),''), CHAR(9),''), '.', ''), '-', ''), '_', ''))))"
    # quitar espacios
    e = f"REPLACE({e}, ' ', '')"
    return e


def buscar_valor(numero_a_buscar: Optional[str] = None):
    global LAST_NUMERO_CONTEXT
    if deny_if_not_allowed("buscar_gestionar", "Buscar/Gestionar"):
        return
    if deny_if_not_admin("Buscar/Gestionar"):
        return

    valor_raw = entry.get().strip() if numero_a_buscar is None else (numero_a_buscar or "").strip()
    if not valor_raw:
        showerror_centered("Error", "Ingrese un valor para buscar")
        return

    valor_normalizado = clean_invisibles(valor_raw).upper()
    valor_normalizado = re.sub(r"[.\-_\s]+", "", valor_normalizado)
    valor_normalizado = valor_normalizado.replace("\xa0", "")
    search_term = f"%{valor_normalizado}%"

    try:
        cols = [
            "l.numero","l.sim","l.pin1","l.pin2","l.puk1","l.puk2","l.extension_vpn","l.cif","l.cuenta",
            "l.cod_origen","l.flg_pendiente_pinpuk","l.txt_notas",
            "a.empleado","a.email","a.grupo","a.device_name","a.device_model",
            "a.cambio_telefono","a.motivo_cambio","a.historial_cambios","a.is_generic","a.responsable"
        ]
        where_exprs = [
            _normalized_like_sql("l.numero"),
            _normalized_like_sql("l.sim"),
            _normalized_like_sql("l.extension_vpn"),
            _normalized_like_sql("l.cif"),
            _normalized_like_sql("l.cuenta"),
            _normalized_like_sql("l.txt_notas"),
            _normalized_like_sql("a.empleado"),
            _normalized_like_sql("a.email"),
            _normalized_like_sql("a.grupo"),
            _normalized_like_sql("a.device_name"),
            _normalized_like_sql("a.device_model"),
            _normalized_like_sql("a.responsable"),
        ]
        where_sql = " OR ".join([f"{w} LIKE ?" for w in where_exprs])

        query = f"""
        SELECT {", ".join(cols)}
        FROM dbo.lineas l
        LEFT JOIN dbo.asignaciones a ON l.numero = a.numero
        WHERE {where_sql}
        """

        params = (search_term,) * len(where_exprs)
        resultados = DB.fetchall(query, params)

        if not resultados:
            # sugerir alta manual
            if askyesno_centered("No encontrado", f"No se encontró '{valor_raw}'. ¿Quieres dar de alta la línea manualmente?"):
                alta_manual_linea(prefill_numero=valor_raw)
            return

        # Múltiples resultados: resumen
        if len(resultados) > 1:
            LAST_NUMERO_CONTEXT = None
            all_info = f"🔎 {len(resultados)} RESULTADOS PARA '{valor_raw}':\n"
            all_info += "Modo 'Gestionar' deshabilitado para múltiples resultados. Sea más específico para gestionar un solo número.\n\n"
            all_info += "=" * 70 + "\n\n"
            for res in resultados[:200]:
                numero = res[0]
                empleado = res[12] or ""
                device_model = res[16] or ""
                origen = res[9] or ""
                pend = "PEND_PINPUK" if bool(res[10]) else ""
                all_info += f"📱 {numero}  |  👤 {empleado}  |  📦 {device_model}  |  {origen} {pend}\n"
            if len(resultados) > 200:
                all_info += f"\n... ({len(resultados)-200} más)\n"
            _set_text(all_info)
            return

        # Un solo resultado: mostrar detalle y fijar contexto
        res = resultados[0]
        numero = res[0]
        LAST_NUMERO_CONTEXT = numero

        info = _format_record(res)
        _set_text(info)

        # Habilitar acciones contextuales
        _refresh_context_labels()

    except Exception as e:
        logging.exception(f"Error buscar_valor: {e}")
        showerror_centered("Error", f"Error en la búsqueda: {e}")


def consulta_rapida(numero_a_buscar: Optional[str] = None):
    global LAST_NUMERO_CONTEXT
    if deny_if_not_allowed("consulta_rapida", "Consulta Rápida"):
        return

    valor_raw = entry.get().strip() if numero_a_buscar is None else (numero_a_buscar or "").strip()
    if not valor_raw:
        showerror_centered("Error", "Ingrese un valor para buscar")
        return

    valor_normalizado = clean_invisibles(valor_raw).upper()
    valor_normalizado = re.sub(r"[.\-_\s]+", "", valor_normalizado)
    search_term = f"%{valor_normalizado}%"

    try:
        cols = [
            "l.numero","l.sim","l.pin1","l.pin2","l.puk1","l.puk2","l.extension_vpn","l.cif","l.cuenta",
            "l.cod_origen","l.flg_pendiente_pinpuk","l.txt_notas",
            "a.empleado","a.email","a.grupo","a.device_name","a.device_model",
            "a.cambio_telefono","a.motivo_cambio","a.historial_cambios","a.is_generic","a.responsable"
        ]
        where_exprs = [
            _normalized_like_sql("l.numero"),
            _normalized_like_sql("a.empleado"),
            _normalized_like_sql("a.device_name"),
            _normalized_like_sql("a.device_model"),
        ]
        where_sql = " OR ".join([f"{w} LIKE ?" for w in where_exprs])

        query = f"""
        SELECT {", ".join(cols)}
        FROM dbo.lineas l
        LEFT JOIN dbo.asignaciones a ON l.numero = a.numero
        WHERE {where_sql}
        """
        params = (search_term,) * len(where_exprs)
        resultados = DB.fetchall(query, params)

        if not resultados:
            LAST_NUMERO_CONTEXT = None
            _set_text(f"Sin resultados para '{valor_raw}'.")
            return

        if len(resultados) > 1:
            LAST_NUMERO_CONTEXT = None
            all_info = f"🔎 {len(resultados)} RESULTADOS (consulta rápida) PARA '{valor_raw}':\n\n"
            for res in resultados[:200]:
                all_info += f"📱 {res[0]} | 👤 {res[12] or ''} | 📦 {res[16] or ''}\n"
            if len(resultados) > 200:
                all_info += f"\n... ({len(resultados)-200} más)\n"
            _set_text(all_info)
            return

        res = resultados[0]
        LAST_NUMERO_CONTEXT = res[0]
        _set_text(_format_record(res))
        _refresh_context_labels()

    except Exception as e:
        logging.exception(f"Error consulta_rapida: {e}")
        showerror_centered("Error", f"Error en la consulta: {e}")


def _format_record(res: Tuple[Any, ...]) -> str:
    (
        numero, sim, pin1, pin2, puk1, puk2, extension_vpn, cif, cuenta,
        cod_origen, flg_pendiente, txt_notas,
        empleado, email, grupo, device_name, device_model,
        cambio_telefono, motivo_cambio, historial_cambios, is_generic, responsable
    ) = res

    pend_txt = "✅" if not bool(flg_pendiente) else "⚠️ PENDIENTE PIN/PUK"
    origen_txt = cod_origen or "?"
    generic_txt = "Sí" if bool(is_generic) else "No"

    info = []
    info.append("📌 FICHA DE LÍNEA\n" + "=" * 70)
    info.append(f"📱 Número: {numero}")
    info.append(f"Origen: {origen_txt} | {pend_txt}")
    if txt_notas:
        info.append(f"📝 Notas: {txt_notas}")
    info.append("-" * 70)
    info.append("🔐 PIN/PUK / SIM")
    info.append(f"SIM/ICCID: {sim or ''}")
    info.append(f"PIN1: {pin1 or ''}   PIN2: {pin2 or ''}")
    info.append(f"PUK1: {puk1 or ''}   PUK2: {puk2 or ''}")
    info.append("-" * 70)
    info.append("🏢 Datos de línea")
    info.append(f"Ext/VPN: {extension_vpn or ''}")
    info.append(f"CIF: {cif or ''}   Cuenta: {cuenta or ''}")
    info.append("-" * 70)
    info.append("👤 ASIGNACIÓN")
    if empleado or email or grupo or device_name or device_model or responsable:
        info.append(f"Empleado: {empleado or ''}")
        info.append(f"Email: {email or ''}")
        info.append(f"Grupo: {grupo or ''}")
        info.append(f"Device Name: {device_name or ''}")
        info.append(f"Device Model: {device_model or ''}")
        info.append(f"Genérico: {generic_txt}")
        info.append(f"Responsable: {responsable or ''}")
        info.append(f"Cambio Teléfono: {cambio_telefono or ''}")
        info.append(f"Motivo: {motivo_cambio or ''}")
        if historial_cambios:
            info.append("\n🧾 Historial:")
            info.append(str(historial_cambios))
    else:
        info.append("(Sin asignación)")
    info.append("\n➡️ Acciones disponibles: 'Emparejar/Editar asignación' y 'Editar línea' (botones).")
    return "\n".join(info)


def _set_text(content: str):
    text_box.config(state="normal")
    text_box.delete("1.0", tk.END)
    text_box.insert(tk.END, content)
    text_box.config(state="disabled")


# =============================================================================
# Diálogos
# =============================================================================

class DialogoLogin(tk.Toplevel):
    def __init__(self, parent: tk.Tk):
        super().__init__(parent)
        self.title("Login")
        self.configure(bg=COLOR_PANEL)
        self.resizable(False, False)

        self.success = False
        self.username: Optional[str] = None
        self.role: Optional[str] = None

        ttk.Label(self, text="Usuario", font=FONT_SUBTITLE).grid(row=0, column=0, padx=12, pady=(14, 6), sticky="w")
        self.e_user = ttk.Entry(self, width=28, font=FONT_TEXT)
        self.e_user.grid(row=0, column=1, padx=12, pady=(14, 6))

        ttk.Label(self, text="Contraseña", font=FONT_SUBTITLE).grid(row=1, column=0, padx=12, pady=6, sticky="w")
        self.e_pass = ttk.Entry(self, width=28, font=FONT_TEXT, show="*")
        self.e_pass.grid(row=1, column=1, padx=12, pady=6)

        btns = ttk.Frame(self)
        btns.grid(row=2, column=0, columnspan=2, pady=(12, 14))

        ttk.Button(btns, text="Entrar", command=self._on_ok).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Cancelar", command=self._on_cancel).pack(side=tk.LEFT, padx=6)

        self.bind("<Return>", lambda _e=None: self._on_ok())
        self.bind("<Escape>", lambda _e=None: self._on_cancel())

        center_window(self, 360, 170)
        self.transient(parent)
        self.grab_set()
        self.e_user.focus_set()

    def _on_ok(self):
        u = self.e_user.get().strip()
        p = self.e_pass.get().strip()
        if not u or not p:
            showwarning_centered("Login", "Usuario y contraseña son obligatorios.", parent=self)
            return
        ok, role = authenticate(u, p)
        if not ok:
            showerror_centered("Login", "Credenciales inválidas.", parent=self)
            return
        self.success = True
        self.username = u
        self.role = role
        self.destroy()

    def _on_cancel(self):
        self.success = False
        self.destroy()


class DialogoLinea(tk.Toplevel):
    def __init__(self, parent: tk.Tk, title: str, prefill: Optional[Dict[str, Any]] = None):
        super().__init__(parent)
        self.title(title)
        self.configure(bg=COLOR_PANEL)
        self.resizable(False, False)
        self.result: Optional[Dict[str, Any]] = None

        prefill = prefill or {}
        self.vars: Dict[str, tk.StringVar] = {}
        fields = [
            ("Número", "numero"),
            ("SIM/ICCID", "sim"),
            ("PIN1", "pin1"),
            ("PIN2", "pin2"),
            ("PUK1", "puk1"),
            ("PUK2", "puk2"),
            ("Ext/VPN", "extension_vpn"),
            ("CIF", "cif"),
            ("Cuenta", "cuenta"),
            ("Notas", "txt_notas"),
        ]
        r = 0
        for label, key in fields:
            ttk.Label(self, text=label, font=FONT_TEXT).grid(row=r, column=0, padx=12, pady=6, sticky="w")
            var = tk.StringVar(value=str(prefill.get(key) or ""))
            self.vars[key] = var
            e = ttk.Entry(self, textvariable=var, width=40, font=FONT_TEXT)
            e.grid(row=r, column=1, padx=12, pady=6)
            r += 1

        self.var_cod_origen = tk.StringVar(value=str(prefill.get("cod_origen") or "manual"))
        self.var_pend = tk.BooleanVar(value=bool(prefill.get("flg_pendiente_pinpuk") or False))
        self.var_keep = tk.BooleanVar(value=bool(prefill.get("flg_no_borrar_por_csv") if prefill.get("flg_no_borrar_por_csv") is not None else True))

        ttk.Label(self, text="Origen", font=FONT_TEXT).grid(row=r, column=0, padx=12, pady=6, sticky="w")
        ttk.Combobox(self, textvariable=self.var_cod_origen, values=["manual","csv","vodafone"], width=37, state="readonly").grid(row=r, column=1, padx=12, pady=6, sticky="w")
        r += 1

        ttk.Checkbutton(self, text="Pendiente PIN/PUK", variable=self.var_pend).grid(row=r, column=1, padx=12, pady=4, sticky="w")
        r += 1
        ttk.Checkbutton(self, text="No borrar por CSV (proteger)", variable=self.var_keep).grid(row=r, column=1, padx=12, pady=(0, 10), sticky="w")
        r += 1

        btns = ttk.Frame(self)
        btns.grid(row=r, column=0, columnspan=2, pady=(8, 14))

        ttk.Button(btns, text="✅ Guardar", command=self._on_ok).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="❌ Cancelar", command=self._on_cancel).pack(side=tk.LEFT, padx=6)

        center_window(self, 520, 470)
        self.transient(parent)
        self.grab_set()

    def _on_ok(self):
        numero = clean_numero_pk(self.vars["numero"].get())
        if not numero:
            showerror_centered("Error", "El número es obligatorio.", parent=self)
            return
        self.result = {
            "numero": numero,
            "sim": clean_invisibles(self.vars["sim"].get()) or None,
            "pin1": clean_invisibles(self.vars["pin1"].get()) or None,
            "pin2": clean_invisibles(self.vars["pin2"].get()) or None,
            "puk1": clean_invisibles(self.vars["puk1"].get()) or None,
            "puk2": clean_invisibles(self.vars["puk2"].get()) or None,
            "extension_vpn": clean_invisibles(self.vars["extension_vpn"].get()) or None,
            "cif": clean_invisibles(self.vars["cif"].get()) or None,
            "cuenta": clean_invisibles(self.vars["cuenta"].get()) or None,
            "txt_notas": clean_invisibles(self.vars["txt_notas"].get()) or None,
            "cod_origen": self.var_cod_origen.get() or "manual",
            "flg_pendiente_pinpuk": bool(self.var_pend.get()),
            "flg_no_borrar_por_csv": bool(self.var_keep.get()),
        }
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


class DialogoAsignacion(tk.Toplevel):
    def __init__(self, parent: tk.Tk, numero: str, grupos: List[str], prefill: Optional[Dict[str, Any]] = None):
        super().__init__(parent)
        self.title(f"Emparejar / Editar asignación ({numero})")
        self.configure(bg=COLOR_PANEL)
        self.resizable(False, False)
        self.result: Optional[Dict[str, Any]] = None

        prefill = prefill or {}
        self.vars: Dict[str, tk.StringVar] = {}

        fields = [
            ("Empleado", "empleado"),
            ("Email", "email"),
            ("Grupo", "grupo"),
            ("Device Name", "device_name"),
            ("Device Model", "device_model"),
            ("Responsable", "responsable"),
            ("Motivo cambio", "motivo_cambio"),
        ]
        r = 0
        for label, key in fields:
            ttk.Label(self, text=label, font=FONT_TEXT).grid(row=r, column=0, padx=12, pady=6, sticky="w")
            var = tk.StringVar(value=str(prefill.get(key) or ""))
            self.vars[key] = var
            if key == "grupo":
                cb = ttk.Combobox(self, textvariable=var, values=sorted(set(grupos)), width=37)
                cb.grid(row=r, column=1, padx=12, pady=6, sticky="w")
            else:
                e = ttk.Entry(self, textvariable=var, width=40, font=FONT_TEXT)
                e.grid(row=r, column=1, padx=12, pady=6)
            r += 1

        self.var_generic = tk.BooleanVar(value=bool(prefill.get("is_generic") or False))
        ttk.Checkbutton(self, text="Es genérico", variable=self.var_generic).grid(row=r, column=1, padx=12, pady=4, sticky="w")
        r += 1

        self.var_cambio = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text="Registrar como cambio de teléfono", variable=self.var_cambio).grid(row=r, column=1, padx=12, pady=(0,10), sticky="w")
        r += 1

        btns = ttk.Frame(self)
        btns.grid(row=r, column=0, columnspan=2, pady=(8, 14))
        ttk.Button(btns, text="✅ Guardar", command=self._on_ok).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="❌ Cancelar", command=self._on_cancel).pack(side=tk.LEFT, padx=6)

        center_window(self, 540, 360)
        self.transient(parent)
        self.grab_set()

    def _on_ok(self):
        self.result = {
            "empleado": clean_invisibles(self.vars["empleado"].get()) or None,
            "email": clean_invisibles(self.vars["email"].get()) or None,
            "grupo": clean_invisibles(self.vars["grupo"].get()) or None,
            "device_name": clean_invisibles(self.vars["device_name"].get()) or None,
            "device_model": clean_invisibles(self.vars["device_model"].get()) or None,
            "responsable": clean_invisibles(self.vars["responsable"].get()) or None,
            "motivo_cambio": clean_invisibles(self.vars["motivo_cambio"].get()) or None,
            "is_generic": bool(self.var_generic.get()),
            "cambio_telefono": "Sí" if self.var_cambio.get() else "No",
        }
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


class DialogoPegarCorreo(tk.Toplevel):
    def __init__(self, parent: tk.Tk):
        super().__init__(parent)
        self.title("Pegar correo Vodafone")
        self.configure(bg=COLOR_PANEL)
        self.resizable(True, True)
        self.result: Optional[Dict[str, Any]] = None

        ttk.Label(self, text="Pega aquí el contenido del correo de alta (Vodafone).", font=FONT_TEXT).pack(anchor="w", padx=12, pady=(12, 6))
        self.txt = scrolledtext.ScrolledText(self, height=18, font=FONT_TEXT)
        self.txt.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        btns = ttk.Frame(self)
        btns.pack(pady=(0, 12))
        ttk.Button(btns, text="🔎 Detectar datos", command=self._on_parse).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="❌ Cancelar", command=self._on_cancel).pack(side=tk.LEFT, padx=6)

        center_window(self, 720, 450)
        self.transient(parent)
        self.grab_set()

    def _on_parse(self):
        raw = self.txt.get("1.0", tk.END)
        data = parse_vodafone_email(raw)
        if not data.get("numero"):
            showwarning_centered("Parse", "No pude detectar el número. Revisa el texto (debe contener el MSISDN).", parent=self)
            return
        self.result = data
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


# =============================================================================
# Parse correo Vodafone (heurístico)
# =============================================================================

def parse_vodafone_email(text: str) -> Dict[str, Any]:
    t = text or ""
    t = t.replace("\r", "\n")
    # Extraer posibles números: +34xxxxxxxxx o 9 dígitos, o 11-15 dígitos
    num = None
    m = re.search(r"(\+?\d[\d\s\-]{7,}\d)", t)
    if m:
        num = clean_numero_pk(m.group(1))

    def find_key(keys: List[str]) -> Optional[str]:
        for k in keys:
            # formato: PIN1: 1234, PIN1 1234, PIN1=1234
            pattern = rf"{k}\s*[:=]?\s*([A-Za-z0-9]{{3,}})"
            mm = re.search(pattern, t, flags=re.IGNORECASE)
            if mm:
                return clean_invisibles(mm.group(1))
        return None

    sim = find_key(["ICCID", "SIM", "Nº SIM", "NUMERO SIM", "NÚMERO SIM"])
    pin1 = find_key(["PIN1", "PIN 1", "PIN"])
    pin2 = find_key(["PIN2", "PIN 2"])
    puk1 = find_key(["PUK1", "PUK 1", "PUK"])
    puk2 = find_key(["PUK2", "PUK 2"])

    return {
        "numero": num,
        "sim": sim,
        "pin1": pin1,
        "pin2": pin2,
        "puk1": puk1,
        "puk2": puk2,
        "cod_origen": "vodafone",
        "flg_no_borrar_por_csv": True,
        "flg_pendiente_pinpuk": False if (pin1 or puk1) else True,
        "txt_notas": "Alta importada desde correo Vodafone",
    }


# =============================================================================
# Acciones UI
# =============================================================================

def alta_manual_linea(prefill_numero: Optional[str] = None, prefill: Optional[Dict[str, Any]] = None):
    if deny_if_not_allowed("alta_manual", "Alta manual"):
        return
    base = prefill or {}
    if prefill_numero and not base.get("numero"):
        base["numero"] = prefill_numero
    dlg = DialogoLinea(root, "Alta / Editar línea (manual)", prefill=base)
    root.wait_window(dlg)
    if dlg.result is None:
        return

    try:
        upsert_linea(
            numero=dlg.result["numero"],
            sim=dlg.result.get("sim"),
            pin1=dlg.result.get("pin1"),
            pin2=dlg.result.get("pin2"),
            puk1=dlg.result.get("puk1"),
            puk2=dlg.result.get("puk2"),
            extension_vpn=dlg.result.get("extension_vpn"),
            cif=dlg.result.get("cif"),
            cuenta=dlg.result.get("cuenta"),
            cod_origen=dlg.result.get("cod_origen") or "manual",
            flg_no_borrar_por_csv=bool(dlg.result.get("flg_no_borrar_por_csv")),
            flg_pendiente_pinpuk=bool(dlg.result.get("flg_pendiente_pinpuk")),
            txt_notas=dlg.result.get("txt_notas"),
        )
        showinfo_centered("OK", "Línea guardada correctamente.")
        consulta_rapida(dlg.result["numero"])
    except Exception as e:
        logging.exception(f"Alta manual error: {e}")
        showerror_centered("Error", f"No se pudo guardar la línea: {e}")


def import_email_vodafone():
    if deny_if_not_allowed("import_email", "Importar correo Vodafone"):
        return
    dlg = DialogoPegarCorreo(root)
    root.wait_window(dlg)
    if dlg.result is None:
        return
    # Abrir alta manual con prefill ya parseado
    alta_manual_linea(prefill=dlg.result)


def editar_ficha_contexto():
    if deny_if_not_allowed("editar_ficha", "Editar ficha"):
        return
    if not LAST_NUMERO_CONTEXT:
        n = askstring_centered("Editar ficha", "Introduce el número a editar (si no has buscado antes):")
        if not n:
            return
        numero = clean_numero_pk(n)
    else:
        numero = LAST_NUMERO_CONTEXT

    data = get_linea_y_asignacion(numero)
    if not data:
        showwarning_centered("Editar", f"No existe la línea {numero}. Puedes darla de alta manual.")
        if askyesno_centered("Alta manual", "¿Quieres dar de alta la línea ahora?"):
            alta_manual_linea(prefill_numero=numero)
        return

    dlg = DialogoLinea(root, f"Editar línea ({numero})", prefill=data["linea"])
    root.wait_window(dlg)
    if dlg.result is None:
        return
    try:
        update_linea_fields(numero, {
            "sim": dlg.result.get("sim"),
            "pin1": dlg.result.get("pin1"),
            "pin2": dlg.result.get("pin2"),
            "puk1": dlg.result.get("puk1"),
            "puk2": dlg.result.get("puk2"),
            "extension_vpn": dlg.result.get("extension_vpn"),
            "cif": dlg.result.get("cif"),
            "cuenta": dlg.result.get("cuenta"),
            "txt_notas": dlg.result.get("txt_notas"),
            "cod_origen": dlg.result.get("cod_origen"),
            "flg_no_borrar_por_csv": bool(dlg.result.get("flg_no_borrar_por_csv")),
            "flg_pendiente_pinpuk": bool(dlg.result.get("flg_pendiente_pinpuk")),
        })
        showinfo_centered("OK", "Línea actualizada.")
        consulta_rapida(numero)
    except Exception as e:
        logging.exception(e)
        showerror_centered("Error", f"No se pudo actualizar: {e}")


def emparejar_contexto():
    if deny_if_not_allowed("emparejar", "Emparejar/Editar asignación"):
        return
    if not LAST_NUMERO_CONTEXT:
        n = askstring_centered("Emparejar", "Introduce el número a emparejar (si no has buscado antes):")
        if not n:
            return
        numero = clean_numero_pk(n)
    else:
        numero = LAST_NUMERO_CONTEXT

    data = get_linea_y_asignacion(numero)
    prefill_asg = data["asignacion"] if data else None
    grupos = get_unique_grupos()
    dlg = DialogoAsignacion(root, numero, grupos, prefill=prefill_asg or {})
    root.wait_window(dlg)
    if dlg.result is None:
        return
    try:
        upsert_asignacion(numero, dlg.result, registrar_historial=True)
        showinfo_centered("OK", "Asignación guardada.")
        consulta_rapida(numero)
    except Exception as e:
        logging.exception(e)
        showerror_centered("Error", f"No se pudo guardar asignación: {e}")


def borrar_asignacion():
    if deny_if_not_allowed("borrar_asignacion", "Borrar Asignación"):
        return
    if deny_if_not_admin("Borrar Asignación"):
        return
    numero_raw = askstring_centered("Borrar asignación", "Introduce el número de teléfono cuya asignación quieres borrar:")
    if not numero_raw:
        return
    numero = clean_numero_pk(numero_raw)
    data = get_linea_y_asignacion(numero)
    if not data or not data.get("asignacion"):
        showwarning_centered("No encontrado", f"No hay asignación para {numero}.")
        return
    empleado = (data["asignacion"] or {}).get("empleado") or ""
    if not askyesno_centered("Confirmar borrado", f"¿Borrar asignación del número {numero}?\nEmpleado: {empleado}"):
        return
    try:
        ok = delete_asignacion(numero)
        if ok:
            _set_text(f"Asignación del número {numero} eliminada.")
            showinfo_centered("OK", "Asignación eliminada.")
        else:
            showwarning_centered("No", "No se pudo borrar (no existía).")
    except Exception as e:
        logging.exception(e)
        showerror_centered("Error", f"Error borrando asignación: {e}")


def contar_por_cif():
    if deny_if_not_allowed("buscar_por_empresa", "Por Empresa (CIF)"):
        return
    cif = askstring_centered("Por empresa", "Introduce CIF:")
    if not cif:
        return
    cif = clean_invisibles(cif).upper()
    rows = DB.fetchall(
        """
        SELECT l.cif, COUNT(1) AS n
        FROM dbo.lineas l
        WHERE UPPER(LTRIM(RTRIM(ISNULL(l.cif,'')))) = ?
        GROUP BY l.cif
        """,
        (cif,),
    )
    if not rows:
        _set_text(f"No hay líneas para CIF {cif}.")
        return
    total = rows[0][1]
    _set_text(f"CIF {cif}: {total} líneas.")


def buscar_por_departamento():
    if deny_if_not_allowed("buscar_por_departamento", "Por Departamento"):
        return
    dept = askstring_centered("Por departamento", "Introduce (parte de) grupo/departamento:")
    if not dept:
        return
    term = f"%{clean_invisibles(dept).upper()}%"
    rows = DB.fetchall(
        """
        SELECT TOP (500)
            a.grupo, l.numero, a.empleado, a.device_model
        FROM dbo.asignaciones a
        JOIN dbo.lineas l ON l.numero=a.numero
        WHERE UPPER(LTRIM(RTRIM(ISNULL(a.grupo,'')))) LIKE ?
        ORDER BY a.grupo, a.empleado
        """,
        (term,),
    )
    if not rows:
        _set_text("Sin resultados.")
        return
    out = [f"Resultados para '{dept}':\n" + "="*70]
    for g,n,e,dm in rows:
        out.append(f"[{g}] {n} | {e or ''} | {dm or ''}")
    _set_text("\n".join(out))


def buscar_por_responsable():
    if deny_if_not_allowed("buscar_por_responsable", "Por Responsable"):
        return
    resp = askstring_centered("Por responsable", "Introduce (parte de) responsable:")
    if not resp:
        return
    term = f"%{clean_invisibles(resp).upper()}%"
    rows = DB.fetchall(
        """
        SELECT TOP (500)
            a.responsable, l.numero, a.empleado, a.device_model
        FROM dbo.asignaciones a
        JOIN dbo.lineas l ON l.numero=a.numero
        WHERE UPPER(LTRIM(RTRIM(ISNULL(a.responsable,'')))) LIKE ?
        ORDER BY a.responsable, a.empleado
        """,
        (term,),
    )
    if not rows:
        _set_text("Sin resultados.")
        return
    out = [f"Resultados para '{resp}':\n" + "="*70]
    for r,n,e,dm in rows:
        out.append(f"[{r}] {n} | {e or ''} | {dm or ''}")
    _set_text("\n".join(out))


def mostrar_estadisticas():
    if deny_if_not_allowed("mostrar_estadisticas", "Estadísticas"):
        return
    # métricas rápidas
    rows = DB.fetchall(
        """
        SELECT
            (SELECT COUNT(1) FROM dbo.lineas) AS total_lineas,
            (SELECT COUNT(1) FROM dbo.asignaciones) AS total_asignaciones,
            (SELECT COUNT(1) FROM dbo.lineas WHERE flg_pendiente_pinpuk = 1) AS pendientes_pinpuk,
            (SELECT COUNT(1) FROM dbo.lineas WHERE cod_origen = 'manual') AS manuales
        """
    )
    total_lineas, total_asg, pend, manuales = rows[0]
    out = []
    out.append("📊 ESTADÍSTICAS\n" + "="*70)
    out.append(f"Total líneas: {total_lineas}")
    out.append(f"Total asignaciones: {total_asg}")
    out.append(f"Pendientes PIN/PUK: {pend}")
    out.append(f"Altas manuales: {manuales}")
    _set_text("\n".join(out))


def mostrar_auditoria():
    if deny_if_not_allowed("mostrar_auditoria", "Ver Auditoría"):
        return
    rows = DB.fetchall(
        """
        SELECT TOP (200)
            fecha, usuario, tabla, registro_id, accion, descripcion
        FROM dbo.auditoria
        ORDER BY fecha DESC
        """
    )
    out = ["🧾 AUDITORÍA (últimos 200)\n" + "="*70]
    for fecha, usuario, tabla, rid, accion, desc in rows:
        out.append(f"{fecha} | {usuario} | {tabla}:{rid} | {accion} | {desc or ''}")
    _set_text("\n".join(out))


# =============================================================================
# Recarga desde CSV (upsert seguro)
# =============================================================================

def reload_data_from_csvs():
    """
    Sincroniza PIN/PUK desde CSVs:
    - Upsert de líneas presentes en CSV (cod_origen='csv'; pending=0; no_borrar_por_csv=0)
    - Por defecto NO borra líneas que no estén en el CSV.
    - Opcional (solo admin): borrar líneas obsoletas que sean puramente CSV y sin asignación.
    """
    if is_admin():
        action_key = "reload_csvs_safe"  # admin lo tiene todo
    else:
        action_key = "reload_csvs_safe"
    if deny_if_not_allowed(action_key, "Recargar CSVs (seguro)"):
        return

    data_dir = APP_DIR
    df = load_pinpuk_sources(data_dir)
    if df.empty:
        showwarning_centered("CSV", f"No se encontraron ficheros {PINPUK_CSV_FILES} en {data_dir}.")
        return

    borrar_obsoletas = False
    if is_admin():
        borrar_obsoletas = askyesno_centered(
            "Recarga CSVs",
            "Modo seguro: se hará UPSERT desde CSV.\n\n"
            "¿Quieres además ELIMINAR líneas obsoletas (solo origen=csv, no protegidas, y sin asignación)?\n"
            "Recomendación: NO salvo que estés seguro."
        )

    try:
        # Preparar staging temp
        DB.execute("IF OBJECT_ID('tempdb..#src_lineas') IS NOT NULL DROP TABLE #src_lineas;")
        DB.execute(
            """
            CREATE TABLE #src_lineas(
                numero NVARCHAR(32) NOT NULL PRIMARY KEY,
                sim NVARCHAR(64) NULL,
                pin1 NVARCHAR(32) NULL,
                pin2 NVARCHAR(32) NULL,
                puk1 NVARCHAR(32) NULL,
                puk2 NVARCHAR(32) NULL,
                extension_vpn NVARCHAR(64) NULL,
                cif NVARCHAR(32) NULL,
                cuenta NVARCHAR(32) NULL
            );
            """
        )

        rows = []
        for _, r in df.iterrows():
            rows.append((
                str(r["numero"]),
                r.get("sim") or None,
                r.get("pin1") or None,
                r.get("pin2") or None,
                r.get("puk1") or None,
                r.get("puk2") or None,
                r.get("extension_vpn") or None,
                r.get("cif") or None,
                r.get("cuenta") or None,
            ))
        DB.executemany(
            "INSERT INTO #src_lineas(numero, sim, pin1, pin2, puk1, puk2, extension_vpn, cif, cuenta) VALUES(?,?,?,?,?,?,?,?,?)",
            rows,
            fast=True,
        )

        # MERGE
        DB.execute(
            """
            MERGE dbo.lineas WITH (HOLDLOCK) AS tgt
            USING #src_lineas AS src
            ON tgt.numero = src.numero
            WHEN MATCHED THEN
              UPDATE SET
                sim = COALESCE(src.sim, tgt.sim),
                pin1 = COALESCE(src.pin1, tgt.pin1),
                pin2 = COALESCE(src.pin2, tgt.pin2),
                puk1 = COALESCE(src.puk1, tgt.puk1),
                puk2 = COALESCE(src.puk2, tgt.puk2),
                extension_vpn = COALESCE(src.extension_vpn, tgt.extension_vpn),
                cif = COALESCE(src.cif, tgt.cif),
                cuenta = COALESCE(src.cuenta, tgt.cuenta),
                cod_origen = 'csv',
                flg_no_borrar_por_csv = 0,
                flg_pendiente_pinpuk = 0,
                ts_update_utc = SYSUTCDATETIME()
            WHEN NOT MATCHED THEN
              INSERT (numero, sim, pin1, pin2, puk1, puk2, extension_vpn, cif, cuenta,
                      cod_origen, flg_no_borrar_por_csv, flg_pendiente_pinpuk, txt_notas, ts_alta_utc, ts_update_utc)
              VALUES (src.numero, src.sim, src.pin1, src.pin2, src.puk1, src.puk2, src.extension_vpn, src.cif, src.cuenta,
                      'csv', 0, 0, NULL, SYSUTCDATETIME(), SYSUTCDATETIME());
            """
        )

        deleted = 0
        if borrar_obsoletas:
            # Solo borrar líneas: origen=csv, no protegidas, y que NO estén en src, y sin asignación
            cur = DB.execute(
                """
                ;WITH to_del AS (
                  SELECT l.numero
                  FROM dbo.lineas l
                  LEFT JOIN #src_lineas s ON s.numero = l.numero
                  LEFT JOIN dbo.asignaciones a ON a.numero = l.numero
                  WHERE s.numero IS NULL
                    AND l.cod_origen = 'csv'
                    AND l.flg_no_borrar_por_csv = 0
                    AND a.numero IS NULL
                )
                DELETE l
                FROM dbo.lineas l
                JOIN to_del d ON d.numero = l.numero;
                """
            )
            # rowcount en pyodbc puede ser -1 según driver; tomamos un SELECT COUNT previo
            # Así que lo calculamos:
            row = DB.fetchone(
                """
                SELECT COUNT(1)
                FROM dbo.lineas l
                LEFT JOIN #src_lineas s ON s.numero = l.numero
                LEFT JOIN dbo.asignaciones a ON a.numero = l.numero
                WHERE s.numero IS NULL
                  AND l.cod_origen = 'csv'
                  AND l.flg_no_borrar_por_csv = 0
                  AND a.numero IS NULL
                """
            )
            deleted = int(row[0]) if row else 0

        DB.commit()

        log_audit("lineas", "all", "RELOAD", CURRENT_USER or "sistema",
                  descripcion=f"Recarga CSVs (upsert). Filas CSV: {len(df)}. Eliminadas: {deleted}.")
        showinfo_centered("OK", f"Recarga completada.\nFilas CSV: {len(df)}\nEliminadas: {deleted}")
    except Exception as e:
        DB.rollback()
        logging.exception(e)
        showerror_centered("Error", f"Error recargando CSVs: {e}")


# =============================================================================
# Exportación
# =============================================================================

def export_to_excel(df: pd.DataFrame, path: Path):
    if openpyxl is None:
        raise RuntimeError("Falta openpyxl. Instala: pip install openpyxl")
    df.to_excel(path, index=False)


def menu_exportacion():
    if deny_if_not_allowed("menu_exportacion", "Exportar / Backup"):
        return
    # Exporta tablas a Excel
    out_dir = Path(filedialog.askdirectory(title="Selecciona carpeta destino"))
    if not out_dir:
        return
    try:
        rows_l = DB.fetchall("SELECT * FROM dbo.lineas")
        rows_a = DB.fetchall("SELECT * FROM dbo.asignaciones")
        rows_u = DB.fetchall("SELECT TOP (1000) * FROM dbo.auditoria ORDER BY fecha DESC")

        df_l = pd.DataFrame.from_records(rows_l, columns=[c[0] for c in DB.execute("SELECT TOP 0 * FROM dbo.lineas").description])
        df_a = pd.DataFrame.from_records(rows_a, columns=[c[0] for c in DB.execute("SELECT TOP 0 * FROM dbo.asignaciones").description])
        df_u = pd.DataFrame.from_records(rows_u, columns=[c[0] for c in DB.execute("SELECT TOP 0 * FROM dbo.auditoria").description])

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_to_excel(df_l, out_dir / f"lineas_{ts}.xlsx")
        export_to_excel(df_a, out_dir / f"asignaciones_{ts}.xlsx")
        export_to_excel(df_u, out_dir / f"auditoria_{ts}.xlsx")

        showinfo_centered("OK", f"Exportado en {out_dir}")
    except Exception as e:
        logging.exception(e)
        showerror_centered("Error", f"Error exportando: {e}")


# =============================================================================
# Context label / UI helpers
# =============================================================================

def _refresh_context_labels():
    # Muestra el contexto activo en el título de resultados
    try:
        if LAST_NUMERO_CONTEXT:
            result_label_var.set(f"Resultado de la consulta (contexto: {LAST_NUMERO_CONTEXT})")
        else:
            result_label_var.set("Resultado de la consulta:")
    except Exception:
        pass


def on_closing():
    try:
        DB.conn.close()
    except Exception:
        pass
    root.destroy()


# =============================================================================
# UI setup
# =============================================================================

def build_ui():
    global text_box, entry, result_label_var

    root.title(APP_TITLE)
    root.configure(bg=COLOR_BG)
    root.geometry("1200x760")
    root.minsize(1100, 680)

    # Estilos ttk
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=COLOR_BG, foreground=COLOR_TXT, font=FONT_TEXT)
    style.configure("Panel.TFrame", background=COLOR_PANEL)
    style.configure("TFrame", background=COLOR_PANEL)
    style.configure("TLabel", background=COLOR_PANEL, foreground=COLOR_TXT, font=FONT_TEXT)
    style.configure("TEntry", fieldbackground=COLOR_PANEL, font=FONT_TEXT)
    style.configure("Accent.TButton", background=COLOR_PRIMARY, foreground="white", font=FONT_BUTTON)
    style.map("Accent.TButton", background=[("active", "#1d4ed8")])
    style.configure("Danger.TButton", background=COLOR_DANGER, foreground="white", font=FONT_BUTTON)
    style.map("Danger.TButton", background=[("active", "#b91c1c")])

    wrapper = ttk.Frame(root, style="Panel.TFrame", padding=18)
    wrapper.pack(fill="both", expand=True, padx=14, pady=14)

    ttk.Label(wrapper, text="GESTOR DE LÍNEAS Y DISPOSITIVOS", style="TLabel", font=FONT_TITLE, anchor="center").pack(pady=(0, 5), fill="x")
    ttk.Label(wrapper, text="Gestión corporativa de móviles (PIN/PUK, asignaciones, auditoría)", style="TLabel", font=FONT_TEXT, foreground=COLOR_TXT_SECONDARY, anchor="center").pack(pady=(0, 16), fill="x")

    # Search row
    search_row = ttk.Frame(wrapper, style="Panel.TFrame")
    search_row.pack(fill="x", pady=(0, 12))

    ttk.Label(search_row, text="Buscar:", font=FONT_SUBTITLE, background=COLOR_PANEL, foreground=COLOR_PRIMARY).pack(side=tk.LEFT, padx=(0, 10))
    entry = ttk.Entry(search_row, font=FONT_TEXT, width=50)
    entry.pack(side=tk.LEFT, expand=True, fill="x", padx=(0, 10))
    entry.bind("<Return>", lambda _e=None: buscar_valor())

    ttk.Button(search_row, text="🔍 Buscar/Gestionar", style="Accent.TButton", command=buscar_valor).pack(side=tk.LEFT, padx=(0, 6))
    ttk.Button(search_row, text="⚡ Consulta rápida", command=consulta_rapida).pack(side=tk.LEFT)

    # Buttons grid
    btn_frame = ttk.Frame(wrapper, style="Panel.TFrame")
    btn_frame.pack(fill="x", pady=(0, 8))

    button_padding = {"padx": 6, "pady": 5, "sticky": "ew"}

    btn_empresa = ttk.Button(btn_frame, text="🏢 Por Empresa (CIF)", width=BUTTON_WIDTH, command=contar_por_cif)
    btn_dept = ttk.Button(btn_frame, text="🏷️ Por Departamento", width=BUTTON_WIDTH, command=buscar_por_departamento)
    btn_resp = ttk.Button(btn_frame, text="🧑‍💼 Por Responsable", width=BUTTON_WIDTH, command=buscar_por_responsable)
    btn_stats = ttk.Button(btn_frame, text="📊 Estadísticas", width=BUTTON_WIDTH, command=mostrar_estadisticas)

    btn_export = ttk.Button(btn_frame, text="📤 Exportar / Backup", width=BUTTON_WIDTH, command=menu_exportacion)
    btn_audit = ttk.Button(btn_frame, text="🧾 Ver Auditoría", width=BUTTON_WIDTH, command=mostrar_auditoria)
    btn_delete = ttk.Button(btn_frame, text="🗑️ Borrar Asignación", width=BUTTON_WIDTH, command=borrar_asignacion, style="Danger.TButton")
    btn_reload = ttk.Button(btn_frame, text="🔄 Recargar CSVs (seguro)", width=BUTTON_WIDTH, command=reload_data_from_csvs)

    btn_alta = ttk.Button(btn_frame, text="➕ Alta manual línea", width=BUTTON_WIDTH, command=alta_manual_linea)
    btn_edit = ttk.Button(btn_frame, text="✏️ Editar línea (contexto)", width=BUTTON_WIDTH, command=editar_ficha_contexto)
    btn_pair = ttk.Button(btn_frame, text="🔗 Emparejar/Editar asg (ctx)", width=BUTTON_WIDTH, command=emparejar_contexto)
    btn_mail = ttk.Button(btn_frame, text="📩 Pegar correo Vodafone", width=BUTTON_WIDTH, command=import_email_vodafone)

    # grid 3 filas
    for c in range(4):
        btn_frame.columnconfigure(c, weight=1)

    btn_empresa.grid(row=0, column=0, **button_padding)
    btn_dept.grid(row=0, column=1, **button_padding)
    btn_resp.grid(row=0, column=2, **button_padding)
    btn_stats.grid(row=0, column=3, **button_padding)

    btn_export.grid(row=1, column=0, **button_padding)
    btn_audit.grid(row=1, column=1, **button_padding)
    btn_delete.grid(row=1, column=2, **button_padding)
    btn_reload.grid(row=1, column=3, **button_padding)

    btn_alta.grid(row=2, column=0, **button_padding)
    btn_edit.grid(row=2, column=1, **button_padding)
    btn_pair.grid(row=2, column=2, **button_padding)
    btn_mail.grid(row=2, column=3, **button_padding)

    # Results area
    result_label_var = tk.StringVar(value="Resultado de la consulta:")
    ttk.Label(wrapper, textvariable=result_label_var, style="TLabel", font=FONT_SUBTITLE, foreground=COLOR_PRIMARY).pack(anchor="w", pady=(10, 3))

    text_box = scrolledtext.ScrolledText(wrapper, height=18, font=FONT_TEXT, bd=1, relief=tk.SOLID)
    text_box.pack(fill="both", expand=True)
    text_box.insert(tk.END, "Listo. Busca un número/empleado/dispositivo o da de alta una línea manual.\n")
    text_box.config(state="disabled")

    # Menú
    menubar = tk.Menu(root)
    root.config(menu=menubar)

    file_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Archivo", menu=file_menu)
    file_menu.add_command(label="📤 Exportar / Backup...", command=menu_exportacion)
    file_menu.add_command(label="🔄 Recargar CSVs (seguro)...", command=reload_data_from_csvs)
    file_menu.add_separator()
    file_menu.add_command(label="❌ Salir", command=on_closing)

    line_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Líneas", menu=line_menu)
    line_menu.add_command(label="➕ Alta manual", command=alta_manual_linea)
    line_menu.add_command(label="✏️ Editar línea (contexto)", command=editar_ficha_contexto)
    line_menu.add_command(label="🔗 Emparejar/Editar asignación (contexto)", command=emparejar_contexto)
    line_menu.add_separator()
    line_menu.add_command(label="📩 Pegar correo Vodafone...", command=import_email_vodafone)

    root.protocol("WM_DELETE_WINDOW", on_closing)

    # Permisos UI (deshabilitar botones según rol)
    apply_permissions_ui()


def apply_permissions_ui():
    # Deshabilitar botones/menus depende rol (simple)
    # La seguridad real está en deny_if_not_allowed / deny_if_not_admin
    pass


# =============================================================================
# Main
# =============================================================================

def run_login() -> bool:
    global CURRENT_USER, CURRENT_ROLE
    dlg = DialogoLogin(root)
    root.wait_window(dlg)
    if not dlg.success:
        return False
    CURRENT_USER = dlg.username
    CURRENT_ROLE = dlg.role
    logging.info(f"Login OK: {CURRENT_USER} ({CURRENT_ROLE})")
    return True


def main():
    init_schema_if_needed()
    init_auth()

    build_ui()

    # ocultar mientras login
    root.withdraw()
    if not run_login():
        on_closing()
        return
    root.deiconify()
    entry.focus_set()
    _refresh_context_labels()

    root.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
    main()


