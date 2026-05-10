from __future__ import annotations

import json
import secrets
import sqlite3
from datetime import datetime, timedelta
from hashlib import pbkdf2_hmac
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "robot_security.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                user_id INTEGER,
                module TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                parameters TEXT NOT NULL,
                summary TEXT NOT NULL,
                result TEXT NOT NULL,
                files TEXT NOT NULL,
                ai_report TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL,
                organization TEXT NOT NULL,
                bio TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(tasks)").fetchall()]
        if "user_id" not in columns:
            conn.execute("ALTER TABLE tasks ADD COLUMN user_id INTEGER")
        user_columns = [row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "email" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
            conn.execute("UPDATE users SET email = username || '@local.invalid' WHERE email IS NULL OR email = ''")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS profile (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                display_name TEXT NOT NULL,
                role TEXT NOT NULL,
                organization TEXT NOT NULL,
                bio TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        row = conn.execute("SELECT id FROM profile WHERE id = 1").fetchone()
        if row is None:
            now = datetime.utcnow().isoformat()
            conn.execute(
                """
                INSERT INTO profile (id, display_name, role, organization, bio, updated_at)
                VALUES (1, ?, ?, ?, ?, ?)
                """,
                ("安全分析员", "机器人网络安全审计", "Robot Security System", "负责侧信道、载荷与运动时序检测复核。", now),
            )


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _loads(value: Optional[str], fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def create_task(
    task_id: str,
    module: str,
    title: str,
    parameters: Dict[str, Any],
    summary: Dict[str, Any],
    result: Dict[str, Any],
    files: Dict[str, Any],
    status: str = "completed",
    user_id: Optional[int] = None,
) -> None:
    now = datetime.utcnow().isoformat()
    with _connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO tasks
            (id, user_id, module, title, status, created_at, updated_at, parameters, summary, result, files, ai_report)
            VALUES (?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM tasks WHERE id = ?), ?), ?, ?, ?, ?, ?, COALESCE((SELECT ai_report FROM tasks WHERE id = ?), NULL))
            """,
            (
                task_id,
                user_id,
                module,
                title,
                status,
                task_id,
                now,
                now,
                _dumps(parameters),
                _dumps(summary),
                _dumps(result),
                _dumps(files),
                task_id,
            ),
        )


def update_task_report(task_id: str, report: str) -> None:
    now = datetime.utcnow().isoformat()
    with _connect() as conn:
        conn.execute(
            "UPDATE tasks SET ai_report = ?, updated_at = ? WHERE id = ?",
            (report, now, task_id),
        )


def list_tasks(module: Optional[str] = None, user_id: Optional[int] = None) -> List[Dict[str, Any]]:
    init_db()
    sql = "SELECT * FROM tasks"
    params: tuple[Any, ...] = ()
    clauses = []
    values: list[Any] = []
    if module:
        clauses.append("module = ?")
        values.append(module)
    if user_id is not None:
        clauses.append("user_id = ?")
        values.append(user_id)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
        params = tuple(values)
    sql += " ORDER BY created_at DESC"
    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_task_from_row(row, include_result=False) for row in rows]


def get_task(task_id: str, user_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
    init_db()
    with _connect() as conn:
        if user_id is None:
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        else:
            row = conn.execute("SELECT * FROM tasks WHERE id = ? AND user_id = ?", (task_id, user_id)).fetchone()
    return _task_from_row(row, include_result=True) if row else None


def get_profile(user_id: int) -> Dict[str, Any]:
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        stats = conn.execute(
            "SELECT module, COUNT(*) AS count FROM tasks WHERE user_id = ? GROUP BY module",
            (user_id,),
        ).fetchall()
    profile = dict(row)
    profile["task_counts"] = {item["module"]: item["count"] for item in stats}
    profile["total_tasks"] = sum(profile["task_counts"].values())
    return profile


def update_profile(user_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    init_db()
    current = get_profile(user_id)
    next_profile = {
        "display_name": str(payload.get("display_name", current["display_name"])).strip() or current["display_name"],
        "role": str(payload.get("role", current["role"])).strip() or current["role"],
        "organization": str(payload.get("organization", current["organization"])).strip() or current["organization"],
        "bio": str(payload.get("bio", current["bio"])).strip() or current["bio"],
    }
    now = datetime.utcnow().isoformat()
    with _connect() as conn:
        conn.execute(
            """
            UPDATE users
            SET display_name = ?, role = ?, organization = ?, bio = ?, updated_at = ?
            WHERE id = ?
            """,
            (next_profile["display_name"], next_profile["role"], next_profile["organization"], next_profile["bio"], now, user_id),
        )
    return get_profile(user_id)


def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt, _ = stored.split("$", 1)
    return secrets.compare_digest(hash_password(password, salt), stored)


def create_user(username: str, email: str, password: str, display_name: str) -> Dict[str, Any]:
    init_db()
    now = datetime.utcnow().isoformat()
    with _connect() as conn:
        try:
            cur = conn.execute(
                """
                INSERT INTO users (username, email, password_hash, display_name, role, organization, bio, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (username, email, hash_password(password), display_name or username, "安全分析员", "Robot Security System", "", now, now),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("用户名或邮箱已存在") from exc
        user_id = int(cur.lastrowid)
    return get_user_by_id(user_id)


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None


def get_user_by_login(login: str) -> Optional[Dict[str, Any]]:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (login, login),
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> Dict[str, Any]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    data = dict(row)
    data.pop("password_hash", None)
    return data


def create_session(user_id: int) -> str:
    init_db()
    token = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    expires = now + timedelta(days=7)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, now.isoformat(), expires.isoformat()),
        )
    return token


def get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT users.*
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ? AND sessions.expires_at > ?
            """,
            (token, datetime.utcnow().isoformat()),
        ).fetchone()
    if row is None:
        return None
    data = dict(row)
    data.pop("password_hash", None)
    return data


def delete_session(token: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def _task_from_row(row: sqlite3.Row, include_result: bool) -> Dict[str, Any]:
    data = {
        "id": row["id"],
        "user_id": row["user_id"],
        "module": row["module"],
        "title": row["title"],
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "parameters": _loads(row["parameters"], {}),
        "summary": _loads(row["summary"], {}),
        "files": _loads(row["files"], {}),
        "ai_report": row["ai_report"] or "",
    }
    if include_result:
        data["result"] = _loads(row["result"], {})
    return data
