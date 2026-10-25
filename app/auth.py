"""Simple user authentication for scanmap.

Stores users in a SQLite database under the data directory. On first run
with no users, the UI redirects to /setup to create the initial admin.
Passwords are hashed with PBKDF2-HMAC-SHA256 using the stdlib only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any


PBKDF2_ITERATIONS = 390000


@dataclass
class User:
    id: int
    username: str
    is_admin: bool
    created_at: float


class AuthManager:
    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            # Test if writable
            test_file = os.path.join(self.data_dir, ".write_test")
            with open(test_file, "w") as f:
                f.write("test")
            os.remove(test_file)
        except OSError:
            # Fallback for read-only or unwriteable dirs (e.g. CI)
            self.data_dir = os.environ.get("TMPDIR") or "/tmp"
            os.makedirs(self.data_dir, exist_ok=True)
        self.db_path = os.path.join(self.data_dir, "users.db")
        try:
            self._init_db()
        except Exception:
            self.data_dir = os.environ.get("TMPDIR") or "/tmp"
            os.makedirs(self.data_dir, exist_ok=True)
            self.db_path = os.path.join(self.data_dir, "users.db")
            self._init_db()
        self._sessions: dict[str, dict[str, Any]] = {}
        self._session_lock = __import__("threading").Lock()

    def _init_db(self) -> None:
        try:
            con = sqlite3.connect(self.db_path)
            cur = con.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
            con.commit()
            con.close()
        except Exception as e:
            raise RuntimeError(f"Cannot open database at {self.db_path}: {e}") from e

    def has_users(self) -> bool:
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        count = cur.fetchone()[0]
        con.close()
        return count > 0

    def list_users(self) -> list[User]:
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY username")
        users = [
            User(id=row[0], username=row[1], is_admin=bool(row[2]), created_at=row[3])
            for row in cur.fetchall()
        ]
        con.close()
        return users

    def update_user_role(self, user_id: int, is_admin: bool) -> bool:
        con = sqlite3.connect(self.db_path)
        try:
            cur = con.cursor()
            cur.execute("BEGIN IMMEDIATE")
            cur.execute("SELECT is_admin FROM users WHERE id=?", (user_id,))
            row = cur.fetchone()
            if row is None:
                con.rollback()
                return False
            if bool(row[0]) and not is_admin:
                cur.execute("SELECT COUNT(*) FROM users WHERE is_admin=1")
                if cur.fetchone()[0] <= 1:
                    raise ValueError("cannot demote the last administrator")
            cur.execute("UPDATE users SET is_admin=? WHERE id=?", (int(is_admin), user_id))
            con.commit()
            return True
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def delete_user(self, user_id: int) -> bool:
        con = sqlite3.connect(self.db_path)
        try:
            cur = con.cursor()
            cur.execute("BEGIN IMMEDIATE")
            cur.execute("SELECT is_admin FROM users WHERE id=?", (user_id,))
            row = cur.fetchone()
            if row is None:
                con.rollback()
                return False
            if bool(row[0]):
                cur.execute("SELECT COUNT(*) FROM users WHERE is_admin=1")
                if cur.fetchone()[0] <= 1:
                    raise ValueError("cannot delete the last administrator")
            cur.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            cur.execute("DELETE FROM users WHERE id=?", (user_id,))
            con.commit()
            with self._session_lock:
                for token, session in list(self._sessions.items()):
                    if session["user_id"] == user_id:
                        self._sessions.pop(token, None)
            return True
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def _hash_password(self, password: str, salt: bytes | None = None) -> tuple[str, str]:
        if salt is None:
            salt = secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
        return dk.hex(), salt.hex()

    @staticmethod
    def _validate_credentials(username: str, password: str) -> str:
        username = username.strip()
        if not username or len(username) < 3 or len(username) > 32:
            raise ValueError("username must be 3-32 characters")
        if not password or len(password) < 8:
            raise ValueError("password must be at least 8 characters")
        if not all(c.isalnum() or c in "-_" for c in username):
            raise ValueError("username may only contain letters, numbers, hyphens and underscores")
        return username.lower()

    def create_user(self, username: str, password: str, is_admin: bool = False) -> User:
        username = self._validate_credentials(username, password)
        phash, salt = self._hash_password(password)
        created_at = time.time()
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash, salt, is_admin, created_at) VALUES (?,?,?,?,?)",
                (username, phash, salt, 1 if is_admin else 0, created_at),
            )
            con.commit()
            user_id = cur.lastrowid
        except sqlite3.IntegrityError:
            con.close()
            raise ValueError("username already exists")
        con.close()
        return User(id=user_id, username=username, is_admin=is_admin, created_at=created_at)

    def create_initial_admin(self, username: str, password: str) -> User:
        username = self._validate_credentials(username, password)
        phash, salt = self._hash_password(password)
        created_at = time.time()
        con = sqlite3.connect(self.db_path)
        try:
            cur = con.cursor()
            cur.execute("BEGIN IMMEDIATE")
            cur.execute("SELECT COUNT(*) FROM users")
            if cur.fetchone()[0]:
                raise ValueError("admin already exists")
            cur.execute(
                "INSERT INTO users (username, password_hash, salt, is_admin, created_at) VALUES (?,?,?,?,?)",
                (username, phash, salt, 1, created_at),
            )
            user_id = cur.lastrowid
            con.commit()
            return User(id=user_id, username=username, is_admin=True, created_at=created_at)
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def verify_user(self, username: str, password: str) -> User | None:
        username = username.strip().lower()
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT id, username, password_hash, salt, is_admin FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        con.close()
        if not row:
            return None
        user_id, uname, phash, salt_hex, is_admin = row
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
        if not hmac.compare_digest(dk.hex(), phash):
            return None
        return User(id=user_id, username=uname, is_admin=bool(is_admin), created_at=0)

    def create_session(self, user_id: int, ttl_hours: int = 24 * 7) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        expires = now + ttl_hours * 3600
        with self._session_lock:
            self._sessions[token] = {"user_id": user_id, "created_at": now, "last_seen": now, "expires_at": expires}
        # persist
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO sessions (token, user_id, created_at, last_seen, expires_at) VALUES (?,?,?,?,?)",
            (token, user_id, now, now, expires),
        )
        con.commit()
        con.close()
        return token

    def get_user_by_session(self, token: str) -> User | None:
        if not token:
            return None
        now = time.time()
        with self._session_lock:
            sess = self._sessions.get(token)
        if sess and sess["expires_at"] > now:
            with self._session_lock:
                sess["last_seen"] = now
            con = sqlite3.connect(self.db_path)
            cur = con.cursor()
            cur.execute("SELECT id, username, is_admin FROM users WHERE id=?", (sess["user_id"],))
            row = cur.fetchone()
            con.close()
            if row:
                return User(id=row[0], username=row[1], is_admin=bool(row[2]), created_at=0)
        # try db
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("SELECT s.user_id, s.expires_at, u.username, u.is_admin FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?", (token,))
        row = cur.fetchone()
        if row and row[1] > now:
            with self._session_lock:
                self._sessions[token] = {"user_id": row[0], "expires_at": row[1], "last_seen": now}
            con.close()
            return User(id=row[0], username=row[2], is_admin=bool(row[3]), created_at=0)
        con.close()
        return None

    def delete_session(self, token: str) -> None:
        with self._session_lock:
            self._sessions.pop(token, None)
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("DELETE FROM sessions WHERE token=?", (token,))
        con.commit()
        con.close()

    def cleanup_sessions(self) -> None:
        now = time.time()
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        con.commit()
        con.close()
        with self._session_lock:
            expired = [t for t, s in self._sessions.items() if s["expires_at"] < now]
            for t in expired:
                self._sessions.pop(t, None)
