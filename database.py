"""
database.py — SQLite schema + all DB helpers for the TRUTH publication RBAC system.

Tables
------
users          — account records with hashed passwords
sessions       — server-side session tokens (JWT-signed)
posts          — articles / broadcast items
post_reactions — likes / comments per post per user
audit_log      — tamper-evident log of sensitive actions
"""

import sqlite3
import os

DB_PATH = os.environ.get("TRUTH_DB", "truth.db")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ─────────────────────────────────────────────────────────────────────
# SCHEMA
# ─────────────────────────────────────────────────────────────────────
SCHEMA = """
-- Users ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'reader',
    display_name  TEXT,
    is_active     INTEGER NOT NULL DEFAULT 1,   -- 0 = deactivated
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now')),

    -- Role must be one of the defined slugs
    CHECK (role IN (
        'editorial_adviser','editor_in_chief','assoc_editor_in_chief',
        'managing_editor','assoc_managing_editor',
        'news_editor','features_editor','sports_editor',
        'sci_tech_editor','literary_editor',
        'senior_layout_artist','junior_layout_artist',
        'senior_graphic_artist','junior_graphic_artist',
        'senior_photojournalist','junior_photojournalist',
        'senior_cartoonist','junior_cartoonist',
        'writer','photojournalist','cartoonist','reader'
    )),
    CHECK (is_active IN (0, 1))
);

-- Index for fast role-based lookups
CREATE INDEX IF NOT EXISTS idx_users_role     ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_active   ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);

-- Sessions ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT    NOT NULL UNIQUE,   -- SHA-256 of the raw JWT
    issued_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT    NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    ip_address TEXT,
    user_agent TEXT,
    CHECK (revoked IN (0,1))
);
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token   ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- Posts ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS posts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT    NOT NULL,
    slug         TEXT    NOT NULL UNIQUE,
    body         TEXT    NOT NULL DEFAULT '',
    category     TEXT    NOT NULL DEFAULT 'news',
    status       TEXT    NOT NULL DEFAULT 'draft',  -- draft | published | archived
    author_id    INTEGER NOT NULL REFERENCES users(id),
    publisher_id INTEGER REFERENCES users(id),      -- who hit publish
    published_at TEXT,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT    NOT NULL DEFAULT (datetime('now')),

    CHECK (status   IN ('draft','published','archived')),
    CHECK (category IN (
        'latest_broadcast','news','sports','sci_tech','feature','literature'
    ))
);
CREATE INDEX IF NOT EXISTS idx_posts_status   ON posts(status);
CREATE INDEX IF NOT EXISTS idx_posts_category ON posts(category);
CREATE INDEX IF NOT EXISTS idx_posts_author   ON posts(author_id);

-- Post reactions (likes / comments) -----------------------------------
CREATE TABLE IF NOT EXISTS post_reactions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id    INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type       TEXT    NOT NULL,   -- 'like' | 'comment'
    content    TEXT,               -- comment body (NULL for likes)
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK (type IN ('like','comment')),
    UNIQUE (post_id, user_id, type)  -- one like per user per post
);
CREATE INDEX IF NOT EXISTS idx_reactions_post ON post_reactions(post_id);

-- Audit log -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id    INTEGER REFERENCES users(id),
    action      TEXT    NOT NULL,   -- e.g. 'publish_post', 'assign_role'
    target_type TEXT,               -- 'post' | 'user'
    target_id   INTEGER,
    detail      TEXT,               -- JSON blob with before/after
    ip_address  TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
"""


def init_db():
    """Create all tables. Safe to call on every startup."""
    with get_conn() as conn:
        conn.executescript(SCHEMA)
    print(f"[DB] Initialised → {DB_PATH}")


# ─────────────────────────────────────────────────────────────────────
# USER QUERIES
# ─────────────────────────────────────────────────────────────────────
def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE id=? AND is_active=1", (user_id,)
        ).fetchone()


def get_user_by_username(username: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username=? AND is_active=1", (username,)
        ).fetchone()


def get_user_by_email(email: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE email=? AND is_active=1", (email,)
        ).fetchone()


def count_users_with_role(role: str) -> int:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role=? AND is_active=1", (role,)
        ).fetchone()
        return row[0]


def create_user(username: str, email: str, password_hash: str,
                role: str, display_name: str = "") -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO users (username, email, password_hash, role, display_name)
               VALUES (?,?,?,?,?)""",
            (username, email, password_hash, role, display_name or username)
        )
        return cur.lastrowid


def update_user_role(user_id: int, new_role: str):
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET role=?, updated_at=datetime('now') WHERE id=?",
            (new_role, user_id)
        )


def deactivate_user(user_id: int):
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET is_active=0, updated_at=datetime('now') WHERE id=?",
            (user_id,)
        )


def list_users(role: str | None = None) -> list[sqlite3.Row]:
    with get_conn() as conn:
        if role:
            return conn.execute(
                "SELECT id,username,email,role,display_name,is_active,created_at "
                "FROM users WHERE role=? ORDER BY created_at", (role,)
            ).fetchall()
        return conn.execute(
            "SELECT id,username,email,role,display_name,is_active,created_at "
            "FROM users ORDER BY role,created_at"
        ).fetchall()


# ─────────────────────────────────────────────────────────────────────
# SESSION QUERIES
# ─────────────────────────────────────────────────────────────────────
def create_session(user_id: int, token_hash: str, expires_at: str,
                   ip: str = "", ua: str = "") -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO sessions (user_id,token_hash,expires_at,ip_address,user_agent)
               VALUES (?,?,?,?,?)""",
            (user_id, token_hash, expires_at, ip, ua)
        )
        return cur.lastrowid


def get_session(token_hash: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            """SELECT s.*, u.role, u.is_active FROM sessions s
               JOIN users u ON u.id = s.user_id
               WHERE s.token_hash=? AND s.revoked=0
                 AND s.expires_at > datetime('now')""",
            (token_hash,)
        ).fetchone()


def revoke_session(token_hash: str):
    with get_conn() as conn:
        conn.execute(
            "UPDATE sessions SET revoked=1 WHERE token_hash=?", (token_hash,)
        )


def revoke_all_user_sessions(user_id: int):
    with get_conn() as conn:
        conn.execute(
            "UPDATE sessions SET revoked=1 WHERE user_id=?", (user_id,)
        )


# ─────────────────────────────────────────────────────────────────────
# POST QUERIES
# ─────────────────────────────────────────────────────────────────────
def create_post(title: str, slug: str, body: str,
                category: str, author_id: int) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO posts (title,slug,body,category,author_id,status)
               VALUES (?,?,?,?,?,'draft')""",
            (title, slug, body, category, author_id)
        )
        return cur.lastrowid


def publish_post(post_id: int, publisher_id: int):
    with get_conn() as conn:
        conn.execute(
            """UPDATE posts SET status='published', publisher_id=?,
               published_at=datetime('now'), updated_at=datetime('now')
               WHERE id=? AND status='draft'""",
            (publisher_id, post_id)
        )


def get_post(post_id: int) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM posts WHERE id=?", (post_id,)
        ).fetchone()


def list_posts(status: str = "published", category: str | None = None):
    with get_conn() as conn:
        if category:
            return conn.execute(
                "SELECT * FROM posts WHERE status=? AND category=? ORDER BY published_at DESC",
                (status, category)
            ).fetchall()
        return conn.execute(
            "SELECT * FROM posts WHERE status=? ORDER BY published_at DESC", (status,)
        ).fetchall()


# ─────────────────────────────────────────────────────────────────────
# AUDIT LOG
# ─────────────────────────────────────────────────────────────────────
def audit(actor_id: int | None, action: str, target_type: str = "",
          target_id: int | None = None, detail: str = "", ip: str = ""):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO audit_log (actor_id,action,target_type,target_id,detail,ip_address)
               VALUES (?,?,?,?,?,?)""",
            (actor_id, action, target_type, target_id, detail, ip)
        )
