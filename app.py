"""
app.py — Flask application: all API routes for the TRUTH publication RBAC system.

Routes
------
POST   /api/auth/register        — create account
POST   /api/auth/login           — get token
POST   /api/auth/logout          — revoke token

GET    /api/posts                — list published posts (public)
POST   /api/posts                — create draft        [PUBLISH]
POST   /api/posts/<id>/publish   — publish a draft     [PUBLISH]
POST   /api/posts/<id>/archive   — archive a post      [PUBLISH]
POST   /api/posts/<id>/react     — like / comment      [READ+REACT]

GET    /api/users                — list users           [MANAGE_USERS]
POST   /api/users/<id>/role      — reassign role        [MANAGE_USERS]
POST   /api/users/<id>/deactivate— deactivate account   [MANAGE_USERS]

GET    /api/me                   — current user info    [any authenticated]
GET    /api/roles                — role reference       [public]
"""

import json
import re
import os
from flask import Flask, request, jsonify, g

import database as db
import auth
from roles import (
    Permission, Role, ROLE_PERMISSIONS, ROLE_LABELS,
    SINGLETON_ROLES, PUBLISHER_ROLES, has_permission,
)

app = Flask(__name__)
db.init_db()


# ── Helpers ────────────────────────────────────────────────────────────

def slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "-", text)
    return text[:120]


def ok(data=None, status=200, **kwargs):
    payload = {"ok": True}
    if data is not None:
        payload["data"] = data
    payload.update(kwargs)
    return jsonify(payload), status


def err(message: str, status=400, **kwargs):
    payload = {"ok": False, "error": message}
    payload.update(kwargs)
    return jsonify(payload), status


def get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "")


# ═══════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.post("/api/auth/register")
def register():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    email    = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    role     = (body.get("role") or Role.READER).strip().lower()

    # Only privileged roles can assign non-reader roles during registration.
    # Readers and writers may self-register.
    protected_roles = set(ROLE_PERMISSIONS.keys()) - {Role.READER, Role.WRITER,
                                                       Role.PHOTOJOURNALIST,
                                                       Role.CARTOONIST}
    if role in protected_roles:
        # Must be authenticated as a manager to assign these
        token = request.cookies.get("auth_token") or \
                (request.headers.get("Authorization", "")[7:] or "")
        if token:
            try:
                payload = auth.validate_token(token)
                actor_role = payload.get("role", "")
                if not has_permission(actor_role, Permission.MANAGE_USERS):
                    return err("Only administrators can assign this role.", 403)
            except ValueError:
                return err("Only administrators can assign this role.", 403)
        else:
            return err("Only administrators can assign this role.", 403)

    try:
        auth.validate_registration(username, email, password, role)
    except auth.RegistrationError as e:
        return err(str(e), 409)

    pw_hash = auth.hash_password(password)
    user_id = db.create_user(
        username     = username,
        email        = email,
        password_hash= pw_hash,
        role         = role,
        display_name = body.get("display_name", "").strip(),
    )
    db.audit(None, "register", "user", user_id, json.dumps({"role": role}), get_ip())
    return ok({"user_id": user_id, "role": role, "role_label": ROLE_LABELS[role]}, 201)


@app.post("/api/auth/login")
def login():
    body     = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    user = db.get_user_by_username(username)
    if not user or not auth.verify_password(password, user["password_hash"]):
        return err("Invalid username or password.", 401)
    if not user["is_active"]:
        return err("Account is deactivated. Contact the Editorial Adviser.", 403)

    token = auth.generate_token(
        user_id = user["id"],
        role    = user["role"],
        ip      = get_ip(),
        ua      = request.headers.get("User-Agent", ""),
    )
    db.audit(user["id"], "login", "user", user["id"], "", get_ip())

    resp = ok({
        "token":      token,
        "user_id":    user["id"],
        "username":   user["username"],
        "role":       user["role"],
        "role_label": ROLE_LABELS.get(user["role"], user["role"]),
        "can_publish": has_permission(user["role"], Permission.PUBLISH),
        "permissions": sorted(ROLE_PERMISSIONS.get(user["role"], set())),
    })
    # Set cookie for browser clients too
    response = app.make_response(resp)
    response.set_cookie("auth_token", token, httponly=True,
                        samesite="Strict", max_age=3600 * 12)
    return response


@app.post("/api/auth/logout")
@auth.login_required
def logout():
    auth.revoke_token(g.token)
    db.audit(g.user_id, "logout", "user", g.user_id, "", get_ip())
    resp = ok({"message": "Logged out successfully."})
    response = app.make_response(resp)
    response.delete_cookie("auth_token")
    return response


# ═══════════════════════════════════════════════════════════════════════
# CURRENT USER
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/me")
@auth.login_required
def me():
    user = db.get_user_by_id(g.user_id)
    if not user:
        return err("User not found.", 404)
    role = user["role"]
    return ok({
        "id":           user["id"],
        "username":     user["username"],
        "email":        user["email"],
        "display_name": user["display_name"],
        "role":         role,
        "role_label":   ROLE_LABELS.get(role, role),
        "permissions":  sorted(ROLE_PERMISSIONS.get(role, set())),
        "can_publish":  has_permission(role, Permission.PUBLISH),
        "can_manage":   has_permission(role, Permission.MANAGE_USERS),
    })


# ═══════════════════════════════════════════════════════════════════════
# POST ROUTES
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/posts")
def list_posts():
    """Public endpoint — returns published posts, optionally filtered by category."""
    category = request.args.get("category")
    posts = db.list_posts(status="published", category=category)
    return ok([dict(p) for p in posts])


@app.post("/api/posts")
@auth.login_required
@auth.permission_required(Permission.PUBLISH)
def create_post():
    """
    Create a new draft post.
    RESTRICTED TO: editorial_adviser, editor_in_chief, assoc_editor_in_chief,
                   managing_editor, assoc_managing_editor
    """
    body     = request.get_json(silent=True) or {}
    title    = (body.get("title") or "").strip()
    content  = (body.get("body") or "").strip()
    category = (body.get("category") or "news").strip()

    if not title:
        return err("'title' is required.")
    if category not in ("latest_broadcast","news","sports","sci_tech","feature","literature"):
        return err("Invalid category.")

    slug = slugify(title)
    # ensure slug uniqueness
    base_slug, n = slug, 1
    while True:
        try:
            post_id = db.create_post(title, slug, content, category, g.user_id)
            break
        except Exception:
            slug = f"{base_slug}-{n}"
            n += 1
            if n > 20:
                return err("Could not generate a unique slug.", 500)

    db.audit(g.user_id, "create_post", "post", post_id,
             json.dumps({"title": title, "category": category}), get_ip())
    return ok({"post_id": post_id, "slug": slug, "status": "draft"}, 201)


@app.post("/api/posts/<int:post_id>/publish")
@auth.login_required
@auth.permission_required(Permission.PUBLISH)
def publish_post(post_id: int):
    """
    Publish a draft.
    RESTRICTED TO: publisher roles only — enforced by @permission_required(PUBLISH).
    """
    post = db.get_post(post_id)
    if not post:
        return err("Post not found.", 404)
    if post["status"] == "published":
        return err("Post is already published.")
    if post["status"] == "archived":
        return err("Archived posts cannot be published directly.")

    db.publish_post(post_id, g.user_id)
    db.audit(g.user_id, "publish_post", "post", post_id, "", get_ip())
    return ok({"post_id": post_id, "status": "published"})


@app.post("/api/posts/<int:post_id>/archive")
@auth.login_required
@auth.permission_required(Permission.PUBLISH)
def archive_post(post_id: int):
    post = db.get_post(post_id)
    if not post:
        return err("Post not found.", 404)
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE posts SET status='archived', updated_at=datetime('now') WHERE id=?",
            (post_id,)
        )
    db.audit(g.user_id, "archive_post", "post", post_id, "", get_ip())
    return ok({"post_id": post_id, "status": "archived"})


@app.post("/api/posts/<int:post_id>/react")
@auth.login_required
def react_to_post(post_id: int):
    """Like or comment on a published post. All authenticated users may react."""
    if not has_permission(g.role, Permission.REACT):
        return err("Your role cannot react to posts.", 403)

    post = db.get_post(post_id)
    if not post or post["status"] != "published":
        return err("Post not found or not published.", 404)

    body    = request.get_json(silent=True) or {}
    rtype   = (body.get("type") or "like").strip()
    content = (body.get("content") or "").strip()

    if rtype not in ("like", "comment"):
        return err("'type' must be 'like' or 'comment'.")
    if rtype == "comment" and not content:
        return err("'content' is required for comments.")

    try:
        with db.get_conn() as conn:
            conn.execute(
                """INSERT INTO post_reactions (post_id,user_id,type,content)
                   VALUES (?,?,?,?)""",
                (post_id, g.user_id, rtype, content or None)
            )
    except Exception:
        if rtype == "like":
            return err("You have already liked this post.")
        raise

    return ok({"post_id": post_id, "reaction": rtype}, 201)


# ═══════════════════════════════════════════════════════════════════════
# USER MANAGEMENT ROUTES  [MANAGE_USERS only]
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/users")
@auth.login_required
@auth.permission_required(Permission.MANAGE_USERS)
def list_users():
    role_filter = request.args.get("role")
    users = db.list_users(role=role_filter)
    return ok([{
        "id":           u["id"],
        "username":     u["username"],
        "email":        u["email"],
        "role":         u["role"],
        "role_label":   ROLE_LABELS.get(u["role"], u["role"]),
        "is_active":    bool(u["is_active"]),
        "created_at":   u["created_at"],
    } for u in users])


@app.post("/api/users/<int:target_id>/role")
@auth.login_required
@auth.permission_required(Permission.MANAGE_USERS)
def assign_role(target_id: int):
    """Reassign a user's role. Enforces singleton limits on the new role."""
    body     = request.get_json(silent=True) or {}
    new_role = (body.get("role") or "").strip().lower()

    if new_role not in ROLE_PERMISSIONS:
        return err(f"Unknown role: '{new_role}'.")

    target = db.get_user_by_id(target_id)
    if not target:
        return err("User not found.", 404)

    old_role = target["role"]

    # Singleton check — exclude current user from count (they're being moved)
    if new_role in SINGLETON_ROLES:
        count_others = 0
        with db.get_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM users WHERE role=? AND is_active=1 AND id!=?",
                (new_role, target_id)
            ).fetchone()
            count_others = row[0]
        if count_others >= 1:
            return err(
                f"Role '{ROLE_LABELS[new_role]}' is already occupied. "
                "Deactivate or reassign the existing holder first.", 409
            )

    db.update_user_role(target_id, new_role)
    db.audit(g.user_id, "assign_role", "user", target_id,
             json.dumps({"from": old_role, "to": new_role}), get_ip())
    return ok({
        "user_id":       target_id,
        "old_role":      old_role,
        "new_role":      new_role,
        "new_role_label": ROLE_LABELS[new_role],
    })


@app.post("/api/users/<int:target_id>/deactivate")
@auth.login_required
@auth.permission_required(Permission.MANAGE_USERS)
def deactivate_user(target_id: int):
    if target_id == g.user_id:
        return err("You cannot deactivate your own account.")
    target = db.get_user_by_id(target_id)
    if not target:
        return err("User not found.", 404)
    db.deactivate_user(target_id)
    db.revoke_all_user_sessions(target_id)
    db.audit(g.user_id, "deactivate_user", "user", target_id, "", get_ip())
    return ok({"user_id": target_id, "deactivated": True})


# ═══════════════════════════════════════════════════════════════════════
# ROLE REFERENCE  [public]
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/roles")
def get_roles():
    return ok({
        "roles": [
            {
                "slug":        slug,
                "label":       ROLE_LABELS[slug],
                "permissions": sorted(perms),
                "can_publish": Permission.PUBLISH in perms,
                "singleton":   slug in SINGLETON_ROLES,
            }
            for slug, perms in ROLE_PERMISSIONS.items()
        ],
        "publisher_roles": sorted(PUBLISHER_ROLES),
    })


# ═══════════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return err("Endpoint not found.", 404)

@app.errorhandler(405)
def method_not_allowed(e):
    return err("Method not allowed.", 405)

@app.errorhandler(500)
def server_error(e):
    return err("Internal server error.", 500)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"\n  the TRUTH — RBAC API  →  http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=True)
