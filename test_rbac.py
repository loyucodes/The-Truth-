"""
test_rbac.py — Automated tests for every RBAC rule.

Run with:  python3 test_rbac.py
All tests must pass before deploying.
"""

import os, sys, json, unittest
import tempfile, atexit
_tmpdb = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["TRUTH_DB"] = _tmpdb.name
atexit.register(lambda: os.unlink(_tmpdb.name))   # in-memory DB per test run

import database as db
import auth
from roles import Role, Permission, ROLE_PERMISSIONS, SINGLETON_ROLES, has_permission

db.init_db()

# ── Helpers ────────────────────────────────────────────────────────────

_counter = {}
def make_user(role, suffix=""):
    _counter[role] = _counter.get(role, 0) + 1
    username = f"t_{role[:12]}_{_counter[role]}{suffix}".replace("-","_")[:30]
    email    = f"{username}@bcs.test"
    pw_hash  = auth.hash_password("Password1!")
    uid = db.create_user(username, email, pw_hash, role, username)
    return uid, role


class TestPasswordHashing(unittest.TestCase):
    def test_correct_password(self):
        h = auth.hash_password("SecurePass99!")
        self.assertTrue(auth.verify_password("SecurePass99!", h))

    def test_wrong_password(self):
        h = auth.hash_password("SecurePass99!")
        self.assertFalse(auth.verify_password("WrongPass", h))

    def test_hashes_differ(self):
        h1 = auth.hash_password("same")
        h2 = auth.hash_password("same")
        self.assertNotEqual(h1, h2)  # different salts


class TestPermissionMatrix(unittest.TestCase):

    def test_publishers_have_publish(self):
        publishers = [
            Role.EDITORIAL_ADVISER, Role.EDITOR_IN_CHIEF,
            Role.ASSOC_EDITOR_IN_CHIEF, Role.MANAGING_EDITOR,
            Role.ASSOC_MANAGING_EDITOR,
        ]
        for role in publishers:
            self.assertTrue(
                has_permission(role, Permission.PUBLISH),
                f"{role} should have PUBLISH"
            )

    def test_non_publishers_lack_publish(self):
        non_publishers = [
            Role.NEWS_EDITOR, Role.FEATURES_EDITOR, Role.SPORTS_EDITOR,
            Role.SCI_TECH_EDITOR, Role.LITERARY_EDITOR,
            Role.SENIOR_LAYOUT_ARTIST, Role.JUNIOR_LAYOUT_ARTIST,
            Role.SENIOR_GRAPHIC_ARTIST, Role.JUNIOR_GRAPHIC_ARTIST,
            Role.SENIOR_PHOTOJOURNALIST, Role.JUNIOR_PHOTOJOURNALIST,
            Role.SENIOR_CARTOONIST, Role.JUNIOR_CARTOONIST,
            Role.WRITER, Role.PHOTOJOURNALIST, Role.CARTOONIST, Role.READER,
        ]
        for role in non_publishers:
            self.assertFalse(
                has_permission(role, Permission.PUBLISH),
                f"{role} must NOT have PUBLISH"
            )

    def test_writers_can_submit_drafts(self):
        self.assertTrue(has_permission(Role.WRITER, Permission.SUBMIT_DRAFT))

    def test_readers_cannot_submit(self):
        self.assertFalse(has_permission(Role.READER, Permission.SUBMIT_DRAFT))

    def test_all_roles_can_read(self):
        for role in ROLE_PERMISSIONS:
            self.assertTrue(has_permission(role, Permission.READ),
                            f"{role} must have READ")

    def test_all_roles_can_react(self):
        for role in ROLE_PERMISSIONS:
            self.assertTrue(has_permission(role, Permission.REACT),
                            f"{role} must have REACT")

    def test_manage_users_limited(self):
        managers = [
            Role.EDITORIAL_ADVISER, Role.EDITOR_IN_CHIEF,
            Role.ASSOC_EDITOR_IN_CHIEF, Role.MANAGING_EDITOR,
        ]
        non_managers = [
            Role.ASSOC_MANAGING_EDITOR,   # publish but not manage_users
            Role.NEWS_EDITOR, Role.WRITER, Role.READER,
        ]
        for r in managers:
            self.assertTrue(has_permission(r, Permission.MANAGE_USERS), r)
        for r in non_managers:
            self.assertFalse(has_permission(r, Permission.MANAGE_USERS), r)

    def test_manage_site_only_top_two(self):
        top = [Role.EDITORIAL_ADVISER, Role.EDITOR_IN_CHIEF]
        others = [
            Role.ASSOC_EDITOR_IN_CHIEF, Role.MANAGING_EDITOR,
            Role.ASSOC_MANAGING_EDITOR, Role.NEWS_EDITOR, Role.READER,
        ]
        for r in top:
            self.assertTrue(has_permission(r, Permission.MANAGE_SITE), r)
        for r in others:
            self.assertFalse(has_permission(r, Permission.MANAGE_SITE), r)


class TestSingletonEnforcement(unittest.TestCase):

    def test_singleton_roles_defined(self):
        singletons = [
            Role.EDITORIAL_ADVISER, Role.EDITOR_IN_CHIEF,
            Role.ASSOC_EDITOR_IN_CHIEF, Role.MANAGING_EDITOR,
            Role.ASSOC_MANAGING_EDITOR,
            Role.NEWS_EDITOR, Role.FEATURES_EDITOR, Role.SPORTS_EDITOR,
            Role.SCI_TECH_EDITOR, Role.LITERARY_EDITOR,
            Role.SENIOR_LAYOUT_ARTIST, Role.JUNIOR_LAYOUT_ARTIST,
            Role.SENIOR_GRAPHIC_ARTIST, Role.JUNIOR_GRAPHIC_ARTIST,
            Role.SENIOR_PHOTOJOURNALIST, Role.JUNIOR_PHOTOJOURNALIST,
            Role.SENIOR_CARTOONIST, Role.JUNIOR_CARTOONIST,
        ]
        for role in singletons:
            self.assertIn(role, SINGLETON_ROLES, f"{role} must be a singleton")

    def test_non_singleton_roles(self):
        unlimited = [Role.WRITER, Role.PHOTOJOURNALIST, Role.CARTOONIST, Role.READER]
        for role in unlimited:
            self.assertNotIn(role, SINGLETON_ROLES,
                             f"{role} must NOT be singleton")

    def test_second_singleton_registration_blocked(self):
        # Register first EIC — should succeed
        auth.validate_registration("eic1x", "eic1x@bcs.test", "Password1!", Role.EDITOR_IN_CHIEF)
        db.create_user("eic1x", "eic1x@bcs.test", auth.hash_password("Password1!"),
                       Role.EDITOR_IN_CHIEF)
        # Second EIC — must fail
        with self.assertRaises(auth.RegistrationError) as ctx:
            auth.validate_registration("eic2x", "eic2x@bcs.test", "Password1!", Role.EDITOR_IN_CHIEF)
        self.assertIn("already filled", str(ctx.exception))

    def test_unlimited_writers(self):
        for i in range(5):
            uname = f"writerX{i}"
            auth.validate_registration(uname, f"{uname}@bcs.test", "Password1!", Role.WRITER)
            db.create_user(uname, f"{uname}@bcs.test",
                           auth.hash_password("Password1!"), Role.WRITER)
        # 6th writer must still succeed
        auth.validate_registration("writerX5", "writerX5@bcs.test", "Password1!", Role.WRITER)


class TestRegistrationGuards(unittest.TestCase):

    def test_short_password_rejected(self):
        with self.assertRaises(auth.RegistrationError):
            auth.validate_registration("shortpw", "shortpw@bcs.test", "abc", Role.READER)

    def test_unknown_role_rejected(self):
        with self.assertRaises(auth.RegistrationError):
            auth.validate_registration("u", "u@bcs.test", "Password1!", "supreme_overlord")


class TestTokenLifecycle(unittest.TestCase):

    def setUp(self):
        uid, role = make_user(Role.READER, "_tok")
        self.uid  = uid
        self.role = role

    def test_generate_and_validate(self):
        token = auth.generate_token(self.uid, self.role)
        payload = auth.validate_token(token)
        self.assertEqual(int(payload["sub"]), self.uid)
        self.assertEqual(payload["role"], self.role)

    def test_revoked_token_rejected(self):
        token = auth.generate_token(self.uid, self.role)
        auth.revoke_token(token)
        with self.assertRaises(ValueError):
            auth.validate_token(token)

    def test_tampered_token_rejected(self):
        token = auth.generate_token(self.uid, self.role)
        bad   = token[:-4] + "XXXX"
        with self.assertRaises(ValueError):
            auth.validate_token(bad)


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
