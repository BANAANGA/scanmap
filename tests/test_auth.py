import sqlite3
import tempfile
import unittest

from app.auth import AuthManager


class AuthManagerUserAdminTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth = AuthManager(self.temp_dir.name)
        self.admin = self.auth.create_user("admin", "admin-password", is_admin=True)
        self.user = self.auth.create_user("regular", "regular-password")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_list_users_returns_account_metadata(self):
        users = self.auth.list_users()
        self.assertEqual([user.username for user in users], ["admin", "regular"])
        self.assertTrue(users[0].is_admin)
        self.assertFalse(users[1].is_admin)

    def test_role_changes_preserve_last_admin(self):
        with self.assertRaisesRegex(ValueError, "last administrator"):
            self.auth.update_user_role(self.admin.id, False)
        self.assertTrue(self.auth.update_user_role(self.user.id, True))
        self.assertTrue(self.auth.update_user_role(self.admin.id, False))

    def test_delete_revokes_sessions_and_preserves_last_admin(self):
        token = self.auth.create_session(self.user.id)
        self.assertTrue(self.auth.delete_user(self.user.id))
        self.assertIsNone(self.auth.get_user_by_session(token))
        with sqlite3.connect(self.auth.db_path) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM sessions WHERE user_id=?", (self.user.id,)
                ).fetchone()[0],
                0,
            )
        with self.assertRaisesRegex(ValueError, "last administrator"):
            self.auth.delete_user(self.admin.id)

    def test_unknown_users_can_be_updated_or_deleted(self):
        self.assertFalse(self.auth.update_user_role(999, True))
        self.assertFalse(self.auth.delete_user(999))

    def test_initial_admin_can_only_be_created_once(self):
        with tempfile.TemporaryDirectory() as data_dir:
            auth = AuthManager(data_dir)
            created = auth.create_initial_admin("first-admin", "first-password")
            self.assertTrue(created.is_admin)
            with self.assertRaisesRegex(ValueError, "admin already exists"):
                auth.create_initial_admin("second-admin", "second-password")
            self.assertEqual(len(auth.list_users()), 1)


if __name__ == "__main__":
    unittest.main()
