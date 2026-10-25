import json
import threading
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from app import main as main_module
from app.auth import AuthManager
from app.main import ScanMapHandler, ScanMapServer


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ScanMapServer(("127.0.0.1", 0), ScanMapHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, path, method="GET", payload=None, headers=None):
        data = None
        headers = dict(headers or {})
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                body = response.read()
                return response.status, body, response.headers
        except urllib.error.HTTPError as error:
            body = error.read()
            headers = error.headers
            code = error.code
            error.close()
            return code, body, headers

    def test_health(self):
        status, body, _ = self.request("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "ok")

    def test_index_is_served(self):
        status, body, headers = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b"scanmap", body)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")

    def test_static_traversal_blocked(self):
        status, _, _ = self.request("/static/../main.py")
        self.assertEqual(status, 403)

    def test_unknown_route(self):
        status, _, _ = self.request("/nope")
        self.assertEqual(status, 404)

    def test_preview(self):
        status, body, _ = self.request(
            "/api/preview", "POST", {"scanner": "nmap", "params": {"target": "10.0.0.1"}}
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["argv"][0], "nmap")

    def test_preview_rejects_injection(self):
        status, body, _ = self.request(
            "/api/preview", "POST", {"scanner": "nmap", "params": {"target": "10.0.0.1; id"}}
        )
        self.assertEqual(status, 400)
        self.assertIn("error", json.loads(body))

    def test_preview_rejects_unknown_scanner(self):
        status, _, _ = self.request(
            "/api/preview", "POST", {"scanner": "nmap;id", "params": {"target": "10.0.0.1"}}
        )
        self.assertEqual(status, 400)

    def test_bad_json(self):
        request = urllib.request.Request(
            self.base + "/api/preview",
            data=b"{not json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(request, timeout=10)
        self.assertEqual(context.exception.code, 400)
        context.exception.close()

    def test_job_endpoint_reports_missing_binary(self):
        # Neither nmap nor zmap is expected inside the unit-test environment.
        status, body, _ = self.request(
            "/api/jobs", "POST", {"scanner": "nmap", "params": {"target": "127.0.0.1"}}
        )
        self.assertIn(status, (202, 503))
        if status == 503:
            self.assertIn("error", json.loads(body))

    def test_admin_api_requires_admin_and_manages_users(self):
        with tempfile.TemporaryDirectory() as data_dir:
            auth = AuthManager(data_dir)
            admin = auth.create_user("admin-user", "admin-password", is_admin=True)
            ordinary = auth.create_user("ordinary-user", "user-password")
            admin_cookie = {"Cookie": f"scanmap_session={auth.create_session(admin.id)}"}
            user_cookie = {"Cookie": f"scanmap_session={auth.create_session(ordinary.id)}"}

            with (
                patch.object(main_module, "AUTH", auth),
                patch.object(main_module.CONFIG, "auth_required", "true"),
                patch.object(main_module.CONFIG, "user", ""),
                patch.object(main_module.CONFIG, "password", ""),
            ):
                self.assertEqual(self.request("/api/admin/users")[0], 401)
                self.assertEqual(
                    self.request("/api/admin/users", headers=user_cookie)[0], 403
                )
                status, body, _ = self.request(
                    "/api/admin/users", headers=admin_cookie
                )
                self.assertEqual(status, 200)
                self.assertEqual(len(json.loads(body)["users"]), 2)

                status, body, _ = self.request(
                    "/api/admin/users",
                    "POST",
                    {"username": "new-user", "password": "new-password"},
                    admin_cookie,
                )
                self.assertEqual(status, 201)
                new_id = json.loads(body)["user"]["id"]

                status, _, _ = self.request(
                    f"/api/admin/users/{new_id}",
                    "PATCH",
                    {"is_admin": True},
                    admin_cookie,
                )
                self.assertEqual(status, 200)
                status, _, _ = self.request(
                    f"/api/admin/users/{new_id}", "DELETE", headers=admin_cookie
                )
                self.assertEqual(status, 200)

                status, _, _ = self.request(
                    f"/api/admin/users/{admin.id}",
                    "PATCH",
                    {"is_admin": False},
                    admin_cookie,
                )
                self.assertEqual(status, 400)
                status, body, _ = self.request("/admin", headers=admin_cookie)
                self.assertEqual(status, 200)
                self.assertIn(b"User administration", body)

    def test_login_assets_are_available_without_auth(self):
        with (
            patch.object(main_module.CONFIG, "auth_required", "true"),
            patch.object(main_module.CONFIG, "user", ""),
            patch.object(main_module.CONFIG, "password", ""),
        ):
            status, body, _ = self.request("/static/auth.js")
            self.assertEqual(status, 200)
            self.assertIn(b"/api/auth/login", body)
            self.assertEqual(self.request("/static/style.css")[0], 200)

    def test_first_run_setup_creates_and_signs_in_admin(self):
        with tempfile.TemporaryDirectory() as data_dir:
            auth = AuthManager(data_dir)
            with (
                patch.object(main_module, "AUTH", auth),
                patch.object(main_module.CONFIG, "user", ""),
                patch.object(main_module.CONFIG, "password", ""),
            ):
                status, body, _ = self.request("/setup")
                self.assertEqual(status, 200)
                self.assertIn(b"/static/auth.js", body)

                status, _, headers = self.request(
                    "/api/auth/setup",
                    "POST",
                    {"username": "first-admin", "password": "first-password"},
                )
                self.assertEqual(status, 200)
                cookie = headers["Set-Cookie"].split(";", 1)[0]
                status, body, _ = self.request("/api/auth/me", headers={"Cookie": cookie})
                self.assertEqual(status, 200)
                self.assertTrue(json.loads(body)["user"]["is_admin"])
                self.assertEqual(
                    self.request(
                        "/api/auth/setup",
                        "POST",
                        {"username": "other-admin", "password": "other-password"},
                    )[0],
                    403,
                )


if __name__ == "__main__":
    unittest.main()
