"""Test helpers. Every call goes through the real API and real authentication; the helpers only pick the identity.

Api(world) picks it from the path: ingest paths use the City ingest key, lab paths use the vendor admin,
everything else uses City's hospital admin. Pass tenant= or role= to act as someone else. Tests that check
roles spell the identity out with world.session(...) instead.
"""

import os

APP_PASSWORD = os.environ.get("TEST_APP_PASSWORD", "test-app-password-123")  # the soc_app password tests use
PASSWORD = "correct horse battery staple"  # every seeded test user
CITY = "city-hospital"
ORTHO = "ortho-clinic"
LAB_PATHS = ("/api/reset", "/api/demo", "/api/autolabel")


class Api:
    def __init__(self, world, tenant=CITY, role="hospital_admin"):
        self.world = world
        self.client = world.client
        self.tenant = tenant
        self.role = role

    def _headers(self, path, method):
        if method == "POST" and (path == "/api/events" or path.startswith("/api/ingest/")):
            return self.world.ingest(self.tenant)
        if path.split("?")[0] in LAB_PATHS:
            return self.world.vendor()
        return self.world.session(self.tenant, self.role)

    def get(self, path, headers=None):
        return self.client.get(path, headers=headers or self._headers(path, "GET"))

    def post(self, path, json=None, headers=None):
        return self.client.post(path, json=json, headers=headers or self._headers(path, "POST"))


def failed_logins(tenant, ip=None, day="2026-11-25"):
    """Five failed logins from one IP within a minute: enough to raise FAILED_LOGIN_BURST.
    The IP is random unless given, so repeated calls do not de-duplicate into one alert."""
    import random
    ip = ip or f"100.{random.randint(64, 127)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    return [{"ts": f"{day}T10:00:0{i}", "tenant": tenant, "source": "auth", "type": "auth_fail",
             "user": "u", "ip": ip} for i in range(5)]
