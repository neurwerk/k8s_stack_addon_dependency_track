"""Initialize local credentials before the client enables external routing."""

import os
from pathlib import Path

from k8s_stack_tooling.api.http import log, request, wait_for_service

COLLECTOR = "sbom-collector"
PERMISSIONS = ("BOM_UPLOAD", "PROJECT_CREATION_UPLOAD", "VIEW_PORTFOLIO")


def login(base: str, username: str, password: str) -> str | None:
    status, token = request(
        f"{base}/api/v1/user/login",
        method="POST",
        form_data=True,
        body={"username": username, "password": password},
    )
    if status == 200 and isinstance(token, str) and token.strip():
        return token.strip()
    return None


def main() -> None:
    base = os.environ["DEPENDENCY_TRACK_URL"].rstrip("/")
    admin = Path("/credentials/adminPassword").read_text().strip()
    collector = Path("/collector/collectorPassword").read_text().strip()
    if min(len(admin), len(collector)) < 32 or admin == collector:
        raise SystemExit("Distinct generated credentials of at least 32 characters required")
    wait_for_service(f"{base}/api/version", timeout=900, prefix="dependency-track")
    token = login(base, "admin", admin)
    if token is None:
        # Only the initial default-password transition is supported here.
        # Existing installations with another password fail rather than being reset.
        status, _ = request(
            f"{base}/api/v1/user/forceChangePassword",
            method="POST",
            form_data=True,
            body={
                "username": "admin",
                "password": "admin",
                "newPassword": admin,
                "confirmPassword": admin,
            },
        )
        if status != 200:
            raise SystemExit("Administrator initialization failed; keep external routing off")
        token = login(base, "admin", admin)
    if token is None:
        raise SystemExit("Administrator credential verification failed")
    headers = {"Authorization": f"Bearer {token}"}
    if login(base, COLLECTOR, collector) is None:
        status, _ = request(
            f"{base}/api/v1/user/managed",
            method="PUT",
            headers=headers,
            body={
                "username": COLLECTOR,
                "fullname": "SBOM Collector",
                "email": "sbom-collector@example.invalid",
                "newPassword": collector,
                "confirmPassword": collector,
                "forcePasswordChange": False,
                "nonExpiryPassword": True,
            },
        )
        if status != 201:
            raise SystemExit(
                f"Collector creation failed (HTTP {status}); existing credentials preserved"
            )
    for permission in PERMISSIONS:
        status, _ = request(
            f"{base}/api/v1/permission/{permission}/user/{COLLECTOR}",
            method="POST",
            headers=headers,
        )
        if status not in (200, 304):
            raise SystemExit("Collector permission assignment failed")
    if login(base, COLLECTOR, collector) is None:
        raise SystemExit("Collector credential verification failed")
    log("Local administrator and scoped collector credentials verified", "dependency-track")
