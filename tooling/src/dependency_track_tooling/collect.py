"""Prepare immutable scan targets and upload inventories without logging credentials."""

import argparse
import hashlib
import json
import re
import tarfile
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import requests
from kubernetes import client, config

from dependency_track_tooling.bootstrap import COLLECTOR, login

WORK = Path("/work")
STATE = Path("/state")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
IMAGE = re.compile(r"^[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}$")


def save(path: Path, value: object) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def prepare(settings: dict) -> None:
    """The preparation container alone sees repository credentials and Pod metadata."""
    previous = (
        json.loads((STATE / "coverage.json").read_text())
        if (STATE / "coverage.json").exists()
        else {}
    )
    targets: dict[str, dict] = {}
    gaps: list[dict] = []
    fingerprint = hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()
    previous_targets = (
        previous.get("targets", {}) if (previous.get("configuration") == fingerprint) else {}
    )

    def add(kind: str, name: str, version: str, **extra: object) -> tuple[str, bool]:
        identity = hashlib.sha256(f"{kind}:{name}@{version}".encode()).hexdigest()[:24]
        old = previous_targets.get(identity, {})
        cached = old.get("status") == "imported" and (
            time.time() - old.get("importedAt", 0) < 7 * 86400
        )
        targets[identity] = {
            **old,
            "kind": kind,
            "name": name,
            "version": version,
            **extra,
            "status": "cached" if cached else "pending",
        }
        return identity, cached

    images = set(settings.get("images", []))
    if settings.get("discoverRunningImages"):
        config.load_incluster_config()
        with client.ApiClient() as api:
            pods = (
                client.CoreV1Api(api)
                .list_pod_for_all_namespaces(_request_timeout=(5, 60))
                .items
            )
        for pod in pods:
            if pod.status.phase not in ("Running", "Pending"):
                continue
            statuses = [
                *(pod.status.container_statuses or []),
                *(pod.status.init_container_statuses or []),
                *(pod.status.ephemeral_container_statuses or []),
            ]
            for status in statuses:
                image = (status.image_id or "").removeprefix("docker-pullable://")
                if IMAGE.fullmatch(image):
                    images.add(image)
                else:
                    gaps.append(
                        {
                            "kind": "image",
                            "namespace": pod.metadata.namespace,
                            "pod": pod.metadata.name,
                            "container": status.name,
                            "reason": "runtime did not provide a pullable image digest",
                        }
                    )
    image_lines = []
    for image in sorted(images):
        if not IMAGE.fullmatch(image):
            raise ValueError("Images must be registry references pinned by sha256 digest")
        name, digest = image.split("@")
        identity, cached = add("image", name, digest, reference=image)
        if not cached:
            image_lines.append(f"{identity}\t{image}\n")
    (WORK / "images.tsv").write_text("".join(image_lines))

    token_file = Path("/github/token")
    headers = {"Accept": "application/vnd.github+json"}
    if token_file.exists():
        headers["Authorization"] = f"Bearer {token_file.read_text().strip()}"
    repository_targets = []
    for repository in settings.get("repositories", []):
        name, ref = repository["name"], repository.get("ref", "HEAD")
        if not REPOSITORY.fullmatch(name) or not isinstance(ref, str):
            raise ValueError("Repository entries require owner/name and a revision")
        try:
            response = requests.get(
                f"https://api.github.com/repos/{name}/commits/{quote(ref, safe='')}",
                headers=headers,
                timeout=(5, 60),
            )
            response.raise_for_status()
            revision = response.json()["sha"]
            if not re.fullmatch(r"[a-f0-9]{40}", revision):
                raise ValueError("GitHub returned an invalid commit")
            identity, cached = add("repository", name, revision)
            if cached:
                continue
            directory = WORK / "sources" / identity
            directory.mkdir(parents=True, exist_ok=True)
            # requests strips Authorization on cross-host redirects to codeload.
            with (
                requests.get(
                    f"https://api.github.com/repos/{name}/tarball/{revision}",
                    headers=headers,
                    timeout=(5, 120),
                    stream=True,
                ) as archive,
                tempfile.TemporaryFile() as temporary,
            ):
                archive.raise_for_status()
                size = 0
                for chunk in archive.iter_content(1024 * 1024):
                    size += len(chunk)
                    if size > 256 * 1024 * 1024:
                        raise ValueError("Source archive exceeds the collection size limit")
                    temporary.write(chunk)
                temporary.seek(0)
                with tarfile.open(fileobj=temporary, mode="r:gz") as tar:
                    members = tar.getmembers()
                    if sum(m.size for m in members) > 1024 * 1024 * 1024:
                        raise ValueError("Expanded source exceeds the collection size limit")
                    # Python's data filter prevents traversal and out-of-tree symlinks.
                    tar.extractall(directory, members=members, filter="data")
            repository_targets.append({"id": identity, "path": str(directory)})
        except (requests.RequestException, ValueError, KeyError, tarfile.TarError, OSError):
            gaps.append(
                {"kind": "repository", "name": name, "reason": "source preparation failed"}
            )
    save(WORK / "repositories.json", repository_targets)
    save(
        WORK / "inventory.json",
        {
            "generatedAt": datetime.now(UTC).isoformat(),
            "configuration": fingerprint,
            "targets": targets,
            "gaps": gaps,
            "osVulnerabilityCoverage": "not yet verified",
        },
    )


def upload(settings: dict) -> None:
    """Only this final container receives the limited collector password."""
    inventory = json.loads((WORK / "inventory.json").read_text())
    base = settings["url"].rstrip("/")
    password = Path("/collector/collectorPassword").read_text().strip()
    token = login(base, COLLECTOR, password)
    if token is None:
        raise ValueError("Collector authentication failed")
    headers = {"Authorization": f"Bearer {token}"}
    failed = bool(inventory["gaps"])
    for identity, target in inventory["targets"].items():
        if target["status"] == "cached":
            target["status"] = "imported"
            continue
        bom_path = WORK / f"{identity}.cdx.json"
        try:
            if (WORK / f"{identity}.failed").exists():
                raise ValueError("Scanner failed")
            if bom_path.stat().st_size > 100 * 1024 * 1024:
                raise ValueError("SBOM exceeds collection size limit")
            bom = json.loads(bom_path.read_text())
            components = bom.get("components", [])
            if bom.get("bomFormat") != "CycloneDX" or not components:
                raise ValueError("No components detected; coverage cannot be established")
            target["components"] = len(components)
            target["missingVersions"] = sum(not c.get("version") for c in components)
            target["missingLicenses"] = sum(not c.get("licenses") for c in components)
            target["missingPackageUrls"] = sum(not c.get("purl") for c in components)
            target["coverage"] = (
                "detected image packages; bundled components may be missing"
                if target["kind"] == "image"
                else "source inventory without installation; resolution may be incomplete"
            )
            project = f"{target['kind']}:{target['name']}"
            started = time.time()
            with bom_path.open("rb") as stream:
                response = requests.post(
                    f"{base}/api/v1/bom",
                    headers=headers,
                    data={
                        "autoCreate": "true",
                        "projectName": project,
                        "projectVersion": target["version"],
                    },
                    files={"bom": ("bom.json", stream, "application/json")},
                    timeout=(5, 120),
                )
            response.raise_for_status()
            # Acceptance alone is not proof of a successful asynchronous import.
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                response = requests.get(
                    f"{base}/api/v1/project/lookup",
                    params={"name": project, "version": target["version"]},
                    headers=headers,
                    timeout=(5, 30),
                )
                if response.status_code == 200 and (
                    response.json().get("lastBomImport", 0) >= int(started * 1000)
                ):
                    target.update(status="imported", importedAt=time.time())
                    break
                if response.status_code not in (200, 404):
                    response.raise_for_status()
                time.sleep(5)
            else:
                raise ValueError("Import completion not confirmed")
        except (requests.RequestException, ValueError, KeyError, OSError):
            target["status"] = "failed"
            failed = True
    save(STATE / "coverage.json", inventory)
    counts = {}
    for target in inventory["targets"].values():
        state = target["status"]
        counts[state] = counts.get(state, 0) + 1
    print(json.dumps({"targets": counts, "gaps": len(inventory["gaps"])}))
    if failed:
        raise SystemExit("Collection incomplete; inspect the private coverage report")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["prepare", "upload"])
    parser.add_argument("--config", type=Path, default=Path("/config/collection.json"))
    args = parser.parse_args()
    try:
        settings = json.loads(args.config.read_text())
        (prepare if args.phase == "prepare" else upload)(settings)
    except (ValueError, KeyError, OSError, client.ApiException):
        raise SystemExit("Collection failed; sensitive details suppressed") from None
