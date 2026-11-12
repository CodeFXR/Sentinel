"""Secure Release Update Checker and Archive Verifier for Sentinel.

Enforces fail-closed supply-chain security:
- Transactional release installation and rollback with strict SHA-256 and HTTPS source verification
- Strict HTTPS origin validation (github.com/CodeFXR/Sentinel)
- Strict semantic version tag validation (^v?\\d+\\.\\d+\\.\\d+$)
- Mandatory SHA-256 digest verification before any archive staging
- Tar-slip (CWE-22), hardlink, escaping symlink, and device member rejection during extraction
- Pre-move rollback journaling, post-update health smoke check, and failure-preserving backups
"""

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import re
import ssl
import tarfile
from typing import Callable, Optional, Tuple
import urllib.error
import urllib.request

from core import __version__

GITHUB_API_LATEST_URL = "https://api.github.com/repos/CodeFXR/Sentinel/releases/latest"
ALLOWED_HTML_PREFIX = "https://github.com/CodeFXR/Sentinel/"
ALLOWED_DOWNLOAD_PREFIX = "https://github.com/CodeFXR/Sentinel/releases/download/"
LEGACY_ALLOWED_HTML_PREFIX = "https://github.com/CodeFXR/Sentinel-CAC-Manager/"
LEGACY_ALLOWED_DOWNLOAD_PREFIX = "https://github.com/CodeFXR/Sentinel-CAC-Manager/releases/download/"
SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
BODY_SHA256_RE = re.compile(r"\b([0-9a-fA-F]{64})\s+\*?Sentinel(?:-CAC-Manager)?[^\s]*\.tar\.gz\b", re.IGNORECASE)
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024  # 50 MB ceiling


@dataclass
class UpdateInfo:
    current_version: str
    latest_version: str
    tag_name: str
    update_available: bool
    html_url: str
    download_url: Optional[str]
    expected_sha256: Optional[str]
    status_message: str
    error: Optional[str] = None


def parse_semver(version_str: str) -> Optional[Tuple[int, int, int]]:
    """Parse a strict 'vX.Y.Z' or 'X.Y.Z' version string into a 3-int tuple."""
    if not isinstance(version_str, str):
        return None
    match = SEMVER_RE.match(version_str.strip())
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def is_newer_version(current_ver: str, candidate_ver: str) -> bool:
    """Return True only if candidate_ver is strictly newer than current_ver."""
    cur = parse_semver(current_ver)
    cand = parse_semver(candidate_ver)
    if cur is None or cand is None:
        return False
    return cand > cur


def _extract_sha256_from_release(release_data: dict, archive_name: str) -> Optional[str]:
    """Extract a 64-hex SHA-256 digest for the release tarball from GitHub metadata or body."""
    assets = release_data.get("assets") or []
    for asset in assets:
        if asset.get("name") == archive_name:
            digest = asset.get("digest", "")
            if isinstance(digest, str) and digest.lower().startswith("sha256:"):
                hex_part = digest.split(":", 1)[1].strip().lower()
                if SHA256_RE.match(hex_part):
                    return hex_part

    body = release_data.get("body") or ""
    if isinstance(body, str):
        match = BODY_SHA256_RE.search(body)
        if match:
            return match.group(1).lower()

    return None


def check_for_updates(current_version: str = __version__, timeout: float = 5.0) -> UpdateInfo:
    """Query GitHub Releases API over HTTPS to check if a newer release is available."""
    req = urllib.request.Request(
        GITHUB_API_LATEST_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"Sentinel/{current_version}",
        },
        method="GET",
    )
    ctx = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw_bytes = resp.read(2 * 1024 * 1024)
            data = json.loads(raw_bytes.decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return UpdateInfo(
                current_version=current_version,
                latest_version=current_version,
                tag_name=f"v{current_version}",
                update_available=False,
                html_url=ALLOWED_HTML_PREFIX + "releases",
                download_url=None,
                expected_sha256=None,
                status_message="No published release found on GitHub (HTTP 404)",
                error="HTTP 404",
            )
        return UpdateInfo(
            current_version=current_version,
            latest_version=current_version,
            tag_name=f"v{current_version}",
            update_available=False,
            html_url=ALLOWED_HTML_PREFIX + "releases",
            download_url=None,
            expected_sha256=None,
            status_message=f"Update check failed (HTTP {e.code})",
            error=f"HTTP {e.code}",
        )
    except Exception as e:
        return UpdateInfo(
            current_version=current_version,
            latest_version=current_version,
            tag_name=f"v{current_version}",
            update_available=False,
            html_url=ALLOWED_HTML_PREFIX + "releases",
            download_url=None,
            expected_sha256=None,
            status_message="Offline or unable to reach GitHub Releases",
            error=str(e),
        )

    tag_name = str(data.get("tag_name", "")).strip()
    parsed_latest = parse_semver(tag_name)
    if parsed_latest is None:
        return UpdateInfo(
            current_version=current_version,
            latest_version=current_version,
            tag_name=f"v{current_version}",
            update_available=False,
            html_url=ALLOWED_HTML_PREFIX + "releases",
            download_url=None,
            expected_sha256=None,
            status_message="Rejected malformed release tag from server",
            error="Invalid semver tag",
        )

    latest_ver_str = f"{parsed_latest[0]}.{parsed_latest[1]}.{parsed_latest[2]}"
    html_url = str(data.get("html_url", "")).strip()
    if not (html_url.startswith(ALLOWED_HTML_PREFIX) or html_url.startswith(LEGACY_ALLOWED_HTML_PREFIX)):
        html_url = f"{ALLOWED_HTML_PREFIX}releases/tag/{tag_name}"

    download_url = None
    archive_name = "Sentinel.tar.gz"
    for asset in data.get("assets") or []:
        name = str(asset.get("name", ""))
        url = str(asset.get("browser_download_url", ""))
        valid_dl_prefix = url.startswith(ALLOWED_DOWNLOAD_PREFIX) or url.startswith(LEGACY_ALLOWED_DOWNLOAD_PREFIX)
        if name.endswith(".tar.gz") and any(k in name for k in ("Sentinel", "sentinel")) and valid_dl_prefix:
            download_url = url
            archive_name = name
            break

    expected_sha256 = _extract_sha256_from_release(data, archive_name)
    newer = is_newer_version(current_version, latest_ver_str)

    if newer:
        status_msg = f"Update available: v{latest_ver_str} (current: v{current_version})"
    else:
        status_msg = f"Up to date (v{current_version})"

    return UpdateInfo(
        current_version=current_version,
        latest_version=latest_ver_str,
        tag_name=tag_name if tag_name.startswith("v") else f"v{latest_ver_str}",
        update_available=newer,
        html_url=html_url,
        download_url=download_url,
        expected_sha256=expected_sha256,
        status_message=status_msg,
        error=None,
    )


def safe_extract_tarball(tar_path: str, dest_dir: str) -> Tuple[bool, str]:
    """Safely extract a .tar.gz archive, rejecting path traversal, hardlinks, escaping symlinks, and devices."""
    abs_dest = os.path.abspath(dest_dir)
    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            members = tar.getmembers()
            if not members:
                return False, "Archive is empty."

            for member in members:
                is_dev = bool(member.isdev() or member.isfifo() or member.ischr() or member.isblk())
                try:
                    from core.rust_bridge import validate_tar_member_safety_rust
                    rust_chk = validate_tar_member_safety_rust(
                        member.name,
                        bool(member.islnk()),
                        bool(member.issym()),
                        is_dev,
                        member.linkname or "",
                        int(member.size or 0),
                    )
                    if rust_chk is not None:
                        ok_member, err_member = rust_chk
                        if not ok_member:
                            return False, err_member
                except Exception:
                    pass

                if member.islnk():
                    return False, f"Security policy: Rejected hard link in archive ({member.name})"
                if is_dev:
                    return False, f"Security policy: Rejected special device file in archive ({member.name})"
                if member.name.startswith("/") or ".." in member.name.split("/"):
                    return False, f"Security policy: Rejected path traversal in archive ({member.name})"

                target_path = os.path.abspath(os.path.join(abs_dest, member.name))
                if os.path.commonpath([abs_dest, target_path]) != abs_dest:
                    return False, f"Security policy: Archive member escapes destination ({member.name})"

                if member.issym():
                    linkname = member.linkname or ""
                    if os.path.isabs(linkname) or ".." in linkname.split("/"):
                        return False, f"Security policy: Rejected unsafe symbolic link in archive ({member.name})"
                    link_target = os.path.abspath(os.path.join(os.path.dirname(target_path), linkname))
                    if os.path.commonpath([abs_dest, link_target]) != abs_dest:
                        return False, f"Security policy: Symbolic link escapes destination ({member.name})"

            for member in members:
                if hasattr(tarfile, "data_filter"):
                    tar.extract(member, path=abs_dest, filter="data")
                else:
                    tar.extract(member, path=abs_dest)
        return True, "Archive extracted safely."
    except Exception as e:
        return False, f"Archive extraction failed: {e}"


def verify_and_stage_archive(
    archive_bytes: bytes,
    expected_sha256: str,
    staging_dir: str,
) -> Tuple[bool, str]:
    """Verify SHA-256 digest of archive bytes and extract safely into staging_dir."""
    if not expected_sha256 or not SHA256_RE.match(expected_sha256.strip()):
        return False, "Security policy: Refusing to stage archive without a valid 64-hex SHA-256 digest."

    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        return False, "Security policy: Archive exceeds maximum permitted size."

    try:
        from core.rust_bridge import verify_archive_sha256_rust
        rust_ver = verify_archive_sha256_rust(archive_bytes, expected_sha256.strip(), MAX_ARCHIVE_BYTES)
        if rust_ver is not None:
            ok_sha, msg_sha = rust_ver
            if not ok_sha:
                return False, msg_sha
    except Exception:
        pass

    actual_sha256 = hashlib.sha256(archive_bytes).hexdigest().lower()
    if not hmac.compare_digest(actual_sha256, expected_sha256.strip().lower()):
        return (
            False,
            f"Security policy: SHA-256 digest mismatch! Expected {expected_sha256.lower()}, got {actual_sha256}.",
        )

    tar_path = os.path.join(staging_dir, "release.tar.gz")
    with open(tar_path, "wb") as f:
        f.write(archive_bytes)

    extract_dir = os.path.join(staging_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)
    return safe_extract_tarball(tar_path, extract_dir)


def perform_update(
    update_info: UpdateInfo,
    project_dir: Optional[str] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str]:
    """Apply a cryptographically verified SHA-256 release archive update with transactional rollback.

    Never uses unauthenticated git checkout; strictly requires a 64-hex SHA-256 digest
    and an official HTTPS GitHub release asset URL.
    """
    import shutil
    import tempfile

    def _log(msg: str) -> None:
        if log_fn:
            log_fn(msg)

    if not update_info.update_available:
        return False, f"Already up to date (v{update_info.current_version})."

    if not update_info.expected_sha256 or not SHA256_RE.match(update_info.expected_sha256.strip()):
        msg = (
            "Security policy: Refusing to apply update without a verified 64-hex SHA-256 digest. "
            f"Verify SHA-256 manually from {update_info.html_url} and run './install'."
        )
        _log(f"[UPDATER] {msg}")
        return False, msg

    valid_dl = update_info.download_url and (
        update_info.download_url.startswith(ALLOWED_DOWNLOAD_PREFIX)
        or update_info.download_url.startswith(LEGACY_ALLOWED_DOWNLOAD_PREFIX)
    )
    if not valid_dl:
        msg = "Security policy: Refusing to download update from untrusted or missing asset URL."
        _log(f"[UPDATER] {msg}")
        return False, msg

    target_dir = os.path.abspath(
        project_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    if not os.path.isdir(target_dir) or not os.access(target_dir, os.W_OK):
        msg = (
            f"Installation directory '{target_dir}' requires administrator permissions. "
            f"Run './install' to upgrade to {update_info.tag_name}."
        )
        _log(f"[UPDATER] {msg}")
        return False, msg

    _log(f"[UPDATER] Downloading {update_info.tag_name} from {update_info.download_url}...")
    req = urllib.request.Request(
        update_info.download_url,
        headers={"User-Agent": f"Sentinel/{update_info.current_version}"},
        method="GET",
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=30.0, context=ctx) as resp:
            archive_bytes = resp.read(MAX_ARCHIVE_BYTES + 1)
    except Exception as e:
        msg = f"Failed to download release archive: {e}"
        _log(f"[UPDATER] {msg}")
        return False, msg

    parent_fs_dir = os.path.dirname(target_dir)
    if not os.access(parent_fs_dir, os.W_OK):
        parent_fs_dir = target_dir

    with tempfile.TemporaryDirectory(dir=parent_fs_dir, prefix=".sentinel_stage_") as staging_dir:
        ok_stage, stage_msg = verify_and_stage_archive(
            archive_bytes, update_info.expected_sha256, staging_dir
        )
        if not ok_stage:
            _log(f"[UPDATER] {stage_msg}")
            return False, stage_msg

        extracted_root = os.path.join(staging_dir, "extracted")
        entries = os.listdir(extracted_root)
        if len(entries) == 1 and os.path.isdir(os.path.join(extracted_root, entries[0])):
            source_root = os.path.join(extracted_root, entries[0])
        else:
            source_root = extracted_root

        backup_dir = os.path.join(staging_dir, "rollback_backup")
        os.makedirs(backup_dir, exist_ok=True)
        journal = []
        rollback_errors = []

        try:
            # 1. Check for obsolete files from previous updates
            prior_items_manifest = os.path.join(target_dir, ".sentinel_release_items.json")
            prior_tracked = []
            if os.path.isfile(prior_items_manifest):
                try:
                    with open(prior_items_manifest, "r", encoding="utf-8") as f_pi:
                        prior_tracked = json.load(f_pi)
                except Exception:
                    prior_tracked = []

            new_release_items = [
                i for i in os.listdir(source_root)
                if not i.startswith(".git")
            ]

            # Prune obsolete files tracked in prior updates that are missing in new release
            for obsolete in prior_tracked:
                if obsolete not in new_release_items and not obsolete.startswith(".git"):
                    obs_target = os.path.join(target_dir, obsolete)
                    obs_bak = os.path.join(backup_dir, obsolete)
                    if os.path.exists(obs_target) or os.path.islink(obs_target):
                        entry = {
                            "item": obsolete,
                            "dst": obs_target,
                            "bak": obs_bak,
                            "had_existing": True,
                            "backed_up": False,
                            "installed": False,
                            "was_obsolete_prune": True,
                        }
                        journal.append(entry)
                        shutil.move(obs_target, obs_bak)
                        entry["backed_up"] = True

            # 2. Stage new release items
            for item in new_release_items:
                src_item = os.path.join(source_root, item)
                dst_item = os.path.join(target_dir, item)
                bak_item = os.path.join(backup_dir, item)
                had_existing = os.path.exists(dst_item) or os.path.islink(dst_item)

                entry = {
                    "item": item,
                    "dst": dst_item,
                    "bak": bak_item,
                    "had_existing": had_existing,
                    "backed_up": False,
                    "installed": False,
                    "was_obsolete_prune": False,
                }
                journal.append(entry)

                if had_existing:
                    shutil.move(dst_item, bak_item)
                    entry["backed_up"] = True
                shutil.move(src_item, dst_item)
                entry["installed"] = True

            # 3. Save new release items manifest
            with open(prior_items_manifest, "w", encoding="utf-8") as f_out:
                json.dump(new_release_items, f_out, indent=2)

            # 4. Post-update health smoke check (verifies core package loads and version is intact)
            if os.path.isdir(os.path.join(target_dir, "core")):
                import subprocess
                import sys
                health_check = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        "import sys; sys.path.insert(0, sys.argv[1]); import core; assert hasattr(core, '__version__')",
                        target_dir,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if health_check.returncode != 0:
                    err_out = health_check.stderr.strip() or health_check.stdout.strip()
                    raise RuntimeError(f"Post-update health check failed (code {health_check.returncode}): {err_out}")

        except Exception as e:
            # Perform reverse rollback based on journal
            for entry in reversed(journal):
                dst = entry["dst"]
                bak = entry["bak"]
                try:
                    if entry["installed"]:
                        if os.path.isdir(dst) and not os.path.islink(dst):
                            shutil.rmtree(dst)
                        elif os.path.exists(dst) or os.path.islink(dst):
                            os.remove(dst)
                    if entry["backed_up"] and (os.path.exists(bak) or os.path.islink(bak)):
                        shutil.move(bak, dst)
                except Exception as rollback_err:
                    rollback_errors.append(f"{entry['item']}: {rollback_err}")

            if rollback_errors:
                # Never wipe un-restored backups! Preserve backup directory for manual administrator recovery
                recovery_dir = tempfile.mkdtemp(prefix="sentinel_update_recovery_")
                try:
                    for b_f in os.listdir(backup_dir):
                        src_bf = os.path.join(backup_dir, b_f)
                        dst_bf = os.path.join(recovery_dir, b_f)
                        if os.path.isdir(src_bf):
                            shutil.copytree(src_bf, dst_bf)
                        else:
                            shutil.copy2(src_bf, dst_bf)
                except Exception:
                    pass
                msg = (
                    f"Update staging failed and rollback encountered errors ({'; '.join(rollback_errors)}). "
                    f"Preserved backup state at '{recovery_dir}' for manual recovery. Original error: {e}"
                )
                _log(f"[UPDATER] {msg}")
                return False, msg

            msg = f"Update staging failed and was rolled back cleanly: {e}"
            _log(f"[UPDATER] {msg}")
            return False, msg

    helper_sync_note = " Restart the application to load the updated version."
    sys_helper = "/usr/libexec/sentinel/privileged_helper.py"
    new_helper = os.path.join(target_dir, "core", "privileged_helper.py")
    if os.path.isfile(sys_helper) and os.path.isfile(new_helper):
        try:
            with open(sys_helper, "rb") as f1, open(new_helper, "rb") as f2:
                if hashlib.sha256(f1.read()).digest() != hashlib.sha256(f2.read()).digest():
                    helper_sync_note = (
                        " Run './install' to synchronize the root-owned privileged helper, "
                        "then restart the application."
                    )
        except OSError:
            pass

    success_msg = (
        f"Verified SHA-256 digest and updated to {update_info.tag_name}.{helper_sync_note}"
    )
    _log(f"[UPDATER] {success_msg}")
    return True, success_msg
