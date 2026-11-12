"""Durable State and Ownership Ledger for Sentinel.

Tracks exact file paths, SHA-256 digests, pre-existing file/symlink backups, and pre-existing
JSON policy snapshots so uninstallation only removes or reverts state that Sentinel
actually created, and never deletes or overwrites administrator-managed files without
a verified, recoverable backup.
"""

import hashlib
import json
import os
import tempfile
from typing import Any, Dict, Optional

DEFAULT_SYSTEM_MANIFEST = "/var/lib/sentinel/ownership_manifest.json"


def resolve_manifest_path(target_path: Optional[str] = None, manifest_path: Optional[str] = None) -> str:
    """Resolve the active ownership manifest path, supporting hermetic temporary directories."""
    if manifest_path:
        return manifest_path
    env_override = os.environ.get("SENTINEL_OWNERSHIP_MANIFEST")
    if env_override:
        return env_override
    if target_path:
        abs_target = os.path.abspath(target_path)
        # When operating inside a temporary test directory (/tmp/...), colocate the ledger
        # inside that root or parent directory so unprivileged tests stay hermetic.
        if abs_target.startswith("/tmp/") or os.geteuid() != 0:
            parent = os.path.dirname(abs_target)
            return os.path.join(parent, ".sentinel_ownership_manifest.json")
    return DEFAULT_SYSTEM_MANIFEST


def compute_file_sha256(filepath: str) -> Optional[str]:
    """Compute SHA-256 hex digest of a regular file."""
    try:
        from core.rust_bridge import compute_file_sha256_rust
        rust_sha = compute_file_sha256_rust(filepath)
        if rust_sha is not None:
            return rust_sha
    except Exception:
        pass

    if not os.path.isfile(filepath) or os.path.islink(filepath):
        return None
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest().lower()
    except OSError:
        return None


def load_ownership_manifest(manifest_path: Optional[str] = None, target_path: Optional[str] = None) -> Dict[str, Any]:
    """Load the ownership manifest JSON or return a fresh structure."""
    resolved = resolve_manifest_path(target_path=target_path, manifest_path=manifest_path)
    default_data: Dict[str, Any] = {"files": {}, "firefox_policies": {}}
    if not os.path.isfile(resolved) or os.path.islink(resolved):
        return default_data
    try:
        with open(resolved, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            if not isinstance(data.get("files"), dict):
                data["files"] = {}
            if not isinstance(data.get("firefox_policies"), dict):
                data["firefox_policies"] = {}
            return data
    except Exception:
        pass
    return default_data


def save_ownership_manifest(
    data: Dict[str, Any],
    manifest_path: Optional[str] = None,
    target_path: Optional[str] = None,
) -> bool:
    """Atomically write the ownership manifest JSON with mode 0600."""
    resolved = resolve_manifest_path(target_path=target_path, manifest_path=manifest_path)
    try:
        parent = os.path.dirname(os.path.abspath(resolved))
        os.makedirs(parent, mode=0o700, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=parent, delete=False, encoding="utf-8") as f_tmp:
            tmp_name = f_tmp.name
            json.dump(data, f_tmp, indent=2, sort_keys=True)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, resolved)
        return True
    except OSError:
        return False


def get_file_ownership_entry(
    target_path: str,
    manifest_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return the recorded ownership entry for target_path, if any."""
    abs_target = os.path.abspath(target_path)
    data = load_ownership_manifest(manifest_path=manifest_path, target_path=abs_target)
    entry = data["files"].get(abs_target)
    return entry if isinstance(entry, dict) else None


def record_installed_file(
    target_path: str,
    installed_sha256: str,
    pre_existing_backup: Optional[str] = None,
    existed_before: Optional[bool] = None,
    was_symlink: bool = False,
    symlink_target: Optional[str] = None,
    manifest_path: Optional[str] = None,
) -> bool:
    """Record that Sentinel installed target_path with installed_sha256."""
    abs_target = os.path.abspath(target_path)
    data = load_ownership_manifest(manifest_path=manifest_path, target_path=abs_target)
    existing_entry = data["files"].get(abs_target, {})
    if not isinstance(existing_entry, dict):
        existing_entry = {}

    # Preserve initial pre-Sentinel state across repeated runs
    if "existed_before" in existing_entry:
        existed_val = bool(existing_entry["existed_before"])
    elif existed_before is not None:
        existed_val = bool(existed_before)
    else:
        existed_val = bool(pre_existing_backup or was_symlink)

    backup_to_keep = existing_entry.get("pre_existing_backup") or pre_existing_backup
    was_sym_keep = existing_entry.get("was_symlink", False) or bool(was_symlink)
    sym_target_keep = existing_entry.get("symlink_target") or symlink_target

    data["files"][abs_target] = {
        "existed_before": existed_val,
        "installed_sha256": installed_sha256.lower(),
        "pre_existing_backup": backup_to_keep,
        "was_symlink": was_sym_keep,
        "symlink_target": sym_target_keep,
    }
    return save_ownership_manifest(data, manifest_path=manifest_path, target_path=abs_target)


def remove_file_ownership_entry(
    target_path: str,
    manifest_path: Optional[str] = None,
) -> None:
    """Remove target_path from the ownership ledger after uninstall/restore."""
    abs_target = os.path.abspath(target_path)
    data = load_ownership_manifest(manifest_path=manifest_path, target_path=abs_target)
    if abs_target in data["files"]:
        data["files"].pop(abs_target, None)
        save_ownership_manifest(data, manifest_path=manifest_path, target_path=abs_target)


def record_firefox_policy_snapshot(
    policy_path: str,
    existed_before: bool,
    prior_policies_dict: Optional[Dict[str, Any]],
    initial_sha256: Optional[str] = None,
    manifest_path: Optional[str] = None,
) -> bool:
    """Record the pre-Sentinel state of a Firefox policies.json file (only on first touch)."""
    abs_path = os.path.abspath(policy_path)
    data = load_ownership_manifest(manifest_path=manifest_path, target_path=abs_path)
    if abs_path not in data["firefox_policies"]:
        data["firefox_policies"][abs_path] = {
            "existed_before": bool(existed_before),
            "initial_sha256": initial_sha256,
            "prior_policies": prior_policies_dict if existed_before else None,
        }
        return save_ownership_manifest(data, manifest_path=manifest_path, target_path=abs_path)
    return True


def get_firefox_policy_snapshot(
    policy_path: str,
    manifest_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve the recorded pre-Sentinel Firefox policy snapshot for policy_path."""
    abs_path = os.path.abspath(policy_path)
    data = load_ownership_manifest(manifest_path=manifest_path, target_path=abs_path)
    snap = data["firefox_policies"].get(abs_path)
    return snap if isinstance(snap, dict) else None


def remove_firefox_policy_snapshot(
    policy_path: str,
    manifest_path: Optional[str] = None,
) -> None:
    """Remove the recorded Firefox policy snapshot for policy_path after revert."""
    abs_path = os.path.abspath(policy_path)
    data = load_ownership_manifest(manifest_path=manifest_path, target_path=abs_path)
    if abs_path in data["firefox_policies"]:
        data["firefox_policies"].pop(abs_path, None)
        save_ownership_manifest(data, manifest_path=manifest_path, target_path=abs_path)
