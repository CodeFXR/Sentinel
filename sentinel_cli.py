"""Headless interface to the Sentinel backend.

    sentinel check                 probe the smart-card stack
    sentinel doctor-browser        will this browser offer my card? (read-only)
    sentinel install-certs         install the DoD self-signed roots (needs pkexec)
    sentinel verify-bundle         check the shipped DoD roots against the manifest
    sentinel configure-browsers    register the PKCS#11 module in every NSS database
    sentinel fix-opensc            restrict OpenSC to the PIV/CAC drivers
    sentinel uninstall-certs       remove the trust anchors Sentinel installed
    sentinel all                   run every action in order, unattended

Global options:

    --dry-run       perform every check, print every command, change nothing.
                    This is the only supported way to exercise the privileged
                    paths, and the only way to preview them safely.
    --json          emit machine-readable output instead of a human summary.
    --platform X    override distribution detection ("fedora", "debian",
                    "arch", "suse"). For testing and for support requests.
    --version

Exit status is 0 when every requested action succeeded, 1 otherwise, so this is
usable in a fleet provisioning pipeline.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

import sentinel_browser
import sentinel_platform as platform_mod
import sentinel_setup
from sentinel_backend import Event, Outcome, SentinelBackend
from sentinel_platform import PIP_REQUIREMENTS, TRUST_ANCHOR_NAME

VERSION = "2.2.0"

# Order matters: check the reader before configuring anything, fix the reader
# hang before anything touches a card, and configure browsers after the roots
# are in the trust store. One definition, used by `all` and by `setup`.
ACTIONS = sentinel_setup.SETUP_STEPS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Headless interface to the Sentinel backend.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Every action supports --dry-run. Nothing needs a TTY.",
    )
    parser.add_argument(
        "action",
        choices=("setup", "doctor", "doctor-browser", "all", "uninstall-certs",
                 "verify-bundle", *ACTIONS),
        help=(
            "setup           configure everything in order, say whether it worked\n"
            "doctor          explain, in plain language, why the card is not seen\n"
            "doctor-browser  will my browser actually offer my card? read-only,\n"
            "                and the one to run when setup says green but the\n"
            "                browser still does nothing\n"
            "all             every action, machine-readable summary only\n"
            "verify-bundle   check the shipped DoD roots against the manifest;\n"
            "                read-only and needs no network"
        ),
        metavar="ACTION",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="check and print only; make no changes",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--platform",
        help="override distribution detection: a family (fedora, debian, arch, "
             "suse) or a distro id (ubuntu, zorin, rhel, manjaro, ...). For "
             "testing and for support requests.",
    )
    parser.add_argument(
        "--version", action="version", version=f"sentinel {VERSION}",
    )
    return parser


def resolve_platform(name: str | None) -> platform_mod.Platform:
    """Detect the platform, or build the named one for testing and support.

    Accepts a family key ("debian") or any distro id or alias the detector
    knows ("zorin", "rhel", "manjaro"), so `--platform ubuntu` does what a
    person would expect.
    """
    if name is None:
        return platform_mod.detect()

    key = name if name in platform_mod._FAMILIES else platform_mod._ALIASES.get(name, name)
    if key not in platform_mod._FAMILIES:
        raise SystemExit(
            f"sentinel: unknown platform '{name}'. "
            f"Known: {', '.join(sorted(platform_mod._FAMILIES))}"
        )
    spec = platform_mod._FAMILIES[key]
    return platform_mod.Platform(
        name=spec["name"],
        family=key,
        install_cmd=spec["install_cmd"],
        packages=spec["packages"],
        trust_anchor_dir=spec["trust_anchor_dir"],
        trust_refresh_cmd=spec["trust_refresh_cmd"],
        trust_anchor_name=spec.get("trust_anchor_name", platform_mod.TRUST_ANCHOR_NAME),
        pkcs11_module=platform_mod.find_pkcs11_module(),
    )


def make_logger(verbose: bool) -> logging.Logger:
    """A stderr logger, so stdout stays parseable under --json."""
    logger = logging.getLogger("sentinel")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


async def dispatch(backend: SentinelBackend, action: str, dry_run: bool) -> list:
    if action == "check":
        return [await backend.check_services(_print, dry_run)]
    if action == "install-certs":
        return [await backend.install_certs(_print, dry_run)]
    if action == "verify-bundle":
        return [await backend.verify_bundle(_print, dry_run)]
    if action == "configure-browsers":
        return [await backend.configure_browsers(_print, dry_run)]
    if action == "fix-opensc":
        return [await backend.fix_opensc_conf(_print, dry_run)]
    if action == "diagnose":
        return [await backend.diagnose_reader(_print, dry_run)]
    if action == "diagnose-browser":
        return [await backend.diagnose_browser(_print, dry_run)]
    if action == "uninstall-certs":
        return [await backend.uninstall_certs(_print, dry_run)]
    raise ValueError(action)


async def run_setup(backend: SentinelBackend, dry_run: bool) -> tuple[list, sentinel_setup.Verdict]:
    """Every step in order, then one plain-language answer."""
    results: dict[str, Outcome] = {}
    ordered: list[Outcome] = []
    for action in sentinel_setup.SETUP_STEPS:
        _print(Event("log", f"\n>>> {action}"))
        outcome = (await dispatch(backend, action, dry_run))[0]
        results[action] = outcome
        ordered.append(outcome)
    verdict = sentinel_setup.summarise(
        results,
        browsers_running=bool(platform_mod.browsers_running()),
        dry_run=dry_run,
    )
    return ordered, verdict


_PROMPTED = False


def _print(event: Event) -> None:
    """Render a backend event on stdout.

    `card-prompt` is the headless equivalent of the TUI's modal. It has to be
    surfaced rather than dropped: the backend emits it when no CAC is in the
    reader, and a headless run that swallowed it would report a failure with no
    stated cause. Printed once per run, because the backend reports it for every
    operation that needs a card.
    """
    global _PROMPTED
    if event.kind == "log":
        print(event.payload)
    elif event.kind == "card-prompt" and not _PROMPTED:
        _PROMPTED = True
        print()
        print("  " + "*" * 56)
        print(f"  ACTION NEEDED: {event.payload}.")
        print("  Put your CAC in the reader, then run this command again.")
        print("  " + "*" * 56)
        print()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logger = make_logger(verbose=False)
    platform = resolve_platform(args.platform)
    backend = SentinelBackend(logger, platform=platform)

    if args.action == "setup":
        return _run_setup_mode(backend, args, platform)
    if args.action == "doctor":
        return _run_doctor_mode(backend, args, platform)
    if args.action == "doctor-browser":
        return _run_browser_doctor_mode(backend, args, platform)

    actions = list(ACTIONS) if args.action == "all" else [args.action]

    if args.json:
        # Send console output to stderr so stdout is pure JSON.
        import io
        import contextlib

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            results = asyncio.run(_collect(backend, actions, args.dry_run))
        captured = buffer.getvalue()
        payload = {
            "version": VERSION,
            "platform": platform.name,
            "family": platform.family,
            "dry_run": args.dry_run,
            "trusted_bundle": TRUST_ANCHOR_NAME,
            "results": [r.to_dict() for r in results],
            "ok": all(r.ok for r in results),
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if payload["ok"] else 1

    print(f"Sentinel {VERSION} — {platform.name}")
    if args.dry_run:
        print("DRY RUN: no changes will be made.")
    print()

    results = asyncio.run(_collect(backend, actions, args.dry_run))

    print()
    print("-" * 52)
    for result in results:
        print(f"  {'OK  ' if result.ok else 'FAIL'}  {result.action:20s} {result.detail}")
    failed = [r for r in results if not r.ok]
    if failed:
        print(f"\n{len(failed)} of {len(results)} action(s) failed.")
    return 1 if failed else 0


def _run_doctor_mode(backend, args, platform) -> int:
    """`sentinel doctor`: why is the card not being seen?"""
    print(f"Sentinel {VERSION} — checking your card reader")
    print()
    outcome = asyncio.run(backend.diagnose_reader(_print, args.dry_run))
    print()
    print("=" * 60)
    if outcome.ok:
        print("  Your card reader is working.")
        print("  If your card still does not appear, the problem is further up:")
        print("    sentinel setup")
    else:
        print("  Your card reader needs attention. Each fix is listed above.")
    print("=" * 60)
    if args.json:
        print(json.dumps(outcome.to_dict(), indent=2, sort_keys=True))
    return 0 if outcome.ok else 1


def _run_browser_doctor_mode(backend, args, platform) -> int:
    """`sentinel doctor-browser`: will this browser offer my card?

    The command to run when the setup says green and the browser still does
    nothing. Read-only: no writes, no privileges, no network.
    """
    # Under --json, nothing but the JSON may reach stdout, or a pipeline that
    # pipes this into jq gets a banner and a report in front of the document and
    # fails. The other sub-modes already redirect the human output; this one
    # printed its banner and its findings before appending the JSON, so the
    # documented global --json did not apply here.
    if args.json:
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            outcome = asyncio.run(backend.diagnose_browser(_print, args.dry_run))
        print(json.dumps(outcome.to_dict(), indent=2, sort_keys=True))
        return 0 if outcome.ok else 1

    print(f"Sentinel {VERSION} — will your browser offer your CAC?")
    print()
    outcome = asyncio.run(backend.diagnose_browser(_print, args.dry_run))
    print()
    print("=" * 60)
    if outcome.ok:
        print("  Yes. Your browser should offer your card when a site asks.")
    else:
        print(f"  No — {len(outcome.data.get('problems', []))} thing(s) to fix,")
        print("  listed above in the order they matter.")
    print("=" * 60)
    return 0 if outcome.ok else 1


def _run_setup_mode(backend, args, platform) -> int:
    """`sentinel setup`: do everything, then say whether it worked."""
    print(f"Sentinel {VERSION} — setting up your smart card on {args.platform or platform.name}")
    if args.dry_run:
        print("DRY RUN: no changes will be made.")
    print()

    results, verdict = asyncio.run(run_setup(backend, args.dry_run))
    print(verdict.render())

    if args.json:
        print(json.dumps({
            "version": VERSION,
            "platform": platform.name,
            "dry_run": args.dry_run,
            "works": verdict.works,
            "headline": verdict.headline,
            "next_steps": list(verdict.next_steps),
            "problems": list(verdict.problems),
            "results": [r.to_dict() for r in results],
        }, indent=2, sort_keys=True))

    return 0 if verdict.works else 1


async def _collect(backend, actions, dry_run) -> list:
    results = []
    for action in actions:
        results.extend(await dispatch(backend, action, dry_run))
        print()
    return results


if __name__ == "__main__":
    sys.exit(main())
