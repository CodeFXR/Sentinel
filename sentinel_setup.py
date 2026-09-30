"""One-command setup, and the verdict a non-technical user can act on.

`sentinel setup` runs every step in the right order and then says, in plain
language, whether the user's CAC now works and what to do next.

The ordering is not arbitrary:

1. ``diagnose``      -- find out whether the reader works at all. Pointless to
                        configure anything if the card cannot be seen.
2. ``fix-opensc``    -- remove the 26-second hang before anything touches a
                        card, so the first insert does not look like a freeze.
3. ``check``         -- start the daemon if it is down.
4. ``install-certs`` -- the DoD roots, so a browser can validate the site.
5. ``configure-browsers`` -- last, because it needs the roots in place.

Every step is independently reversible and reports its own result. The verdict
is assembled from what was *measured*, not from what was attempted.

On the language: the user is a soldier on their own laptop who wants to reach a
.mil or .gov site, not an administrator. So the verdict avoids `pkcs11`,
`NSS`, `trust anchor` and `pkexec` entirely, and says what to do next instead
of what went wrong internally.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel_backend import Event, Outcome

# Run in this order. Reader first, browsers last.
SETUP_STEPS = ("diagnose", "fix-opensc", "check", "install-certs", "configure-browsers")


@dataclass
class Verdict:
    """Whether the CAC works, in words a user can act on."""

    works: bool
    headline: str
    next_steps: tuple[str, ...]
    problems: tuple[str, ...]

    def render(self) -> str:
        lines = ["", "=" * 60, f"  {self.headline}", "=" * 60, ""]
        if self.next_steps:
            lines.append("  Do this next:")
            lines.append("")
            for step in self.next_steps:
                lines.append(f"    {step}")
            lines.append("")
        if self.problems:
            lines.append("  Still not working? These are the known causes:")
            lines.append("")
            for problem in self.problems:
                lines.append(f"    - {problem}")
            lines.append("")
            lines.append("  Run 'sentinel doctor' to check each one again.")
            lines.append("")
        return "\n".join(lines)


def summarise(
    results: dict[str, Outcome],
    *,
    browsers_running: bool = False,
    dry_run: bool = False,
) -> Verdict:
    """Turn a set of step results into one honest answer.

    A verdict is only "works" when every link in the chain was measured: the
    reader was seen, the daemon was up, the roots were installed, and a browser
    that is not sandboxed was configured. Anything unmeasured is not assumed
    good.
    """
    problems: list[str] = []
    next_steps: list[str] = []

    diagnose = results.get("diagnose")
    check = results.get("check")
    certs = results.get("install-certs")
    browsers = results.get("configure-browsers")

    # 1. Is the hardware path working?
    if diagnose is None or not diagnose.ok:
        if diagnose is not None:
            for finding in diagnose.data.get("findings", []):
                if finding.get("severity") == "problem" and finding.get("fix"):
                    problems.append(f"{finding['title']} -- {finding['fix']}")
        if not problems:
            problems.append(
                "The card reader could not be checked. Install the tools it "
                "asks for and run 'sentinel doctor'."
            )

    # 2. Is the service up?
    if check is not None and not check.ok:
        if check.data.get("missing_tools"):
            missing = ", ".join(check.data["missing_tools"])
            problems.append(
                f"Some required programs are missing ({missing}). Re-run the "
                "installer; it installs them."
            )
        else:
            problems.append("The smart card service (pcscd) is not running.")

    # 3. Are the DoD roots in the trust store?
    if certs is not None and not certs.ok:
        problems.append(
            f"The DoD root certificates were not installed: {certs.detail}. "
            "Run 'sentinel-cli install-certs --dry-run' to see what it would do."
        )

    # 4. Can a browser use the card?
    if browsers is not None and not browsers.ok:
        for guidance in browsers.data.get("guidance", []):
            problems.append(guidance.splitlines()[0] if guidance else browsers.detail)
    if browsers is not None and browsers.data.get("confined"):
        for name in browsers.data["confined"]:
            problems.append(
                f"{name} is sandboxed and cannot use a smart card. Install "
                "Firefox from your distribution's software centre instead of "
                "as a snap or Flatpak."
            )

    # 5. Things that are not failures but are the next thing to do.
    if browsers_running:
        next_steps.append("Close Firefox or Chrome completely, then reopen it.")
    next_steps.append(
        "Go to the .mil or .gov site and choose your CAC when it asks to sign in."
    )
    next_steps.append(
        "If the site does not offer your card, run 'sentinel doctor'."
    )

    works = not problems

    if dry_run:
        # A dry run has changed nothing. Saying "your smart card is ready" here
        # would be the same class of defect as the v1.0.0 green light: a claim
        # about a state that was never created.
        if works:
            headline = ("Nothing has been changed. Everything looks ready to "
                        "configure -- re-run without --dry-run to do it.")
        else:
            headline = ("Nothing has been changed. These would need fixing, "
                        "and are listed below.")
        return Verdict(works, headline, tuple(next_steps), tuple(problems))

    if works:
        headline = "Your smart card is ready. It should now work in your browser."
    elif len(problems) == 1:
        headline = "Almost there. One thing needs fixing."
    else:
        headline = f"{len(problems)} things need fixing. Each is listed below."
    return Verdict(works, headline, tuple(next_steps), tuple(problems))
