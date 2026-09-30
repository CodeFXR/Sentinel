# Sentinel

**Get your DoD CAC working on your own Linux laptop.**

You installed Linux because you wanted to. Your CAC does not work on it: the
browser has never heard of it, the sites you need to reach will not load
without it, and every guide online assumes you already know what a trust store
is. Sentinel does that part, and then tells you in plain language whether it
worked.

It runs as your normal user and escalates only for the two operations that
genuinely need your password.

```
     ____         __  _          __
    / __/__ ___  / /_(_)__  ___ / /
   _\ \/ -_) _ \/ __/ / _ \/ -_) /
  /___/\__/_//_/\__/_/_//_/\__/_/
```

## Status: v2.1.0

**Tested on Fedora, Debian, Ubuntu, Arch and openSUSE.** Every one of those is
run in a real container on every release: the right trust-store path, the right
refresh command, the right package names, and the PKCS#11 module actually found
where the code says it is.

```
  pass   fedora
  pass   debian
  pass   ubuntu
  pass   arch
  pass   suse
```

That found three real bugs that 181 unit tests had missed, because a mock cannot
tell you whether a directory exists on a distribution it has never seen. See
[Known limitations](#known-limitations) for what a container still cannot prove.

Every privileged operation has a dry-run mode that shows you exactly what it
would do and changes nothing:

```bash
sentinel-cli install-certs --dry-run
```

Run that first. It is the whole point.

## What it does

One command does all of it:

```bash
sentinel setup
```

It works out whether your card reader works, fixes a 26-second freeze it causes
on some issued readers, starts the smart card service, installs the DoD root
certificates, registers your card with your browser, and then tells you whether
your CAC now works — and if not, exactly what to do about it.

If it does not work, ask it why:

```bash
sentinel doctor
```

That answers the question people actually have, which is never "is pcscd
running". It is one of: the reader is not plugged in; a laptop's fingerprint
sensor is holding the card slot; your account cannot open the reader; two
drivers are fighting over it; or your browser is a snap that cannot see your
card at all. Each one comes with the command to fix it.

Under the hood it does five things:

1. **Checks the reader** — is there a reader, can your account use it, is a card
   in it.
2. **Fixes the reader hang** — restricts OpenSC to the PIV/CAC drivers, which
   removes a 26-second freeze on the Broadcom Corp 58200, a standard issued DoD
   reader.
3. **Starts the service** — `pcscd`, if it is not already running.
4. **Installs the DoD roots** — 7 self-signed root certificates into your
   distribution's trust store, so the sites you need will load.
5. **Configures your browser** — registers the card, and warns you if your
   browser is installed in a way that cannot use one.

A **Scan** tab shows card insert and removal as they happen.

## What it does NOT do

Read this before assuming otherwise. Every item was removed in v2.0.0 or never
existed.

- It does **not** validate certificates, check revocation, or report your
  identity. Removed in v2.0.0. The old implementation printed
  `OCSP/CRL Check: PASSED` without performing any revocation check, which is
  worse than no check. It also built its trust store from a certificate
  downloaded over **plaintext HTTP** from a URL inside the card's AIA
  extension, so an on-path attacker controlled the verdict.
- It does **not** manage your PIN, sign PDFs, or export SSH keys. Removed in
  v2.0.0. The PIN *and the PUK* used to be passed as command-line arguments,
  readable by any local user with `ps aux`.
- It does **not** run STIG or SCAP audits. Removed in v2.0.0.
- It does **not** write to `~/.ssh/authorized_keys`. That old feature granted
  inbound SSH to anyone holding the card.
- It does **not** update itself. Ever. An earlier version ran `git fetch` and
  could re-execute itself on every launch; on a compromised or force-pushed
  repository that is silent code execution on a machine holding a CAC. Updating
  is now an explicit `./update`.

## Requirements

| | |
|---|---|
| **OS** | Linux. Fedora/RHEL, Debian/Ubuntu (incl. Mint, Zorin), Arch, openSUSE. All tested in containers. |
| **Python** | 3.10+ (verified 3.10 to 3.13) |
| **Python packages** | `textual`, `distro` — installed by the installer |
| **System packages** | installed by the installer |

There is no `requirements.txt`. The two dependencies are pinned with upper
bounds in `sentinel_platform.py`, and their wheels are **committed in
`vendor/`**, so the installer works with no access to PyPI at all. Every wheel
is pure Python, so the same 2.5 MB works on any machine and any Python 3.10+.
This matters if you are on a unit with a restricted network: the install does
not need the internet.

## Install

```bash
git clone https://github.com/CodeFXR/Sentinel.git
cd Sentinel
./install
```

The installer detects your distribution, installs the system packages with the
right package manager for it, creates a virtual environment, installs the two
Python dependencies, and puts `sentinel`, `snl` and `sentinel-cli` on your
`PATH`. It adds the path to every shell config you have — bash, zsh, fish — not
just the first one it finds, and also links into `/usr/local/bin` when that is
available, so the commands work for root and from scripts too.

Pin a specific version if you want a reproducible install:

```bash
SENTINEL_REF=v2.1.0 ./install
```

Every step is checked. If `pip install` fails you are told; you do not get a
working-looking install that dies on `import textual` at first launch.

## Usage

### Dashboard

Press `enter` to set everything up. `d` explains why your card is not being seen.
The rest is for when you want one part on its own: `c` checks, `i` installs the
certificates, `b` configures the browser, `f` fixes the reader hang, `s` opens
the card monitor, `q` quits. Every button also has a click target.

The sidebar LEDs show live state. Four states, and the distinction matters:

| LED | Meaning |
|---|---|
| ○ grey | not checked, or nothing to report |
| ● green | verified working |
| ⊗ red | failed |
| spinner amber | in progress |

A grey LED means "we did not measure this", never "this is fine".

### From a terminal

```bash
sentinel setup                      # do everything, then say if it worked
sentinel doctor                     # why is my card not being seen?
sentinel-cli install-certs          # just the certificates (asks for your password)
sentinel-cli all --dry-run          # show what would change, change nothing
sentinel-cli all --json             # machine-readable
```

`--dry-run` never claims success it did not achieve: it says "nothing has been
changed" even when everything looks ready. Exit status is 0 only if the
requested actions actually worked.

## What gets installed, exactly

`DoD_Roots.pem` contains **7 self-signed root certificates**, verified at
install time:

```
DoD Root CA 2     DoD Root CA 3     DoD Root CA 4     DoD Root CA 5
ECA Root CA 4     ECA Root CA 5     DoD WCF Root CA 1
```

That is the whole file, 8.6 KB. Sentinel refuses to install anything else: if a
bundle contains a single certificate that is not self-signed, the install aborts
and names it. A trust-anchor directory may contain only roots. An issuing CA
installed as a root is a security defect, not a convenience.

Earlier versions installed 197 entries covering 69 unique certificates, of which
only these 7 were roots. The other 62 were DoD issuing CAs, WCF intermediates
and cross-certificates, all promoted to roots of trust. If you ran one of those
versions, `INSTALL CERTS` removes the old bundle for you.

**On the "foreign roots" question.** Earlier documentation in this project
claimed the bundle contained Australian Defence Organisation, Netherlands
Ministry of Defence, US State Department and Treasury, and commercial SSP roots
from DigiCert, Entrust, Verizon and IdenTrust. **That was wrong, and has been
corrected.** Those certificates live in
`DoD_Approved_External_PKIs_Trust_Chains_v11.4/`, which the build tool never
reads. Every certificate in the DoD source material has `O = U.S. Government`.
The IdenTrust entries that do appear are DoD cross-certificates *issued by*
`ECA Root CA 4`, not IdenTrust roots. `tests/test_certs.py` asserts this so it
cannot regress.

## Known limitations

**A container is not a laptop.** The portability suite proves Sentinel picks
the right paths, package names and module on each distribution. It cannot prove
a card can be read, because there is no card in a container. Someone still has
to run `sentinel setup` on real hardware with a real reader.

**Snap Firefox on Ubuntu is untested with a real browser.** The tool detects it
and refuses to claim success, which is the important part. Whether a
classic-confinement snap can actually load the module is not something this
codebase can prove.

**Add a distribution in one place.** `sentinel_platform._FAMILIES` holds the
trust path, refresh command and package names. Adding a distribution is one
entry there and one expected-value row in the portability suite.

**`pkexec` cannot show its prompt inside a TUI.** If no polkit agent is
available, the authorization dialog is invisible and the request waits up to two
minutes. Run `sudo systemctl enable --now pcscd` yourself, or use
`sentinel-cli`, which can render a prompt.

**A snap or Flatpak Firefox cannot use a smart card.** Since Ubuntu 24.04,
Firefox is a snap, and on many distributions it is a Flatpak. Both are sandboxed
and cannot load a card-reader module from the host filesystem. Sentinel detects
this and tells you so rather than reporting success — but it cannot fix it for
you. Install Firefox from your distribution's own packages instead:

```bash
sudo apt install firefox      # or: sudo dnf install firefox
```

If you want to keep the snap, `sudo snap install --classic firefox` works.

**Browser configuration is discarded if Firefox is running.** Firefox rewrites
its profile on exit and throws away a change made while it was open. Sentinel
warns you when it detects a running browser, but it cannot close it for you.
Close Firefox, configure, restart.

**A laptop's fingerprint reader can look like a card reader.** Some laptops
expose the fingerprint sensor as a smart card reader, and pcscd will
enumerate that instead of your CAC. If your card is in an external reader and
Sentinel says no card is present, this is usually why. `sentinel doctor` calls
it out.

**`DoD_Roots.pem` reflects the bundle version in this repository** (PKCS#7 v5.6
DoD, v5.12 ECA, v5.17 WCF). It does not include CNSA 2.0 roots such as DoD Root
CA 6 or ECA Root CA 6, because the bundled DoD material does not contain them.
A newer DoD bundle can be dropped in to replace it.

**`INSTALL CERTS` refreshes the whole trust store**, not just the DoD roots. On
some systems, a re-keyed or re-issued non-DoD root can be silently dropped by
`update-ca-trust`. That is standard behaviour of the distribution's tooling, not
something Sentinel introduces, but it is why the tool prints the refresh command
it runs.

**The Broadcom 58200 workaround is appended to `/etc/opensc.conf`, not merged.**
Sentinel writes a backup to `/etc/opensc.conf.sentinel.bak` first and only ever
appends, so your existing settings survive. It never rewrites the file.

**Two commands mean the same thing.** `sentinel` and `snl` are identical, and
`sentinel-cli` is the same backend with a headless interface.

## Logs

Writes `sentinel.log` next to the application, not in the current directory.
It is created `0600`, rotates at 1 MB, and keeps 3 backups. It records what
Sentinel did and what the tools reported — it does not contain your cardholder
identity or certificate contents, because the code that logged those was
removed in v2.0.0.

## Update

```bash
cd ~/.sentinel && ./update
./update --dry-run     # show the commits you would receive
SENTINEL_REF=v2.2.0 ./update
```

The updater fetches, shows you the commits, fast-forwards, reinstalls the pinned
dependencies, and confirms the application still imports. It refuses to merge —
if your checkout has diverged, it stops and tells you. It never changes system
packages or your installed certificates.

## Uninstall

```bash
cd ~/.sentinel
./uninstall                  # remove Sentinel and the commands, keep the certs
./uninstall --purge-certs    # also remove the DoD trust anchors (needs root)
./uninstall --dry-run        # show what would happen
```

The uninstaller asks the application where your trust store is, so it removes
the right filename on your distribution, and it covers the legacy names too so
an earlier version's anchors are cleaned up as well. Removing the certificates
is opt-in because it is the only step that touches system state and needs root.

## Development

```bash
./run_tests.py                      # 181 tests, no third-party runner needed
./run_tests.py -v                   # verbose
./run_tests.py backend              # one file

python3 tests/test_portability.py   # run on 5 real distributions in containers
python3 tests/test_portability.py --list

The portability suite needs podman or docker, and network access for the first
image pull. It is separate from run_tests.py for that reason.
```

The suite covers the privileged paths with `dry_run=True` and a stubbed
subprocess layer, so `install_certs` — which builds root commands — is tested
without root and without a card. It renders the real TUI and asserts that text
actually reaches the console, because a bug where the console writer silently
failed every call was caught by neither the other 143 tests nor a manual look.
It also asserts that the committed trust bundle contains nothing but
self-signed roots, which is the regression that matters most.

## Troubleshooting

`pcscd` not detected:

```bash
sudo systemctl enable --now pcscd
```

No card seen, but a reader is plugged in: run `sentinel doctor`. It separates a
dead port, a laptop fingerprint sensor occupying the card slot, a permissions
problem, and a driver conflict, and gives the command for each.

Reader hangs ~26 seconds on insert: OpenSC probes the card with a driver the
Broadcom Corp 58200 firmware cannot answer. Press `f`, or:

```bash
sudo sh -c 'echo "card_drivers = piv-II, cac, cac1" >> /etc/opensc.conf'
```

Browser still does not offer the card: close Firefox first (it rewrites its
profile on exit and discards the change), then re-run `sentinel setup`.

Installing the certificates by hand:

```bash
# Debian/Ubuntu/Zorin, openSUSE
sudo cp DoD_Roots.pem /usr/local/share/ca-certificates/DoD_Roots.crt
sudo update-ca-certificates

# Fedora/RHEL
sudo cp DoD_Roots.pem /etc/pki/ca-trust/source/anchors/DoD_Roots.pem
sudo update-ca-trust

# Arch
sudo cp DoD_Roots.pem /etc/ca-certificates/trust-source/anchors/DoD_Roots.pem
sudo trust extract-compat
```
