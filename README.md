<div align="center">
  <img src="sentinel_icon.png" alt="sentinel_icon" width="220" />

  <h1>Sentinel</h1>

  <p>
    <strong>Get your DoD CAC working on your own Linux laptop.</strong>
  </p>

  <p>
    <img src="https://img.shields.io/badge/Made%20with-Python-00ADD8?style=flat-square&logo=python" alt="Python" />
    <img src="https://img.shields.io/badge/TUI-Textual-00ADD8?style=flat-square" alt="Textual" />
    <img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square" alt="Python Version" />
    <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License" />
  </p>

  <p>
    <img src="https://img.shields.io/badge/Fedora-Tested-00ADD8?style=flat-square&logo=fedora" alt="Fedora" />
    <img src="https://img.shields.io/badge/Debian-Tested-00ADD8?style=flat-square&logo=debian" alt="Debian" />
    <img src="https://img.shields.io/badge/Ubuntu-Tested-00ADD8?style=flat-square&logo=ubuntu" alt="Ubuntu" />
    <img src="https://img.shields.io/badge/Arch-Tested-00ADD8?style=flat-square&logo=archlinux" alt="Arch" />
    <img src="https://img.shields.io/badge/openSUSE-Tested-00ADD8?style=flat-square&logo=opensuse" alt="openSUSE" />
  </p>

  <p>
    <a href="#why-sentinel"><strong>Why Sentinel</strong></a> ·
    <a href="#installation"><strong>Installation</strong></a> ·
    <a href="#usage"><strong>Usage</strong></a> ·
    <a href="#troubleshooting"><strong>Troubleshooting</strong></a> ·
    <a href="https://github.com/CodeFXR/Sentinel/issues"><strong>Report Bug</strong></a>
  </p>
</div>

<br>
<br>

## Why Sentinel?

You installed Linux because you wanted to. Your CAC does not work on it — the browser has never heard of it, the sites you need will not load without it, and every guide online assumes you already know what a trust store is.

Sentinel does that part. Then it tells you, in plain language, whether it worked.

- **One Command Setup:** `sentinel setup` does everything and answers with a single sentence — working, or here is exactly what to fix.
- **Plain-Language Diagnosis:** `sentinel doctor` explains *why* your card is not seen, in terms you can act on. It catches the four real causes, including the one nobody documents: a laptop's fingerprint sensor occupying the card slot.
- **Seven Roots, Not 197:** Installs only the self-signed DoD roots. An earlier version installed 62 issuing CAs as trust anchors. The bundle is re-checked at install time and refuses anything that is not self-signed.
- **Never Lies to You:** A green light means it was verified. A sandboxed browser, an unreadable configuration, a dry run — each gets its own honest state instead of a reassuring tick.
- **Works Offline:** The Python dependencies ship with the repository. Installation needs no access to PyPI, which matters on a unit with a restricted network.
- **Fixes a 26-Second Freeze:** OpenSC probes your card with a driver the Broadcom Corp 58200 firmware cannot answer. Sentinel disables that probe. Your laptop stops hanging on every card insert.

<br>

## Installation

```bash
git clone https://github.com/CodeFXR/Sentinel.git
cd Sentinel
./install
```

The installer detects your distribution, installs what Sentinel needs, and puts `sentinel`, `snl` and `sentinel-cli` on your `PATH`.

<details>
<summary>Requirements</summary>

| | |
|---|---|
| **OS** | Linux — Fedora/RHEL, Debian/Ubuntu (incl. Mint, Zorin), Arch, openSUSE |
| **Python** | 3.10 or newer |
| **Packages** | installed for you |

</details>

<details>
<summary>Prefer a specific version?</summary>

```bash
SENTINEL_REF=v2.2.0 ./install
```

Pins the install to a tag, so it is reproducible.

</details>

<br>

## Usage

### The two commands that matter

```bash
sentinel setup      # do everything, then say whether it worked
sentinel doctor     # explain why your card is not being seen
```

### The dashboard

`sentinel` opens the status panel. The sidebar LEDs show the state of the service, the middleware, your card, the certificates and the browser.

| Key | Action |
|:---:|---|
| `enter` | Set up everything |
| `d` | Why is my card not seen? |
| `c` | Run checks |
| `i` | Install certificates |
| `b` | Configure browsers |
| `f` | Fix the reader hang |
| `s` | Watch card insert and removal |
| `q` | Quit |

### From a terminal

For scripting, and for reviewing a change before you make it.

```bash
sentinel-cli check --dry-run        # show what would change, change nothing
sentinel-cli install-certs          # install the DoD roots (asks your password)
sentinel-cli verify-bundle          # check the shipped roots against the manifest
sentinel-cli all --json             # machine-readable, for a pipeline
```

`--dry-run` never claims success it did not achieve.

<br>

## What gets installed

`DoD_Roots.pem` — seven self-signed roots, 8.6 KB, and nothing else.

```
DoD Root CA 2     DoD Root CA 3     DoD Root CA 4     DoD Root CA 5
ECA Root CA 4     ECA Root CA 5     DoD WCF Root CA 1
```

A trust-anchor directory may hold only roots. Anything else is promoted to a root of trust, which means a retired or re-keyed issuing CA can validate a certificate directly. Sentinel checks this before installing and aborts rather than doing it.

Every root is verified to belong to `O = U.S. Government`. No foreign government or commercial roots are included.

### Where the certificates come from

They ship with Sentinel. You never visit a website to get them, and the
installer never downloads anything to install them — that is the point of the
tool, and a step that needs a browser and a manual download is a step someone
will skip.

The roots are extracted from the signed PKI bundles DoD publishes, which are in
this repository under `certificates_pkcs7_v5_12_eca/`,
`Certificates_PKCS7_v5_17_WCF/` and `Certificates_PKCS7_v5.6_DoD/`. Each of
those per-root `.p7b` files contains the root *and every certificate beneath it*
— 59 certificates across the seven files — so the build keeps only the
self-signed ones. Taking the first certificate from each file would install an
issuing CA as a root of trust, which is the specific mistake this project exists
to prevent.

### Checking they are current

```bash
sentinel-cli verify-bundle
```

Read-only, needs no network, and answers the question that follows every
"the tool handles the certificates for you": *are these the current ones?* It
confirms every root is self-signed and in date, then compares the bundle against
`DoD_Roots.manifest`, which records each certificate's SHA-256, expiry date and
fingerprint. It reports a root that has been **removed, added, replaced or
reordered** — a swapped root has the same name and count, so only the
fingerprint catches it.

The same question for a maintainer, answered against the sources:

```bash
python3 tools/refresh_roots.py --verify-sources   # are the sources unmodified?
python3 tools/refresh_roots.py --check             # does the bundle match them?
python3 tools/refresh_roots.py --write             # rebuild both files
```

`--verify-sources` checks every source file against the SHA-256 manifest that
DoD ships inside each bundle's `.sha256` file — which despite its name is a CMS
object signed by a DoD PKE code-signing credential, not a checksum list.

<br>

## Updating

```bash
cd ~/.sentinel && ./update
```

| Flag | Effect |
|---|---|
| `--dry-run` | Show the commits you would receive, apply nothing |
| `SENTINEL_REF=<tag>` | Move to a specific version |

Updating never happens on its own. An earlier version fetched from GitHub on every launch, which on a compromised repository is silent code execution on a machine holding a CAC.

<br>

## Uninstalling

```bash
cd ~/.sentinel
./uninstall                  # remove Sentinel and the commands, keep the certificates
./uninstall --purge-certs    # also remove the DoD roots (asks your password)
./uninstall --dry-run        # show what would happen
```

The uninstaller asks the application where your trust store is, so it removes the right file on your distribution.

<br>

## Troubleshooting

| Symptom | Fix |
|---|---|
| `sentinel doctor` says no reader found | Check the cable, then try another port |
| Reader present, no card seen | Your laptop's fingerprint sensor may be occupying the card slot. `sentinel doctor` says so explicitly |
| Hangs ~26s on card insert | Press `f`, or add `card_drivers = piv-II, cac, cac1` to `/etc/opensc.conf` |
| Browser does not offer the card | Close Firefox first, then re-run `sentinel setup` |
| Firefox is a snap or Flatpak | Neither can use a smart card. Install Firefox from your distribution's packages |
| `pcscd` not running | `sudo systemctl enable --now pcscd` |
| `pkexec` seems to hang | The prompt cannot render inside a terminal. Use `sentinel-cli`, which can show it |

<br>

## Honest limitations

- **The browser step is verified on two real machines, not one.** Fedora 44 with a Broadcom Corp 58200, and Zorin OS 18.1 with Chromium only. On the Zorin laptop the first run of the p11-kit check reported a working configuration as broken, because it demanded a `p11-kit-proxy` entry in `~/.pki/nssdb` that Chromium never writes; the field log is the fixture `tests/test_zorin_report.py` asserts against. Distribution support is verified in real containers as well, but a container has no smart card, so a container proves the packaging and not the card.
- **`systemctl is-enabled` reports `indirect` on most machines, and that is not a fault.** pcscd is normally pulled in by `pcscd.socket` and a D-Bus unit. Comparing that against the literal string `enabled` sends a user to fix a service that starts at every boot, so the check accepts every state that means "comes up on its own".
- **The certificates have not been read on the machines they are installed from the network path.** The sources in this repository are unmodified from DoD's signed publication and the bundle reproduces byte-for-byte from them, but if DoD publishes a new bundle version, `tools/refresh_roots.py --check` will say so rather than anyone noticing.
- **The CMS signature on DoD's `.sha256` manifests no longer validates.** The signing certificate has expired since publication, so a present-day OpenSSL refuses it. The file digests inside it are still used to confirm the sources are unmodified, which is a weaker statement than "the signature verifies today" and is labelled as such in `tools/refresh_roots.py`.
- **The browser step has not been run on a machine without p11-kit.** That fallback path — writing a PKCS#11 module entry with `modutil` by hand — is exercised by the test suite but not by real hardware, because no p11-kit-free machine was available. On any current distribution p11-kit is present and that path does not run.
- **Snap Firefox is detected but unproven.** Sentinel refuses to claim success with a sandboxed browser. Whether a classic-confinement snap can load the module needs a real machine.
- **`DoD_Roots.pem` reflects the bundle in this repository** (PKCS#7 v5.6 / v5.12 / v5.17). CNSA 2.0 roots are not included, because the source material does not contain them.
- **Installation is a clone, not a package.** There is no `.deb` or `.rpm` yet.

<br>

## License

[MIT](LICENSE) © 2026 CodeFXR
