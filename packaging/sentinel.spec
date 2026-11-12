Name:           sentinel
Version:        2.0.3
Release:        1%{?dist}
Summary:        Enterprise DoD CAC and PIV Smart Card Manager for Linux
License:        MIT
URL:            https://github.com/CodeFXR/Sentinel
Source0:        %{name}-%{version}.tar.gz
Provides:       sentinel-cac-manager = %{version}-%{release}
Obsoletes:      sentinel-cac-manager < %{version}-%{release}

BuildRequires:  python3-devel
BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  pcsc-lite-devel

Requires:       pcsc-lite
Requires:       pcsc-lite-ccid
Requires:       opensc
Requires:       nss-tools
Requires:       python3-gobject
Requires:       gtk4
Requires:       libadwaita
Requires:       polkit

%description
Sentinel is a native Linux smart card identity and middleware
management application for Department of Defense (DoD) Common Access Cards (CAC)
and federal Personal Identity Verification (PIV) credentials. Provides smart card
diagnostics, certificate inspection and export, automated DoD PKI trust anchor
installation, browser authentication integration, and secure PIN management.

%prep
%autosetup

%build
cargo build --release --manifest-path native/sentinel_core/Cargo.toml

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_libexecdir}/sentinel/core
mkdir -p %{buildroot}%{_datadir}/sentinel/certificates
mkdir -p %{buildroot}%{_datadir}/applications
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/256x256/apps
mkdir -p %{buildroot}%{_datadir}/polkit-1/actions
mkdir -p %{buildroot}%{_prefix}/lib/sentinel

# Application files
cp -a cli.py main.py core ui %{buildroot}%{_prefix}/lib/sentinel/
cp -a target/release/libsentinel_core.so %{buildroot}%{_prefix}/lib/sentinel/core/

# Privileged helper
install -m 0755 core/privileged_helper.py %{buildroot}%{_libexecdir}/sentinel/privileged_helper.py
cp -a core/ca_manifest.py core/ownership.py core/rust_bridge.py core/__init__.py %{buildroot}%{_libexecdir}/sentinel/core/
install -m 0755 target/release/libsentinel_core.so %{buildroot}%{_libexecdir}/sentinel/core/

# Shared certificates
cp -a certificates/* %{buildroot}%{_datadir}/sentinel/certificates/

# Polkit policy & desktop entry
install -m 0644 polkit/com.codefxr.sentinel.policy %{buildroot}%{_datadir}/polkit-1/actions/
install -m 0644 sentinel.desktop %{buildroot}%{_datadir}/applications/
install -m 0644 sentinel.png %{buildroot}%{_datadir}/icons/hicolor/256x256/apps/

# CLI wrappers
cat << 'EOF' > %{buildroot}%{_bindir}/sentinel
#!/bin/sh
exec /usr/bin/python3 %{_prefix}/lib/sentinel/cli.py "$@"
EOF
chmod 0755 %{buildroot}%{_bindir}/sentinel

cat << 'EOF' > %{buildroot}%{_bindir}/sentinel-cac-manager
#!/bin/sh
exec /usr/bin/python3 %{_prefix}/lib/sentinel/main.py "$@"
EOF
chmod 0755 %{buildroot}%{_bindir}/sentinel-cac-manager

%post
if [ $1 -eq 1 ]; then
    systemctl daemon-reload || true
    systemctl enable --now pcscd.socket pcscd || true
    if [ -x %{_libexecdir}/sentinel/privileged_helper.py ]; then
        %{_libexecdir}/sentinel/privileged_helper.py --certs --family fedora || true
    fi
fi

%preun
if [ $1 -eq 0 ]; then
    if [ -x %{_libexecdir}/sentinel/privileged_helper.py ]; then
        %{_libexecdir}/sentinel/privileged_helper.py --uninstall --family fedora || true
    fi
fi

%files
%license LICENSE
%doc README.md
%{_bindir}/sentinel
%{_bindir}/sentinel-cac-manager
%{_libexecdir}/sentinel/
%{_prefix}/lib/sentinel/
%{_datadir}/sentinel/
%{_datadir}/applications/sentinel.desktop
%{_datadir}/icons/hicolor/256x256/apps/sentinel.png
%{_datadir}/polkit-1/actions/com.codefxr.sentinel.policy
