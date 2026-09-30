Name:           fingerprint-ocv
Version:        1.0.0
Release:        1%{?dist}
Summary:        Fingerprint driver for the FPC 10a5:9201 sensor

License:        AGPL-3.0-only
URL:            https://github.com/vander00/redmibook-fingerprint
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake
BuildRequires:  gcc-c++
BuildRequires:  openssl-devel
BuildRequires:  opencv-devel
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libevent_core)
BuildRequires:  pkgconfig(libusb-1.0)
BuildRequires:  systemd-rpm-macros
Requires:       fprintd

%description
Fingerprint driver for the FPC 10a5:9201 sensor, run through fprintd's
system D-Bus service.

%prep
%autosetup

%build
%cmake \
    -DBUILD_TESTING=OFF \
    -DJINX_BUILD_CJSON=OFF \
    -DJINX_BUILD_EVDNS=OFF \
    -DJINX_BUILD_HTTP=OFF
%cmake_build

%install
%cmake_install
install -d %{buildroot}%{_unitdir}/fprintd.service.d
sed 's|/usr/local/bin/fingerprint-ocv|%{_bindir}/fingerprint-ocv|' \
    fprintd-fingerprint-ocv.conf > \
    %{buildroot}%{_unitdir}/fprintd.service.d/20-fingerprint-ocv.conf

%files
%license LICENSE
%doc README.md
%{_bindir}/fingerprint-ocv
%{_unitdir}/fprintd.service.d/20-fingerprint-ocv.conf

%changelog
* Wed Sep 30 2026 RedmiBook fingerprint contributors - 1.0.0-1
- Add Fedora Copr package build
