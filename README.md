# RedmiBook fingerprint driver

Linux fingerprint driver for the FPC Sensor Controller `10a5:9201`, tested on the RedmiBook Pro 15 2023.

> [WARNING]
> This driver is rewritten mostly by AI so the code might be not the best.

## Check compatibility

Run the following command and confirm that it prints a device with ID
`10a5:9201`:

```bash
lsusb -d 10a5:9201
```

Other devices are not supported by this driver.

## Install

The installer supports Ubuntu/Debian, Arch Linux and derivatives, and Fedora.
It installs the required packages and enables the systemd service. It first
tries to download a compatible binary from the latest GitHub release. If no
binary is available, it builds the driver from source instead.

Release binaries should be named `fingerprint-ocv-linux-x86_64` or
`fingerprint-ocv-linux-aarch64`. The legacy `fingerprint-ocv` name is also
accepted on x86-64.

```bash
git clone https://github.com/vander00/redmibook-fingerprint.git
cd redmibook-fingerprint
./install.sh
```


After installation, enroll a fingerprint:

```bash
fprintd-enroll
```

Then verify it:

```bash
fprintd-verify
```

Existing fingerprint templates in `/var/lib/fprint` are kept when the driver
is reinstalled.

## Troubleshooting

Check whether the service is running:

```bash
systemctl status fingerprint-ocv.service
```

View its recent logs:

```bash
journalctl -u fingerprint-ocv.service -b --no-pager
```

To rebuild after pulling an update, run `./install.sh` again.

## Manual build

Install the development packages listed in `install.sh`, then run:

```bash
git submodule update --init --recursive asyncdbus asyncusb jinx
cmake -S . -B build \
  -DCMAKE_C_COMPILER=gcc \
  -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=OFF \
  -DFINGERPRINT_OCV_USE_VCPKG=OFF
cmake --build build --parallel
sudo cmake --install build --prefix /usr/local
```

## Uninstall

```bash
sudo systemctl disable --now fingerprint-ocv.service
sudo rm /etc/systemd/system/fingerprint-ocv.service
sudo rm /usr/local/bin/fingerprint-ocv
sudo systemctl daemon-reload
```

The uninstall commands intentionally leave enrolled fingerprints in
`/var/lib/fprint` intact.

This project is a fork of
[vrolife/fingerprint-ocv](https://github.com/vrolife/fingerprint-ocv). That projects is not actively maintained now.
