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
The installer only works for systemd systems.
It downloads the latest binary from the releases.
It can also build from source for Arch, Debian/Ubuntu, Fedora linux systems.

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
systemctl status fprintd.service
```

View its recent logs:

```bash
journalctl -u fprintd.service -b --no-pager
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
sudo rm /etc/systemd/system/fprintd.service.d/20-fingerprint-ocv.conf
sudo rm /usr/local/bin/fingerprint-ocv
sudo systemctl daemon-reload
sudo systemctl restart fprintd.service
```

The uninstall commands intentionally leave enrolled fingerprints in
`/var/lib/fprint` intact.

This project is a fork of
[vrolife/fingerprint-ocv](https://github.com/vrolife/fingerprint-ocv). That projects is not actively maintained now.
