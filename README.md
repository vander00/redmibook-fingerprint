
## USB fingerprint sensor driver

Supported device: FPC Sensor Controller L:0001 FW:021.26.2.x (10a5:9201)

**This is a fork of [this](https://github.com/vrolife/fingerprint-ocv). It is mostly written with AI so the code quality might be not the best.**

I have checked the version on Redmibook Pro 15 2023 and it works quite fine but I can't say anything about other Redmi laptops.

## Environment

Ubuntu: `apt install -y --no-install-recommends libusb-1.0-0-dev libevent-dev libdbus-1-dev libssl-dev libopencv-dev make cmake pkg-config gcc g++`

Archlinux: `pacman --noconfirm -S libusb libevent libdbus openssl libopencv-dev make cmake pkg-config gcc`

## Build

```bash
git clone https://github.com/vrolife/fingerprint-ocv
cd fingerprint-ocv
git submodule init
git submodule update
cmake -S . -B build
cmake --build build
cp build/src/fingerprint-ocv /path/to/somewhere
```

## Install && Binary

[Link](https://github.com/vrolife/modern_laptop/tree/main/drivers/fingerprint)
