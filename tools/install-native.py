#!/usr/bin/env python3
"""Install one reviewed native binary, preserving the previous binary and databases.
Run through sudo/pkexec; no dependency downloads, provisioning, or template deletion.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=Path)
parser.add_argument("sha256")
args = parser.parse_args()
if os.geteuid() != 0:
    raise SystemExit("Root authentication is required to install the system driver")
image = args.binary.read_bytes()
if hashlib.sha256(image).hexdigest() != args.sha256 or not image.startswith(b"\x7fELF"):
    raise SystemExit("Reviewed native binary hash mismatch")
target = Path("/usr/local/bin/fingerprint-ocv")
state = Path("/var/lib/fprint")
stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
backup = state / "native-rollbacks" / stamp
backup.mkdir(mode=0o700, parents=True, exist_ok=False)
os.chmod(backup.parent, 0o700)


def command(*argv, check=True):
    return subprocess.run(argv, check=check, capture_output=True, text=True)


def replace(payload):
    descriptor, filename = tempfile.mkstemp(prefix=".fingerprint-ocv-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fchmod(output.fileno(), 0o755)
            os.fsync(output.fileno())
        os.replace(filename, target)
        parent = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        Path(filename).unlink(missing_ok=True)


command("systemctl", "stop", "fprintd.service")
previous = None
try:
    previous = target.read_bytes() if target.exists() else None
    if previous is not None:
        shutil.copy2(target, backup / "fingerprint-ocv")
    for name in ("fpc9201.bin", "fpc9201-native.bin"):
        source = state / name
        if source.exists():
            shutil.copy2(source, backup / name)
            os.chmod(backup / name, 0o600)
    manifest = {"previous_sha256": hashlib.sha256(previous).hexdigest() if previous else None,
                "native_sha256": args.sha256, "binary": str(target)}
    (backup / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    replace(image)
    command("systemctl", "reset-failed", "fprintd.service", check=False)
    command("systemctl", "start", "fprintd.service")
    deadline = time.monotonic() + 20
    ready = False
    while time.monotonic() < deadline:
        reply = command("busctl", "call", "net.reactivated.Fprint", "/net/reactivated/Fprint/Manager",
                        "net.reactivated.Fprint.Manager", "GetDefaultDevice", check=False)
        if reply.returncode == 0 and reply.stdout.startswith("o "):
            ready = True
            print("Reader registered:", reply.stdout.strip())
            break
        time.sleep(0.25)
    if not ready:
        log = command("journalctl", "-u", "fprintd.service", "-n", "30", "--no-pager", check=False)
        print(log.stdout)
        raise RuntimeError("Native driver did not register the reader within20 seconds")
    print("Native driver installed. Rollback snapshot:", backup)
except BaseException:
    command("systemctl", "stop", "fprintd.service", check=False)
    if previous is not None:
        replace(previous)
    command("systemctl", "reset-failed", "fprintd.service", check=False)
    command("systemctl", "start", "fprintd.service", check=False)
    print("Installation failed; previous driver restored. Snapshot:", backup)
    raise
