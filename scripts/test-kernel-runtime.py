#!/usr/bin/env python3
"""Boot a disposable, diskless QEMU guest; never load the module on the host."""
import argparse
import gzip
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--kdir", default=f"/lib/modules/{os.uname().release}/build")
parser.add_argument("--kernel", help="Boot image matching --kdir")
parser.add_argument("--output", help="Directory for build artifacts and serial log")
args = parser.parse_args()
kdir = Path(args.kdir).resolve()
kernel = Path(args.kernel or f"/boot/vmlinuz-{kdir.name}")
if not (kdir / "Makefile").is_file() or not kernel.is_file():
    parser.error("matching kernel image and development headers are required")
out = Path(args.output or tempfile.mkdtemp(prefix="snakedrv-runtime-"))
out.mkdir(parents=True, exist_ok=True)
out = out.resolve()
print(f"Runtime artifacts: {out}", flush=True)

def run(argv, **kwargs):
    return subprocess.run([str(x) for x in argv], check=True, **kwargs)

# Stage sources so neither cached objects nor host-installed modules affect the test.
source = out / "dkms"
run(["bash", root / "scripts/stage-dkms.sh", source])
run(["make", "-C", source / "kernel", "-j2", f"KDIR={kdir}", "TESTING=1"])
build = out / "build"
run(["cmake", "-S", root / "userland", "-B", build,
     "-DCMAKE_BUILD_TYPE=Debug", "-DSNAKEDRV_BUILD_TESTS=ON"])
run(["cmake", "--build", build, "-j2"])

guest = out / "root"
guest.mkdir(exist_ok=True)
for name in ["proc", "sys", "dev", "tmp", "lib", "lib64"]:
    (guest / name).mkdir(exist_ok=True)

def copy_file(path, destination=None):
    path = Path(path)
    target = guest / str(destination or path).lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, target, follow_symlinks=True)

for binary, destination in [(build / "test_driver_runtime", "/init"),
                             (build / "test_protection", "/test_protection")]:
    copy_file(binary, destination)
    deps = subprocess.check_output(["ldd", str(binary)], text=True)
    for dependency in re.findall(r"(?:=>\s*)?(/[^\s]+)", deps):
        copy_file(dependency)
copy_file(source / "kernel/snakedrv.ko", "/snakedrv.ko")
archive = out / "initramfs.cpio"
members = subprocess.check_output(["find", ".", "-print0"], cwd=guest)
with archive.open("wb") as stream:
    run(["cpio", "--null", "-o", "--format=newc", "--quiet"],
        cwd=guest, input=members, stdout=stream)
compressed = out / "initramfs.cpio.gz"
with archive.open("rb") as source_file, gzip.open(compressed, "wb", compresslevel=1) as packed:
    shutil.copyfileobj(source_file, packed)

serial = out / "serial.log"
command = ["qemu-system-x86_64", "-nodefaults", "-no-reboot", "-display", "none",
           "-serial", "stdio", "-monitor", "none", "-m", "1024", "-smp", "2",
           "-accel", "tcg,thread=multi", "-cpu", "max", "-machine", "q35",
           "-kernel", str(kernel), "-initrd", str(compressed), "-append",
           "console=ttyS0 rdinit=/init panic=1 oops=panic nokaslr loglevel=4"]
with serial.open("wb") as log:
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    try:
        process.wait(timeout=300)
    except BaseException:
        process.kill()
        process.wait()
        raise
text = serial.read_text(errors="replace")
for line in text.splitlines():
    if "PASS" in line or "FAIL" in line or "panic" in line or "BUG:" in line:
        print(line)
if process.returncode or "SNAKEDRV_RUNTIME_PASS" not in text or "SNAKEDRV_RUNTIME_FAIL" in text:
    print(text[-12000:])
    raise SystemExit(f"Runtime validation failed; inspect {serial}")
print(f"Diskless kernel runtime validation passed: {serial}")
