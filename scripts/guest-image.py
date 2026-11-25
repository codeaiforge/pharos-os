#!/usr/bin/env python3
"""The Tier 3 guest image (#296, bridge.md, D-036): pinned Alpine as one
initramfs, with Python and LangGraph, and an init that starts the agent and
nothing else. Python's standard library only; run by `cargo xtask guest`.

  guest-image.py lock <lockfile>
      Resolves the pins (network): Alpine's minirootfs and `linux-virt`, the
      `python3` package and its dependencies from Alpine's index, and
      LangGraph's wheels for musl and Python 3.14 through pip's resolver.
      Writes one line per download: `<kind> <sha256> <url>`. A maintainer
      runs this to move a pin; the lock is reviewed like code.

  guest-image.py build <lockfile> <cache dir> <out dir>
      Downloads what the cache lacks, checks every file against its SHA-256
      in the lock (any mismatch fails the build), and writes `vmlinuz-virt`
      and `initramfs` (newc cpio, gzip) to the out dir. Two builds from the
      same lock give the same bytes: entries sorted, owners 0, times 0.
"""

import gzip
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

ALPINE = "https://dl-cdn.alpinelinux.org/alpine"
BRANCH = "v3.24"
ARCH = "x86_64"
PYTHON = "3.14"
# Alpine 3.24's musl 1.2 runs wheels for musllinux 1.1 and 1.2 (pydantic-core
# ships only 1.1); pip takes only the tags it is given.
WHEEL_PLATFORMS = ["musllinux_1_2_x86_64", "musllinux_1_1_x86_64"]
# The framework (D-036 item 6). Its dependencies come from pip's resolver.
REQUIREMENTS = ["langgraph==1.2.24"]
# Alpine packages on top of the minirootfs.
PACKAGES = ["python3"]
KINDS = ("rootfs", "kernel", "apk", "wheel")
KERNEL = "boot/vmlinuz-virt"
SITE = f"usr/lib/python{PYTHON}/site-packages/"

# PID 1. No openrc, getty, network scripts, or package manager runs: the
# kernel has no network device, and `lo` is never brought up.
INIT = b"""#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
# The bridge's port by name (bridge.md), as udev would link it.
mkdir -p /dev/virtio-ports
for p in /sys/class/virtio-ports/*; do
    [ -e "$p/name" ] && ln -sf "/dev/${p##*/}" "/dev/virtio-ports/$(cat "$p/name")"
done
echo "guest: init done"
/usr/bin/python3 -I /agent/main.py
echo "guest: agent exited $?"
poweroff -f
"""

# The agent and the client library (#299), from the repository's `guest/`.
GUEST = pathlib.Path(__file__).resolve().parent.parent / "guest"


def fail(msg):
    sys.exit(f"guest-image: {msg}")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


# --- lock ----------------------------------------------------------------


def apk_index():
    """Alpine main's index: name -> record, and provided name -> name."""
    data = fetch(f"{ALPINE}/{BRANCH}/main/{ARCH}/APKINDEX.tar.gz")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        text = t.extractfile("APKINDEX").read().decode()
    pkgs, provides = {}, {}
    for block in text.strip().split("\n\n"):
        rec = {}
        for line in block.splitlines():
            k, _, v = line.partition(":")
            rec[k] = v
        name = rec["P"]
        pkgs[name] = rec
        provides.setdefault(name, name)
        for p in rec.get("p", "").split():
            provides.setdefault(strip_version(p), name)
    return pkgs, provides


def strip_version(dep):
    for op in ("<=", ">=", "~", "=", "<", ">"):
        dep = dep.split(op)[0]
    return dep


def closure(roots, pkgs, provides):
    seen, todo = [], list(roots)
    while todo:
        name = provides.get(strip_version(todo.pop(0)))
        if name is None:
            fail(f"no Alpine package provides a dependency of {roots}")
        if name in seen:
            continue
        seen.append(name)
        todo += [d for d in pkgs[name].get("D", "").split() if not d.startswith("!")]
    return sorted(seen)


def lock(path):
    lines = [f"# The guest image's pins (#296): Alpine {BRANCH}, Python {PYTHON}, {' '.join(REQUIREMENTS)}.",
             "# Written by `scripts/guest-image.py lock`; `<kind> <sha256> <url>`."]
    releases = fetch(f"{ALPINE}/{BRANCH}/releases/{ARCH}/latest-releases.yaml").decode()
    rootfs = [l.split(":", 1)[1].strip() for l in releases.splitlines() if l.strip().startswith("file: alpine-minirootfs-")]
    if not rootfs:
        fail("no minirootfs in Alpine's latest-releases.yaml")
    url = f"{ALPINE}/{BRANCH}/releases/{ARCH}/{rootfs[0]}"
    lines.append(f"rootfs {sha256(fetch(url))} {url}")
    pkgs, provides = apk_index()
    kernel = pkgs["linux-virt"]
    url = f"{ALPINE}/{BRANCH}/main/{ARCH}/linux-virt-{kernel['V']}.apk"
    lines.append(f"kernel {sha256(fetch(url))} {url}")
    for name in closure(PACKAGES, pkgs, provides):
        url = f"{ALPINE}/{BRANCH}/main/{ARCH}/{name}-{pkgs[name]['V']}.apk"
        lines.append(f"apk {sha256(fetch(url))} {url}")
    with tempfile.TemporaryDirectory() as tmp:
        report = pathlib.Path(tmp) / "report.json"
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", "--dry-run", "--ignore-installed",
                        "--report", str(report), *(a for p in WHEEL_PLATFORMS for a in ("--platform", p)),
                        "--python-version", PYTHON,
                        "--implementation", "cp", "--only-binary=:all:", "--target", tmp, *REQUIREMENTS],
                       check=True)
        for item in sorted(json.loads(report.read_text())["install"], key=lambda i: i["metadata"]["name"]):
            info = item["download_info"]
            lines.append(f"wheel {info['archive_info']['hashes']['sha256']} {info['url']}")
    pathlib.Path(path).write_text("\n".join(lines) + "\n")


# --- build ---------------------------------------------------------------


def read_lock(path):
    entries = []
    for n, line in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3 or parts[0] not in KINDS or len(parts[1]) != 64 or not parts[2].startswith("https://"):
            fail(f"{path} line {n}: expected `<kind> <sha256> <https url>`")
        entries.append(tuple(parts))
    for kind in ("rootfs", "kernel"):
        if sum(e[0] == kind for e in entries) != 1:
            fail(f"{path}: needs exactly one `{kind}` line")
    return entries


def get(entry, cache):
    """The file's bytes, from the cache or the network, checked."""
    _, want, url = entry
    cached = pathlib.Path(cache) / f"{want}-{url.rsplit('/', 1)[1]}"
    if cached.exists():
        data = cached.read_bytes()
    else:
        data = fetch(url)
    got = sha256(data)
    if got != want:
        cached.unlink(missing_ok=True)
        fail(f"{url}: SHA-256 is {got}, the lock says {want}; refusing it (a moved pin is changed with `lock`)")
    if not cached.exists():
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(data)
    return data


def add_tar(tree, data, skip_dot=False):
    """Every member of a (concatenated) gzip tar into `tree`: path ->
    (mode, bytes) for files, ('l', target) for symlinks, (mode, None) for
    directories. Later archives replace earlier ones' files."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        members = t.getmembers()
        by_name = {m.name: m for m in members}
        for m in members:
            name = m.name.removeprefix("./").rstrip("/")
            if name in ("", ".") or (skip_dot and name.startswith(".")):
                continue
            if m.isdir():
                tree.setdefault(name, (0o040000 | m.mode, None))
            elif m.issym():
                tree[name] = ("l", m.linkname)
            elif m.islnk():
                src = by_name.get(m.linkname) or by_name.get("./" + m.linkname)
                tree[name] = (0o100000 | src.mode, t.extractfile(src).read())
            elif m.isfile():
                tree[name] = (0o100000 | m.mode, t.extractfile(m).read())


def add_wheel(tree, data):
    """A wheel's files into site-packages; `*.data/purelib` and `platlib`
    too, scripts and headers dropped (nothing runs them)."""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            name = info.filename
            first, _, rest = name.partition("/")
            if first.endswith(".data"):
                kind, _, rest = rest.partition("/")
                if kind not in ("purelib", "platlib"):
                    continue
                name = rest
            mode = (info.external_attr >> 16) & 0o777 or 0o644
            tree[SITE + name] = (0o100000 | mode, z.read(info))


def cpio(tree):
    """newc cpio of `tree`, sorted, every parent directory present, owners
    and times 0, so equal trees give equal bytes."""
    tree = dict(tree)
    for name in list(tree):
        parts = name.split("/")
        for i in range(1, len(parts)):
            tree.setdefault("/".join(parts[:i]), (0o040755, None))
    out = io.BytesIO()

    def entry(ino, name, mode, body):
        nb = name.encode() + b"\0"
        fields = [ino, mode, 0, 0, 2 if mode & 0o040000 == 0o040000 else 1, 0, len(body), 0, 0, 0, 0, len(nb), 0]
        out.write(b"070701" + b"".join(b"%08X" % f for f in fields) + nb)
        out.write(b"\0" * (-out.tell() % 4) + body)
        out.write(b"\0" * (-out.tell() % 4))

    for ino, name in enumerate(sorted(tree), 1):
        mode, body = tree[name]
        if mode == "l":
            entry(ino, name, 0o120777, body.encode())
        else:
            entry(ino, name, mode, body or b"")
    entry(0, "TRAILER!!!", 0, b"")
    return out.getvalue()


def build(lockfile, cache, out):
    entries = read_lock(lockfile)
    tree = {}
    kernel = None
    for kind in KINDS:  # the rootfs first, so packages and wheels replace its files
        for entry in (e for e in entries if e[0] == kind):
            data = get(entry, cache)
            if kind == "rootfs":
                add_tar(tree, data)
            elif kind == "kernel":
                k = {}
                add_tar(k, data, skip_dot=True)
                if KERNEL not in k:
                    fail(f"{entry[2]} has no {KERNEL}")
                kernel = k[KERNEL][1]
            elif kind == "apk":
                add_tar(tree, data, skip_dot=True)
            else:
                add_wheel(tree, data)
    tree["init"] = (0o100755, INIT)
    tree["agent/main.py"] = (0o100644, (GUEST / "main.py").read_bytes())
    tree[SITE + "pharos_bridge.py"] = (0o100644, (GUEST / "pharos_bridge.py").read_bytes())
    image = gzip.compress(cpio(tree), compresslevel=6, mtime=0)
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "vmlinuz-virt").write_bytes(kernel)
    (out / "initramfs").write_bytes(image)
    print(f"guest-image: vmlinuz-virt {sha256(kernel)}")
    print(f"guest-image: initramfs {sha256(image)} ({len(image) >> 20} MiB, {len(tree)} files)")


if __name__ == "__main__":
    if sys.argv[1:2] == ["lock"] and len(sys.argv) == 3:
        lock(sys.argv[2])
    elif sys.argv[1:2] == ["build"] and len(sys.argv) == 5:
        build(*sys.argv[2:])
    else:
        fail("usage: guest-image.py lock <lockfile> | build <lockfile> <cache dir> <out dir>")
