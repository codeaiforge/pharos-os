#!/usr/bin/env python3
"""Host tests for scripts/guest-image.py (#296). No network.

Run: python3 -m unittest scripts/test_guest_image.py
"""

import hashlib
import importlib.util
import io
import pathlib
import tarfile
import tempfile
import unittest
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("guest", HERE / "guest-image.py")
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


def read_cpio(data):
    """newc entries as (name, mode, body), in order."""
    out, off = [], 0
    while True:
        assert data[off:off + 6] == b"070701", "bad magic"
        f = [int(data[off + 6 + 8 * i:off + 14 + 8 * i], 16) for i in range(13)]
        mode, size, namesize = f[1], f[6], f[11]
        assert f[2] == f[3] == f[5] == 0, "owner or time not zero"
        name = data[off + 110:off + 110 + namesize - 1].decode()
        off += 110 + namesize
        off += -off % 4
        body = data[off:off + size]
        off += size
        off += -off % 4
        if name == "TRAILER!!!":
            return out
        out.append((name, mode, body))


def targz(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, kind, value in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(value)
                info.mode = 0o755
                t.addfile(info, io.BytesIO(value))
            elif kind == "sym":
                info.type, info.linkname = tarfile.SYMTYPE, value
                t.addfile(info)
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                t.addfile(info)
            elif kind == "hard":
                info.type, info.linkname = tarfile.LNKTYPE, value
                t.addfile(info)
    return buf.getvalue()


class Cpio(unittest.TestCase):
    def test_equal_trees_give_equal_bytes_in_any_order(self):
        a = {"usr/bin/x": (0o100755, b"x"), "etc/f": (0o100644, b"ff"), "bin/sh": ("l", "/bin/busybox")}
        b = dict(reversed(list(a.items())))
        self.assertEqual(guest.cpio(a), guest.cpio(b))

    def test_entries_are_sorted_with_every_parent(self):
        entries = read_cpio(guest.cpio({"a/b/c": (0o100644, b"hello"), "z": ("l", "a/b/c")}))
        self.assertEqual([e[0] for e in entries], ["a", "a/b", "a/b/c", "z"])
        self.assertEqual(entries[2], ("a/b/c", 0o100644, b"hello"))
        self.assertEqual(entries[3], ("z", 0o120777, b"a/b/c"))
        self.assertEqual(entries[0][1] & 0o170000, 0o040000)


class Lock(unittest.TestCase):
    def write(self, text):
        f = tempfile.NamedTemporaryFile("w", suffix=".lock", delete=False)
        f.write(text)
        f.close()
        return f.name

    def test_a_good_lock_is_read(self):
        h = "0" * 64
        path = self.write(f"# c\nrootfs {h} https://x/r.tar.gz\nkernel {h} https://x/k.apk\nwheel {h} https://x/w.whl\n")
        self.assertEqual(len(guest.read_lock(path)), 3)

    def test_bad_lines_are_refused(self):
        h = "0" * 64
        for bad in [f"rootfs {h}", f"deb {h} https://x/a", f"rootfs abc https://x/a", f"rootfs {h} http://x/a",
                    f"kernel {h} https://x/k.apk"]:  # the last: no rootfs
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                guest.read_lock(self.write(bad + "\n"))


class Fetch(unittest.TestCase):
    def test_a_mismatched_file_is_refused_and_dropped(self):
        with tempfile.TemporaryDirectory() as cache:
            want = hashlib.sha256(b"pinned").hexdigest()
            cached = pathlib.Path(cache) / f"{want}-f.apk"
            cached.write_bytes(b"tampered")
            with self.assertRaises(SystemExit) as e:
                guest.get(("apk", want, "https://example.invalid/f.apk"), cache)
            self.assertIn("SHA-256", str(e.exception))
            self.assertFalse(cached.exists())

    def test_a_matching_cached_file_is_used(self):
        with tempfile.TemporaryDirectory() as cache:
            want = hashlib.sha256(b"pinned").hexdigest()
            (pathlib.Path(cache) / f"{want}-f.apk").write_bytes(b"pinned")
            self.assertEqual(guest.get(("apk", want, "https://example.invalid/f.apk"), cache), b"pinned")


class Image(unittest.TestCase):
    def test_the_hashes_are_recorded_beside_the_image(self):
        with tempfile.TemporaryDirectory() as out:
            (pathlib.Path(out) / guest.HASHES).write_text("stale\n")
            guest.write_image(out, b"kernel", b"initrd")
            k, i = (hashlib.sha256(b).hexdigest() for b in (b"kernel", b"initrd"))
            self.assertEqual((pathlib.Path(out) / guest.HASHES).read_text(),
                             f"{k}  vmlinuz-virt\n{i}  initramfs\n")
            self.assertEqual((pathlib.Path(out) / "initramfs").read_bytes(), b"initrd")


class Unpack(unittest.TestCase):
    def test_tar_files_links_and_apk_metadata(self):
        tree = {}
        data = targz([(".", "dir", None), (".PKGINFO", "file", b"meta"), ("usr/lib/a", "file", b"A"),
                      ("usr/lib/b", "hard", "usr/lib/a"), ("lib/s", "sym", "../usr/lib/a")])
        guest.add_tar(tree, data, skip_dot=True)
        self.assertEqual(sorted(tree), ["lib/s", "usr/lib/a", "usr/lib/b"])
        self.assertEqual(tree["usr/lib/b"], (0o100755, b"A"))
        self.assertEqual(tree["lib/s"], ("l", "../usr/lib/a"))

    def test_wheel_data_dirs(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("pkg/__init__.py", b"x")
            z.writestr("pkg-1.0.data/purelib/extra.py", b"y")
            z.writestr("pkg-1.0.data/scripts/tool", b"z")
        tree = {}
        guest.add_wheel(tree, buf.getvalue())
        self.assertEqual(sorted(tree), [guest.SITE + "extra.py", guest.SITE + "pkg/__init__.py"])


class Init(unittest.TestCase):
    def test_init_starts_only_the_agent(self):
        text = guest.INIT.decode()
        for word in ("ifconfig", "ip link", "udhcpc", "getty", "openrc", "apk "):
            self.assertNotIn(word, text)
        self.assertIn("/agent/main.py", text)


if __name__ == "__main__":
    unittest.main()
