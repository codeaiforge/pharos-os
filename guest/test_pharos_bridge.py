"""Host tests for the client library (#299), against a fake bridge on a
socket pair: run with `python3 -m unittest -q guest/test_pharos_bridge.py`."""

import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pharos_bridge as pb  # noqa: E402


def frame(kind, payload):
    return struct.pack("<2sBBI", b"PB", 1, kind, len(payload)) + payload


def read_frame(sock):
    head = b""
    while len(head) < 8:
        head += sock.recv(8 - len(head))
    _, _, kind, n = struct.unpack("<2sBBI", head)
    body = b""
    while len(body) < n:
        body += sock.recv(n - len(body))
    return kind, body


def reply(msg, data=b""):
    return frame(pb.REPLY, bytes([len(msg)]) + msg + data)


class Fake:
    """The bridge's end: sends `before`, then for each request records it
    and sends the next of `answers`."""

    def __init__(self, before, answers):
        self.guest, self.pharos = socket.socketpair()
        self.got = []

        def run():
            self.pharos.sendall(before)
            for a in answers:
                self.got.append(read_frame(self.pharos))
                self.pharos.sendall(a)

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        self.bridge = pb.Bridge(fd=self.guest.fileno(), timeout=5)

    def requests(self):
        """Each REQUEST's (message, buffer data)."""
        self.thread.join(5)
        out = []
        for kind, p in self.got:
            assert kind == pb.REQUEST
            out.append((p[1 : 1 + p[0]], p[1 + p[0] :]))
        return out


HELLO = struct.pack("<IB", 7, 2)


class Hello(unittest.TestCase):
    def test_an_earlier_attempts_frames_are_skipped_and_hello_echoed(self):
        stale = frame(pb.REPLY, b"\x01\x00") + frame(pb.HELLO, b"\x00" * 4)
        f = Fake(stale + frame(pb.HELLO, HELLO), [])
        self.assertEqual(f.bridge.hello(), (7, 2))
        self.assertEqual(read_frame(f.pharos), (pb.HELLO, HELLO))


class Operations(unittest.TestCase):
    def test_task_log_checkpoint_and_complete(self):
        assigned = struct.pack("<BIBII", 0, 7, 2, 5, 3)
        data = b"input" + b"\x00" * (pb.CHECKPOINT_AT - 5) + b"cpt"
        f = Fake(b"", [reply(assigned, data), reply(b"\x00"), reply(b"\x00"), reply(b"\x00")])
        t = f.bridge.task()
        self.assertEqual((t.task, t.attempt, t.input, t.checkpoint), (7, 2, b"input", b"cpt"))
        f.bridge.log("step 1")
        f.bridge.checkpoint(b"state")
        f.bridge.complete("done")
        self.assertEqual(
            f.requests(),
            [
                (bytes([1, pb.TASK]), b""),
                (bytes([1, pb.LOG]) + b"step 1", b""),
                (bytes([1, pb.CHECKPOINT]) + struct.pack("<I", 5), b"state"),
                (bytes([1, pb.COMPLETE]) + struct.pack("<I", 4), b"done"),
            ],
        )

    def test_https_request_and_answer(self):
        answered = struct.pack("<BBHBIB", 0, 0, 200, 4, 2, 1)
        f = Fake(b"", [reply(answered, b"text{}")])
        a = f.bridge.request("items", "/items", b"x")
        self.assertEqual((a.http, a.content_type, a.body, a.stripped), (200, "text", b"{}", 1))
        msg, data = f.requests()[0]
        self.assertEqual(msg, bytes([1, pb.HTTPS, 5]) + b"items" + struct.pack("<HI", 6, 1))
        self.assertEqual(data, b"/itemsx")

    def test_data_and_ask(self):
        f = Fake(b"", [reply(b"\x00"), reply(struct.pack("<BI", 0, 2), b"hi"), reply(b"\x00\x02")])
        f.bridge.data_put("notes", b"hi")
        self.assertEqual(f.bridge.data_get("notes"), b"hi")
        self.assertEqual(f.bridge.ask(pb.https_permission("items"), 5000), pb.PENDING)
        reqs = f.requests()
        self.assertEqual(reqs[0], (bytes([1, pb.DATA_PUT, 5]) + b"notes" + struct.pack("<I", 2), b"hi"))
        self.assertEqual(reqs[2][0], bytes([1, pb.ASK, 10, 5]) + b"items" + struct.pack("<I", 5000))


class Refusals(unittest.TestCase):
    def test_a_refused_status_raises_with_it(self):
        f = Fake(b"", [reply(b"\x03")])
        with self.assertRaises(pb.PharosError) as e:
            f.bridge.log("x")
        self.assertEqual(e.exception.status, 3)

    def test_the_bridges_error_raises_with_its_reason(self):
        f = Fake(b"", [frame(pb.ERROR, b"\x08attempt ended")])
        with self.assertRaises(pb.PharosError) as e:
            f.bridge.task()
        self.assertEqual((e.exception.status, e.exception.reason), (8, "attempt ended"))

    def test_a_bad_frame_from_pharos_raises(self):
        f = Fake(b"XX\x01\x03\x00\x00\x00\x00", [b""])
        with self.assertRaises(pb.PharosError):
            f.bridge.task()

    def test_bad_text_and_names_are_refused_before_sending(self):
        f = Fake(b"", [])
        for text in ["", "x" * 201, "tab\there", "é"]:
            with self.assertRaises(ValueError):
                f.bridge.log(text)
        with self.assertRaises(ValueError):
            f.bridge.data_get("n" * 33)

    def test_silence_raises(self):
        guest, _pharos = socket.socketpair()
        with self.assertRaises(pb.PharosError):
            pb.Bridge(fd=guest.fileno(), timeout=0.1).task()


if __name__ == "__main__":
    unittest.main()
