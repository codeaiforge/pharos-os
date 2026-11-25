"""The Tier 3 client library (#299, bridge.md): a guest agent's side of the
channel to Pharos. Python's standard library only, one file.

It opens the guest's one port, answers the bridge's HELLO, and turns each
call into one agents v1 request in a REQUEST frame, waiting for the REPLY.
Everything the guest does is checked by the Pharos runtime as the guest
agent's own request: grants, budgets, approvals, and records apply as for
any agent. The guest holds no credential; `request` names a gateway route,
and the gateway adds the route's secret outside the guest.

Frames: b"PB", version 1, kind (1 HELLO, 2 REQUEST, 3 REPLY, 4 ERROR), the
payload's length (u32, little-endian), then the payload.
"""

import os
import select
import struct

PORT = "/dev/virtio-ports/org.pharos.bridge"

HELLO, REQUEST, REPLY, ERROR = 1, 2, 3, 4
MAX_PAYLOAD = 70_000
VERSION = 1  # agents v1
# Operations (pharos_proto::agents::op).
TASK, CHECKPOINT, COMPLETE, FAIL, LOG = 1, 2, 5, 6, 10
DATA_PUT, DATA_GET, ASK, HTTPS = 11, 12, 13, 34
INFO = 0xF0
# Statuses (pharos_proto::status).
OK, BAD_REQUEST, NO_ACCESS = 0, 1, 3
CHECKPOINT_AT = 4096
MAX_TEXT = 200
# Permission kinds on the wire (pharos_proto::permission::kind).
PERMISSION_HTTPS = 10
# The ASK reply's outcomes.
GRANTED, REFUSED, PENDING = 0, 1, 2


class PharosError(Exception):
    """A refused request (`status`, the agents v1 status code), or the
    bridge's ERROR frame (`status` its code, `reason` its text)."""

    def __init__(self, status, reason=""):
        super().__init__(f"pharos: status {status} {reason}".strip())
        self.status = status
        self.reason = reason


def _text(text):
    b = text.encode() if isinstance(text, str) else bytes(text)
    if not 1 <= len(b) <= MAX_TEXT or any(c < 0x20 or c > 0x7E for c in b):
        raise ValueError("text must be 1 to 200 printable ASCII bytes")
    return b


def _name(name):
    b = name.encode() if isinstance(name, str) else bytes(name)
    if not 1 <= len(b) <= 32:
        raise ValueError("a name is 1 to 32 bytes")
    return bytes([len(b)]) + b


def https_permission(route):
    """`https <route>` on the wire, for `ask`."""
    return bytes([PERMISSION_HTTPS]) + _name(route)


class Task:
    def __init__(self, task, attempt, input, checkpoint):
        self.task = task
        self.attempt = attempt
        self.input = input
        self.checkpoint = checkpoint


class Answer:
    """A gateway answer: the HTTP status, content type, body, and how many
    times the route's secret was found and replaced (`[secret]`)."""

    def __init__(self, http, content_type, body, stripped):
        self.http = http
        self.content_type = content_type
        self.body = body
        self.stripped = stripped


class Bridge:
    """The channel. `fd` is the open port (a socket in tests); `timeout`
    bounds each wait for Pharos, in seconds."""

    def __init__(self, fd=None, timeout=120):
        self.fd = os.open(PORT, os.O_RDWR) if fd is None else fd
        self.timeout = timeout
        self.task_id = None
        self.attempt = None

    # --- frames ---------------------------------------------------------

    def _read(self, n):
        got = b""
        while len(got) < n:
            if not select.select([self.fd], [], [], self.timeout)[0]:
                raise PharosError(None, f"nothing from pharos in {self.timeout} s")
            chunk = os.read(self.fd, n - len(got))
            if not chunk:
                raise PharosError(None, "the channel closed")
            got += chunk
        return got

    def _frame(self):
        magic, version, kind, n = struct.unpack("<2sBBI", self._read(8))
        if magic != b"PB" or version != 1 or n > MAX_PAYLOAD:
            raise PharosError(None, "a bad frame from pharos")
        return kind, self._read(n)

    def _send(self, kind, payload):
        if len(payload) > MAX_PAYLOAD:
            raise ValueError("frame too large")
        self._write(struct.pack("<2sBBI", b"PB", 1, kind, len(payload)) + payload)

    def _write(self, data):
        while data:
            data = data[os.write(self.fd, data) :]

    def hello(self):
        """Waits for the bridge's HELLO and answers it: the task and attempt
        this guest now speaks for. Frames of an earlier attempt are skipped."""
        while True:
            kind, p = self._frame()
            if kind == HELLO and len(p) == 5:
                break
        self._send(HELLO, p)
        self.task_id, self.attempt = struct.unpack("<IB", p)
        return self.task_id, self.attempt

    def call(self, msg, data=b""):
        """One agents v1 message and its buffer bytes: the reply message and
        the bytes the operation wrote. A non-OK status raises."""
        if not 2 <= len(msg) <= 256:
            raise ValueError("a message is 2 to 256 bytes")
        self._send(REQUEST, bytes([len(msg)]) + msg + data)
        kind, p = self._frame()
        if kind == ERROR:
            raise PharosError(p[0] if p else None, p[1:].decode(errors="replace"))
        if kind != REPLY or not p or len(p) < 1 + p[0]:
            raise PharosError(None, "a bad reply from pharos")
        reply, out = p[1 : 1 + p[0]], p[1 + p[0] :]
        if not reply or reply[0] != OK:
            raise PharosError(reply[0] if reply else None)
        return reply, out

    # --- operations -----------------------------------------------------

    def task(self):
        reply, data = self.call(bytes([VERSION, TASK]))
        task, attempt, n, cp = struct.unpack("<IBII", reply[1:14])
        return Task(task, attempt, data[:n], data[CHECKPOINT_AT : CHECKPOINT_AT + cp])

    def log(self, text):
        self.call(bytes([VERSION, LOG]) + _text(text))

    def checkpoint(self, data):
        self.call(bytes([VERSION, CHECKPOINT]) + struct.pack("<I", len(data)), data)

    def request(self, route, path, body=b""):
        """An HTTPS request on gateway route `route` (needs `https <route>`)."""
        path = path.encode() if isinstance(path, str) else path
        body = body.encode() if isinstance(body, str) else body
        name = _name(route)
        msg = bytes([VERSION, HTTPS]) + name + struct.pack("<HI", len(path), len(body))
        reply, data = self.call(msg, path + body)
        if len(reply) != 10:
            raise PharosError(None, "a bad gateway reply")
        _, _, http, type_len, answer_len, stripped = struct.unpack("<BBHBIB", reply)
        kind = data[:type_len].decode(errors="replace")
        return Answer(http, kind, data[type_len : type_len + answer_len], stripped)

    def data_put(self, name, data):
        self.call(bytes([VERSION, DATA_PUT]) + _name(name) + struct.pack("<I", len(data)), data)

    def data_get(self, name):
        reply, data = self.call(bytes([VERSION, DATA_GET]) + _name(name))
        (n,) = struct.unpack("<I", reply[1:5])
        return data[:n]

    def ask(self, permission, for_ms=0):
        """Asks for `permission` (wire form, see `https_permission`): GRANTED,
        REFUSED, or PENDING (ask again)."""
        reply, _ = self.call(bytes([VERSION, ASK]) + permission + struct.pack("<I", for_ms))
        return reply[1]

    def complete(self, result):
        result = result.encode() if isinstance(result, str) else result
        self.call(bytes([VERSION, COMPLETE]) + struct.pack("<I", len(result)), result)

    def fail(self, reason):
        self.call(bytes([VERSION, FAIL]) + _text(reason))
