"""The guest's agent (#299, #300, bridge.md): an unmodified LangGraph graph
that uses Pharos through two tools, `pharos_log` and `pharos_https`, and
never sees a socket, a header, or a secret. The model is scripted (fixed
answers that call the tools) until the model broker (M6.9).

It prints what it checks to the guest's serial console, which the host
keeps as a file. First what the guest can reach: Python, LangGraph, the
network interfaces, disks, shared mounts, virtio devices, and ports, and
a connection to the host. Then, for each attempt the bridge binds, the
case its task's input names:

- `agent`: the LangGraph graph (a log, a granted HTTPS request), a
  checkpoint, and the answer;
- `refusals`: what the guest agent is not granted (a route, a path, a
  permission, its data), each refused while the attempt goes on;
- a hostile case (`magic`, `version`, `kind`, `length`, `message`, `data`,
  `notpassed`, `early`, `flood`): a frame the bridge must refuse, or 1 MiB
  of bytes that are none, ending the task with the bridge's `ERROR`;
- `again`: completes, so Pharos still binds after the hostile cases;
- `hold`: on its first attempt, logs and waits (the test kernel then kills
  the bridge, whose restart ends the attempt); completes on its second.
"""

import os
import socket
import struct
import sys
from importlib.metadata import version

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

import pharos_bridge as pb
from pharos_bridge import Bridge, PharosError


def say(*words):
    print("guest:", *words, flush=True)


# What the guest can reach, before any attempt.
say("python", sys.version.split()[0], "langgraph", version("langgraph"))
say("net", sorted(os.listdir("/sys/class/net")))
# Block devices with hardware behind them (not ram or loop devices).
say("disks", sorted(d for d in os.listdir("/sys/block") if os.path.exists(f"/sys/block/{d}/device")))
with open("/proc/mounts") as f:
    kinds = [line.split()[2] for line in f]
say("shared mounts", [k for k in kinds if k in ("9p", "virtiofs", "nfs", "nfs4", "cifs", "fuse")])
say("virtio devices", len(os.listdir("/sys/bus/virtio/devices")))
say("ports", sorted(os.listdir("/dev/virtio-ports")))
try:
    socket.create_connection(("10.0.2.2", 47450), timeout=3).close()
    say("connect 10.0.2.2: connected")
except OSError as e:
    say("connect 10.0.2.2: unreachable", e.errno)

bridge = Bridge()


@tool
def pharos_log(text: str) -> str:
    """Writes one line to Pharos's console, as this agent."""
    bridge.log(text)
    return "logged"


@tool
def pharos_https(route: str, path: str) -> str:
    """GET `path` on the Pharos gateway route `route`."""
    try:
        a = bridge.request(route, path)
    except PharosError as e:
        return f"refused, status {e.status}"
    return f"{a.http} {a.body.decode(errors='replace')}"


TOOLS = [pharos_log, pharos_https]


def call(name, **args):
    return {"name": name, "args": args, "id": f"call-{name}", "type": "tool_call"}


# The scripted model: what it says after each number of its own turns.
SCRIPT = [
    AIMessage(content="", tool_calls=[call("pharos_log", text="hello from the guest's log")]),
    AIMessage(content="", tool_calls=[call("pharos_https", route="items", path="/items")]),
    AIMessage(content="hello from the guest"),
]


def model(state: MessagesState):
    turns = sum(isinstance(m, AIMessage) for m in state["messages"])
    return {"messages": [SCRIPT[min(turns, len(SCRIPT) - 1)]]}


g = StateGraph(MessagesState)
g.add_node("model", model)
g.add_node("tools", ToolNode(TOOLS))
g.add_edge(START, "model")
g.add_conditional_edges("model", tools_condition)
g.add_edge("tools", "model")
graph = g.compile()


def agent(task):
    out = graph.invoke({"messages": [HumanMessage(task.input.decode(errors="replace"))]})
    for m in out["messages"]:
        if m.type == "tool":
            say(f"tool {m.name}: {m.content}")
    bridge.checkpoint(b"graph done")
    say("checkpointed")
    return out["messages"][-1].content


def status(f, *args):
    """The status `f` is refused with, or None if it is not."""
    try:
        f(*args)
    except PharosError as e:
        return e.status
    return None


def refusals(task):
    got = {
        "a route not granted": status(bridge.request, "other", "/items"),
        "a path the route refuses": status(bridge.request, "items", "/admin"),
        "data not granted": status(bridge.data_put, "notes", b"x"),
    }
    want = {
        "a route not granted": pb.NO_ACCESS,
        "a path the route refuses": pb.BAD_REQUEST,
        "data not granted": pb.NO_ACCESS,
    }
    for what in want:
        say(f"refused {what}: status {got[what]}")
    asked = bridge.ask(pb.https_permission("other"), 1000)
    say("asked for a route not granted:", "refused" if asked == pb.REFUSED else asked)
    if got != want or asked != pb.REFUSED:
        return None
    return "refusals ok"


def frame(kind, payload, magic=b"PB", ver=1, length=None):
    n = len(payload) if length is None else length
    return struct.pack("<2sBBI", magic, ver, kind, n) + payload


def request(msg, data=b""):
    return frame(pb.REQUEST, bytes([len(msg)]) + msg + data)


# What each hostile case writes, in one write.
HOSTILE = {
    "magic": frame(pb.REQUEST, b"", magic=b"XX"),
    "version": frame(pb.REQUEST, b"", ver=2),
    "kind": frame(9, b""),
    "length": frame(pb.REQUEST, b"", length=pb.MAX_PAYLOAD + 1),
    "message": frame(pb.REQUEST, b"\x00"),
    # CHECKPOINT of 5 bytes with 3.
    "data": request(bytes([1, pb.CHECKPOINT]) + struct.pack("<I", 5), b"abc"),
    # USAGE, a control client's request, not on the bridge's list.
    "notpassed": request(bytes([1, 22])),
    # A second request before the first's reply.
    "early": request(bytes([1, pb.LOG]) + b"one") + request(bytes([1, pb.LOG]) + b"two"),
    # A flood: 1 MiB of bytes that are no frame, as fast as the port takes them.
    "flood": b"\xff" * (1 << 20),
}


def hostile(name):
    bridge._write(HOSTILE[name])
    try:
        while True:
            kind, p = bridge._frame()
            if kind == pb.ERROR:
                return f"error {p[0]} {p[1:].decode(errors='replace')}"
            if kind == pb.REPLY:
                return "answered, not refused"
    except PharosError as e:
        return f"no error frame: {e.reason}"


while True:
    try:
        task_id, attempt = bridge.hello()
        say("bound task", task_id, "attempt", attempt)
        task = bridge.task()
        case = task.input.decode(errors="replace")
        say("task input", case)
        if case in HOSTILE:
            say(f"case {case}: {hostile(case)}")
            continue
        if case == "hold" and task.attempt == 1:
            bridge.log("holding")
            say("case hold: holding attempt 1")
            continue
        result = {"agent": agent, "refusals": refusals, "again": lambda t: "again ok", "hold": lambda t: "held ok"}.get(case, lambda t: None)(task)
        if result is None:
            bridge.fail(f"case {case} failed")
            say(f"case {case}: failed")
        else:
            bridge.complete(result)
            say("completed", result)
    except PharosError as e:
        say("refused, status", e.status, e.reason)
        if e.reason == "the channel closed":
            break
