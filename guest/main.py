"""The guest's agent (#299, bridge.md): an unmodified LangGraph graph that
uses Pharos through two tools, `pharos_log` and `pharos_https`, and never
sees a socket, a header, or a secret. The model is scripted (fixed answers
that call the tools) until the model broker (M6.9).

It prints what it checks to the guest's serial console, which the host
keeps as a file: the boot check (Python, LangGraph, the network interfaces
and ports), then each tool's outcome and the task's end.
"""

import os
import sys
from importlib.metadata import version

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

from pharos_bridge import Bridge, PharosError

print("guest: python", sys.version.split()[0], "langgraph", version("langgraph"))
print("guest: net", sorted(os.listdir("/sys/class/net")))
print("guest: ports", sorted(os.listdir("/dev/virtio-ports")))

bridge = Bridge()
task_id, attempt = bridge.hello()
print("guest: bound task", task_id, "attempt", attempt)
task = bridge.task()
print("guest: task input", task.input.decode(errors="replace"))


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
out = g.compile().invoke({"messages": [HumanMessage(task.input.decode(errors="replace"))]})

for m in out["messages"]:
    if m.type == "tool":
        print(f"guest: tool {m.name}: {m.content}")
answer = out["messages"][-1].content
try:
    bridge.complete(answer)
    print("guest: completed", answer)
except PharosError as e:
    print("guest: complete refused, status", e.status)
