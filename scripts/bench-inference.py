#!/usr/bin/env python3
"""Benchmark an inference engine's command-line tool on the host (M3.1, #68).

Usage:
    python3 scripts/bench-inference.py --engine llama --model MODEL.gguf \\
        --label "qwen2.5-0.5b q4_k_m" --threads 1 --runs 3 \\
        --version-cmd "/path/llama-completion --version" \\
        -- /path/llama-completion -m {model} -p {prompt} -n {n} \\
           -t {threads} -s {seed} --temp 0 -no-cnv

Everything after `--` is the engine's command line. The placeholders {model},
{prompt}, {n}, {threads}, and {seed} are filled in for each run; check the
flags against your build of the engine.

Engines (how their output is read):
    llama   llama.cpp tools that print `common_perf_print:` (build b11609),
            `llama_perf_context_print:`, or `llama_print_timings:` lines:
            prompt and generation timings, and the load time when printed.
    native  Pharos's own engine: its last stdout line is one JSON object with
            load_ms, prompt_tokens, prompt_ms, gen_tokens, gen_ms.

For every prompt and run it records the engine's timings, the wall time and
peak resident memory of the process (from wait4), the exit status, and the
generated text with its SHA-256 (for output comparison between engines).
Results go to target/bench/<engine>-<label>-<time>.json and are never
committed.

Read-only apart from target/bench/: it installs and downloads nothing, and
stops with a message naming what is missing. Uses only the standard library.
"""

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "target" / "bench"
SEED = 42

# A one-page text written for this harness (no third-party content), used
# for the first agent scenario S1: summarize a granted file.
REPORT = """\
The harbour authority met on Tuesday to review the winter maintenance plan.
The main breakwater lost about forty metres of armour stone in the November
storms, and divers found two cracked concrete blocks near the lighthouse.
Repairs will start in March, when the sea is calmer, and are expected to take
six weeks. During that time the northern berth will be closed, and fishing
boats will moor at the eastern quay instead.

The committee also discussed the lighthouse itself. Its lamp was converted to
LED two years ago, which cut power use by most of a half, but the backup
battery bank is now ten years old and failed its last load test. A
replacement has been ordered and should arrive before the repairs begin.

Finally, the treasurer reported that the repair budget is sufficient if the
stone can be sourced from the local quarry. If it must be shipped from
abroad, costs would rise by roughly a third, and the committee would need to
postpone the planned new crane until the following year. A decision on the
supplier is due at the next meeting.
"""

PROMPTS = [
    ("short", "Write one sentence about lighthouses."),
    ("summary", "Summarize the following report in three sentences.\n\n" + REPORT),
]

# Older builds print `llama_print_timings:`, documented ones
# `llama_perf_context_print:`, and build b11609 `common_perf_print:` after a
# timestamp and level. The decimal separator follows the locale (`337,46`).
TIMING = re.compile(
    r"(?:^|\s)(?:llama_perf_context_print|llama_print_timings|common_perf_print):\s*"
    r"(?P<what>load time|prompt eval time|eval time)\s*=\s*(?P<ms>\d+(?:[.,]\d+)?) ms"
    r"(?:\s*/\s*(?P<count>\d+) (?:tokens|runs))?"
)


PLACEHOLDER = re.compile(r"\{(\w+)\}")


class BenchError(Exception):
    """A problem the user must fix, with a message saying what to do."""


def parse_llama(output):
    """Timings from llama.cpp's performance lines (stdout and stderr)."""
    found = {}
    for line in output.splitlines():
        m = TIMING.search(line.strip())
        if m:
            ms = float(m["ms"].replace(",", "."))
            found[m["what"]] = (ms, int(m["count"]) if m["count"] else None)
    if "prompt eval time" not in found or "eval time" not in found:
        raise BenchError(
            "no llama.cpp timing lines (common_perf_print: or llama_perf_context_print: prompt eval time "
            "and eval time) in the output; is this a llama.cpp tool, and did it finish?"
        )
    prompt_ms, prompt_tokens = found["prompt eval time"]
    gen_ms, gen_tokens = found["eval time"]
    return timings(found.get("load time", (None, None))[0], prompt_tokens, prompt_ms, gen_tokens, gen_ms)


def parse_native(output):
    """Timings from the native engine's last stdout line (one JSON object)."""
    lines = [line for line in output.splitlines() if line.strip()]
    try:
        report = json.loads(lines[-1]) if lines else None
        values = [report[k] for k in ("load_ms", "prompt_tokens", "prompt_ms", "gen_tokens", "gen_ms")]
    except (ValueError, TypeError, KeyError) as e:
        raise BenchError(
            "the native engine's last line must be a JSON object with load_ms, "
            f"prompt_tokens, prompt_ms, gen_tokens, and gen_ms ({e!r})"
        ) from None
    return timings(*values)


def timings(load_ms, prompt_tokens, prompt_ms, gen_tokens, gen_ms):
    def rate(tokens, ms):
        return round(tokens * 1000 / ms, 3) if tokens and ms else None

    return {
        "load_ms": load_ms,
        "prompt_tokens": prompt_tokens,
        "prompt_ms": prompt_ms,
        "prompt_tok_s": rate(prompt_tokens, prompt_ms),
        "gen_tokens": gen_tokens,
        "gen_ms": gen_ms,
        "gen_tok_s": rate(gen_tokens, gen_ms),
    }


ENGINES = {"llama": parse_llama, "native": parse_native}


def fill(template, values):
    """The command for one run: each argument with its placeholders filled."""
    # Only {name} tokens are placeholders, so arguments with other braces
    # (JSON, grammars) pass through unchanged.
    def one(m):
        if m[1] not in values:
            raise BenchError(
                f"unknown placeholder {m[0]} in the engine command; use {{model}}, "
                "{prompt}, {n}, {threads}, {seed}"
            )
        return str(values[m[1]])

    return [PLACEHOLDER.sub(one, arg) for arg in template]


def measure(cmd):
    """Runs cmd; returns (exit status, wall seconds, peak RSS in KiB, stdout, stderr)."""
    if not cmd:
        raise BenchError("no engine command given after --")
    exe = cmd[0]
    if shutil.which(exe) is None:
        raise BenchError(
            f"engine binary not found: {exe}; build or install it (see "
            "docs/project/inference-evaluation.md) and pass its path"
        )
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile(dir=OUT_DIR) as out, tempfile.TemporaryFile(dir=OUT_DIR) as err:
        start = time.monotonic()
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        _, status, usage = os.wait4(proc.pid, 0)
        wall = time.monotonic() - start
        proc.returncode = os.waitstatus_to_exitcode(status)
        out.seek(0)
        err.seek(0)
        return (
            proc.returncode,
            wall,
            usage.ru_maxrss,  # KiB on Linux
            out.read().decode("utf-8", "replace"),
            err.read().decode("utf-8", "replace"),
        )


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def host_info():
    info = {"kernel": platform.release(), "machine": platform.machine()}
    try:
        cpu = pathlib.Path("/proc/cpuinfo").read_text()
        name = re.search(r"^model name\s*:\s*(.+)$", cpu, re.M)
        flags = set(re.search(r"^flags\s*:\s*(.+)$", cpu, re.M).group(1).split())
        info["cpu"] = name.group(1) if name else None
        info["simd"] = sorted(flags & {"sse2", "avx", "avx2", "fma", "f16c", "avx512f"})
        info["logical_cpus"] = os.cpu_count()
        mem = re.search(r"^MemTotal:\s*(\d+) kB", pathlib.Path("/proc/meminfo").read_text(), re.M)
        info["mem_kib"] = int(mem.group(1)) if mem else None
    except (OSError, AttributeError):
        pass
    return info


def selected(names):
    """The prompts to run: all, or those named (in the given order)."""
    if not names:
        return PROMPTS
    known = dict(PROMPTS)
    unknown = [n for n in names if n not in known]
    if unknown:
        raise BenchError(f"unknown prompt {unknown[0]!r}; choose from {', '.join(known)}")
    return [(n, known[n]) for n in names]


def run(args):
    model = pathlib.Path(args.model)
    if not model.is_file():
        raise BenchError(f"model file not found: {model}; download it (see docs/project/inference-evaluation.md)")
    parse = ENGINES[args.engine]
    version = None
    if args.version_cmd:
        try:
            v = subprocess.run(shlex.split(args.version_cmd), capture_output=True, text=True, timeout=60)
            version = (v.stdout + v.stderr).strip()[-500:]
        except OSError as e:
            raise BenchError(f"version command failed: {e}") from None
    results = []
    for name, prompt in selected(args.prompt):
        for i in range(args.runs):
            cmd = fill(args.command, {"model": model, "prompt": prompt, "n": args.n, "threads": args.threads, "seed": SEED})
            code, wall, rss, out, err = measure(cmd)
            if code != 0:
                tail = "\n".join((err or out).splitlines()[-10:])
                raise BenchError(f"engine exited with status {code} on prompt '{name}':\n{tail}")
            report = parse_llama(out + "\n" + err) if parse is parse_llama else parse(out)
            text = out if parse is parse_llama else "\n".join(out.splitlines()[:-1])
            results.append({
                "prompt": name, "run": i + 1, "wall_s": round(wall, 3), "max_rss_kib": rss,
                **report, "output_sha256": hashlib.sha256(text.encode()).hexdigest(), "output": text,
            })
    record = {
        "engine": args.engine,
        "label": args.label,
        "version": version,
        "command": args.command,
        "threads": args.threads,
        "n": args.n,
        "seed": SEED,
        "model": {"path": str(model), "bytes": model.stat().st_size, "sha256": sha256(model)},
        "host": host_info(),
        "date": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "results": results,
    }
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", args.label).strip("-") or "model"
    path = out_dir / f"{args.engine}-{safe}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    path.write_text(json.dumps(record, indent=2) + "\n")
    return path, record


def summary(record):
    lines = [f"{record['engine']} / {record['label']} ({record['threads']} threads, n={record['n']})"]
    for name in dict.fromkeys(r["prompt"] for r in record["results"]):
        rows = [r for r in record["results"] if r["prompt"] == name]

        def med(key):
            values = [r[key] for r in rows if r[key] is not None]
            return statistics.median(values) if values else None

        same = len({r["output_sha256"] for r in rows}) == 1
        lines.append(
            f"  {name:8} gen {med('gen_tok_s')} tok/s, prompt {med('prompt_tok_s')} tok/s, "
            f"load {med('load_ms')} ms, peak {med('max_rss_kib')} KiB, "
            f"output {'identical' if same else 'DIFFERS'} across {len(rows)} runs"
        )
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--engine", choices=sorted(ENGINES), required=True)
    p.add_argument("--model", required=True, help="model file (hashed and recorded)")
    p.add_argument("--label", required=True, help="model name and quantization, for the record")
    p.add_argument("--threads", type=int, default=1)
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("-n", type=int, default=128, help="tokens to generate")
    p.add_argument("--version-cmd", help="command that prints the engine's version")
    p.add_argument("--prompt", action="append", help="run only this prompt (repeatable): short, summary")
    p.add_argument("--out-dir", default=str(OUT_DIR))
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- then the engine command")
    args = p.parse_args(argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    try:
        path, record = run(args)
    except BenchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(summary(record))
    print(f"results: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
