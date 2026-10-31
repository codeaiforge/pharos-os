#!/usr/bin/env python3
"""Compare pharos-infer's Qwen2 tokenizer with llama.cpp's `llama-tokenize`
on the benchmark prompts and a corpus of hard cases (#84). Standard library
only; it installs and downloads nothing.

Usage:
    python3 scripts/compare-tokenizer.py --model MODEL.gguf \\
        --llama-tokenize /path/llama-tokenize [--pharos target/release/pharos-infer]

Exits 0 only if every case gives identical token IDs. Build pharos-infer
first: cargo build --release -p pharos-infer.
"""

import argparse
import ast
import importlib.util
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

CASES = [
    ("ascii", "Hello world, it's 2026!"),
    ("contractions", "I'm sure you've seen it; they'll go, he'd know. DON'T SHOUT, We'RE here, 'tis"),
    ("apostrophes", "rock 'n' roll, the '90s, O'Brien's, ''quoted''"),
    ("digits", "3.14159 1,000,000 2026-10-31 0x7f 12345678901234567890"),
    ("spaces", "a  b   c    d"),
    ("tabs-newlines", "a\t\tb\n\nc \r\n d   \n   e    "),
    ("trailing-space", "end with spaces   "),
    ("only-spaces", "      "),
    ("leading-newline", "\n\nstart"),
    ("crlf", "line one\r\nline two\r\n\r\nline four"),
    ("punctuation", "Hello!!! ...wait?! (yes) [no] {maybe} <tag> --flag=1 a/b\\c @#$%^&*"),
    ("space-punct", "a , b . c ; d :: e"),
    ("german", "Grüße aus Köln, naïve café, Straße"),
    ("russian", "Привет, мир! Как дела?"),
    ("greek", "Γειά σου Κόσμε, Ελλάδα"),
    ("chinese", "你好，世界！我是通义千问。"),
    ("japanese", "日本語のテキストです。カタカナも。"),
    ("korean", "한국어 텍스트입니다"),
    ("arabic", "مرحبا بالعالم ١٢٣"),
    ("devanagari", "हिन्दी पाठ, नमस्ते"),
    ("thai", "สวัสดีชาวโลก"),
    ("emoji", "emoji 😀👍🏽 🇬🇷 ❤️ done"),
    ("combining", "é ä ño"),
    ("ligature-circled", "ﬁne ﬂow Ⓐ Ⓑ ⓒ"),
    ("number-letters", "Ⅻ Ⅳ ½ ¾ ² ³"),
    ("invisible", "a​b a b a　b a b"),
    ("control-chars", "a\x00b\x07c\x1bd"),
    ("specials", "<|im_start|>system\nYou are helpful.<|im_end|>\n<|im_start|>user\nHi<|im_end|>\n<|im_start|>assistant\n"),
    ("special-eot", "text<|endoftext|>more"),
    ("special-partial", "<|im_start <|im_end| <|endoftext"),
    ("special-tools", "<tool_call>{\"name\": \"f\"}</tool_call>"),
    ("code", "fn main() {\n    println!(\"hi\");\n}\n"),
    ("indented", "    four\n\ttab\n        eight"),
    ("long-word", "a" * 3000),
    ("long-spaces", " " * 300 + "x"),
    ("long-digits", "1" * 60),
    ("url", "https://example.com/path?q=1&r=two#frag"),
    ("mixed", "The café's 3 crêpes cost €12.50 — naïvely, 10% off!"),
]


def benchmark_prompts():
    spec = importlib.util.spec_from_file_location("bench", ROOT / "scripts/bench-inference.py")
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    return [(f"bench-{name}", text) for name, text in bench.PROMPTS]


def ids(output):
    """The last line that parses as a list of integers."""
    for line in reversed(output.strip().splitlines()):
        try:
            value = ast.literal_eval(line.strip())
        except (ValueError, SyntaxError):
            continue
        if isinstance(value, list) and all(isinstance(v, int) for v in value):
            return value
    raise ValueError(f"no token list in output: {output[-300:]!r}")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model", required=True)
    p.add_argument("--llama-tokenize", required=True)
    p.add_argument("--pharos", default=str(ROOT / "target/release/pharos-infer"))
    args = p.parse_args(argv)
    failures = 0
    cases = benchmark_prompts() + CASES
    with tempfile.TemporaryDirectory() as tmp:
        for name, text in cases:
            path = pathlib.Path(tmp) / "case.txt"
            path.write_bytes(text.encode("utf-8"))
            ref = subprocess.run(
                [args.llama_tokenize, "-m", args.model, "-f", str(path), "--ids", "--log-disable"],
                capture_output=True, text=True, timeout=120,
            )
            ours = subprocess.run(
                [args.pharos, "tokenize", args.model, str(path)],
                capture_output=True, text=True, timeout=120,
            )
            if ref.returncode != 0 or ours.returncode != 0:
                print(f"FAIL {name}: llama-tokenize exit {ref.returncode}, pharos-infer exit {ours.returncode}: {ours.stderr.strip()}")
                failures += 1
                continue
            a, b = ids(ref.stdout), ids(ours.stdout)
            if a == b:
                print(f"ok   {name} ({len(a)} tokens)")
            else:
                at = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
                print(f"FAIL {name}: first difference at token {at}: llama {a[at:at + 6]} pharos {b[at:at + 6]} ({len(a)} vs {len(b)} tokens)")
                failures += 1
    print(f"{len(cases) - failures} of {len(cases)} cases identical")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
