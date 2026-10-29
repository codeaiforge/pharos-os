#!/usr/bin/env python3
"""Host tests for scripts/bench-inference.py (#68).

Run: python3 -m unittest scripts/test_bench_inference.py
"""

import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import textwrap
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bench", HERE / "bench-inference.py")
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)
# Scratch space stays under target/, like everything the scripts write.
TMP = bench.OUT_DIR
TMP.mkdir(parents=True, exist_ok=True)

# Timing lines as llama.cpp prints them, quoted from its documentation
# (docs/multimodal/MobileVLM.md and docs/backend/snapdragon/README.md in
# github.com/ggml-org/llama.cpp, MIT): the older prefix with a load time, and
# the current prefix without one. Not recorded on this host.
LLAMA_OLD = """\
 A group of llamas are walking together in a field.

llama_print_timings:        load time =    5506.60 ms
llama_print_timings:      sample time =       0.44 ms /    13 runs   (    0.03 ms per token, 29545.45 tokens per second)
llama_print_timings: prompt eval time =    2031.58 ms /   190 tokens (   10.69 ms per token,    93.52 tokens per second)
llama_print_timings:        eval time =     438.92 ms /    12 runs   (   36.58 ms per token,    27.34 tokens per second)
llama_print_timings:       total time =    5990.25 ms /   202 tokens
"""
LLAMA_NEW = """\
llama_perf_context_print: prompt eval time =    3843.67 ms /   197 tokens ( 19.51 ms per token, 51.25 tokens per second)
llama_perf_context_print:        eval time =    1686.13 ms /    31 runs   ( 54.39 ms per token, 18.39 tokens per second)
llama_perf_context_print:       total time =    6266.30 ms /   228 tokens
"""

# Recorded on the reference host with llama.cpp build b11609
# (llama-completion, Qwen2.5-0.5B-Instruct q8_0, 1 thread, LC_NUMERIC=el_GR).
LLAMA_B11609 = """\
0.02.040.469 I common_perf_print:    sampling time =       8,69 ms
0.02.040.470 I common_perf_print:    samplers time =       3,48 ms /    40 tokens
0.02.040.473 I common_perf_print:        load time =     337,46 ms
0.02.040.474 I common_perf_print: prompt eval time =     111,25 ms /     8 tokens (   13,91 ms per token,    71,91 tokens per second)
0.02.040.474 I common_perf_print:        eval time =    1286,72 ms /    31 runs   (   41,51 ms per token,    24,09 tokens per second)
0.02.040.475 I common_perf_print:       total time =    1407,62 ms /    39 tokens
"""

# A stand-in engine for end-to-end runs: echoes its prompt's first word,
# allocates `alloc` MiB, and prints a native timing line.
FAKE = textwrap.dedent("""\
    import json, sys
    prompt, alloc = sys.argv[1], int(sys.argv[2])
    block = bytearray(alloc * 1024 * 1024)
    for i in range(0, len(block), 4096):
        block[i] = 1
    print("echo:", prompt.split()[0])
    print(json.dumps({"load_ms": 5.0, "prompt_tokens": 10, "prompt_ms": 20.0,
                      "gen_tokens": 8, "gen_ms": 400.0}))
    """)


class Parsing(unittest.TestCase):
    def test_llama_old_prefix_with_load_time(self):
        t = bench.parse_llama(LLAMA_OLD)
        self.assertEqual(t["load_ms"], 5506.60)
        self.assertEqual((t["prompt_tokens"], t["prompt_ms"]), (190, 2031.58))
        self.assertEqual((t["gen_tokens"], t["gen_ms"]), (12, 438.92))
        self.assertAlmostEqual(t["gen_tok_s"], 27.34, places=2)
        self.assertAlmostEqual(t["prompt_tok_s"], 93.52, places=2)

    def test_llama_new_prefix_without_load_time(self):
        t = bench.parse_llama(LLAMA_NEW)
        self.assertIsNone(t["load_ms"])
        self.assertEqual((t["prompt_tokens"], t["gen_tokens"]), (197, 31))
        self.assertAlmostEqual(t["gen_tok_s"], 18.39, places=2)

    def test_llama_b11609_with_timestamps_and_decimal_commas(self):
        t = bench.parse_llama(LLAMA_B11609)
        self.assertEqual(t["load_ms"], 337.46)
        self.assertEqual((t["prompt_tokens"], t["prompt_ms"]), (8, 111.25))
        self.assertEqual((t["gen_tokens"], t["gen_ms"]), (31, 1286.72))
        self.assertAlmostEqual(t["gen_tok_s"], 24.09, places=2)

    def test_llama_without_timings_is_an_error(self):
        with self.assertRaisesRegex(bench.BenchError, "no llama.cpp timing lines"):
            bench.parse_llama("some text\nllama_perf_context_print: total time = 1 ms\n")

    def test_native_reads_the_last_line(self):
        out = 'text\n{"load_ms": 1, "prompt_tokens": 4, "prompt_ms": 2, "gen_tokens": 10, "gen_ms": 500}\n'
        t = bench.parse_native(out)
        self.assertEqual(t["gen_tok_s"], 20.0)
        self.assertEqual(t["prompt_tok_s"], 2000.0)

    def test_native_malformed_is_an_error(self):
        for bad in ["", "not json", '{"load_ms": 1}', "[1, 2]"]:
            with self.assertRaisesRegex(bench.BenchError, "last line must be a JSON object"):
                bench.parse_native(bad)


class Commands(unittest.TestCase):
    def test_placeholders_are_filled_per_argument(self):
        cmd = bench.fill(["e", "-m", "{model}", "-p", "{prompt}", "-t", "{threads}"],
                         {"model": "m.gguf", "prompt": "a b c", "n": 1, "threads": 2, "seed": 42})
        self.assertEqual(cmd, ["e", "-m", "m.gguf", "-p", "a b c", "-t", "2"])

    def test_unknown_placeholder_is_an_error(self):
        with self.assertRaisesRegex(bench.BenchError, "unknown placeholder"):
            bench.fill(["e", "{temperature}"], {"model": "m"})

    def test_other_braces_pass_through(self):
        self.assertEqual(bench.fill(['{"a": 1}', "{model}"], {"model": "m"}), ['{"a": 1}', "m"])

    def test_prompts_can_be_selected(self):
        self.assertEqual([n for n, _ in bench.selected(["summary"])], ["summary"])
        self.assertEqual(bench.selected(None), bench.PROMPTS)
        with self.assertRaisesRegex(bench.BenchError, "unknown prompt 'long'"):
            bench.selected(["long"])

    def test_missing_binary_is_named(self):
        with self.assertRaisesRegex(bench.BenchError, "engine binary not found: /nonexistent/llama"):
            bench.measure(["/nonexistent/llama", "-h"])


class Measuring(unittest.TestCase):
    def test_peak_memory_and_wall_time(self):
        code, wall, rss, out, _ = bench.measure(
            [sys.executable, "-c", FAKE, "hello", "64"])
        self.assertEqual(code, 0)
        self.assertGreater(rss, 64 * 1024, "peak RSS covers the 64 MiB allocation")
        self.assertGreater(wall, 0)
        self.assertIn("echo: hello", out)

    def test_end_to_end_with_a_stand_in_engine(self):
        with tempfile.TemporaryDirectory(dir=TMP) as d:
            model = pathlib.Path(d) / "tiny.bin"
            model.write_bytes(b"weights")
            code = bench.main([
                "--engine", "native", "--model", str(model), "--label", "tiny test/1",
                "--runs", "2", "--out-dir", d, "--",
                sys.executable, "-c", FAKE, "{prompt}", "1",
            ])
            self.assertEqual(code, 0)
            [path] = pathlib.Path(d).glob("native-tiny-test-1-*.json")
            record = json.loads(path.read_text())
            self.assertEqual(record["model"]["sha256"], hashlib.sha256(b"weights").hexdigest())
            self.assertEqual(record["model"]["bytes"], 7)
            self.assertEqual(len(record["results"]), 2 * len(bench.PROMPTS))
            first = record["results"][0]
            self.assertEqual((first["prompt"], first["gen_tok_s"]), ("short", 20.0))
            self.assertEqual(first["output"], "echo: Write")
            self.assertEqual(record["seed"], bench.SEED)
            self.assertIn("simd", record["host"])

    def test_missing_model_and_failing_engine_are_reported(self):
        with tempfile.TemporaryDirectory(dir=TMP) as d:
            self.assertEqual(bench.main([
                "--engine", "native", "--model", f"{d}/none.gguf", "--label", "x", "--", "true"]), 1)
            model = pathlib.Path(d) / "m.bin"
            model.write_bytes(b"m")
            args = bench.argparse.Namespace(
                engine="native", model=str(model), label="x", threads=1, runs=1, n=4,
                version_cmd=None, prompt=None, out_dir=d, command=[sys.executable, "-c", "import sys; sys.exit(3)"])
            with self.assertRaisesRegex(bench.BenchError, "exited with status 3"):
                bench.run(args)


if __name__ == "__main__":
    unittest.main()
