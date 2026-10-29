//! `pharos-infer`: runs the native engine spike on the host (M3.1, #69).
//!
//! Usage:
//! - `pharos-infer <model.bin> <tokenizer.bin> <prompt> <n>`: a llama2.c
//!   model. Prints the text as llama2.c's `run.c` prints it (prompt
//!   included, single unprintable bytes skipped).
//! - `pharos-infer <model.gguf> <token IDs> <n>`: a Qwen2 GGUF model with
//!   Q8_0 weights. The prompt is given as token IDs (for example from
//!   llama.cpp's `llama-tokenize --ids`), so no tokenizer is needed. Prints
//!   only the generated text, as `llama-completion --no-display-prompt`
//!   does: control tokens hidden, stopping at the end-of-text tokens. The
//!   generated token IDs go to stderr.
//!
//! Both generate `n` tokens after the prompt (as llama.cpp's `-n`;
//! llama2.c's `run.c -n` counts the prompt too), then print a newline and
//! one JSON line with `load_ms`, `prompt_tokens`, `prompt_ms`, `gen_tokens`,
//! and `gen_ms` for `scripts/bench-inference.py --engine native`.

use std::io::Write;
use std::process::ExitCode;
use std::time::Instant;

use pharos_infer::gguf::Gguf;
use pharos_infer::qwen2::{Qwen2, Qwen2State, decode_byte_level};
use pharos_infer::{Math, Model, Tokenizer, argmax, generate};

/// The standard library's functions, as `run.c` uses C's.
struct Std;

impl Math for Std {
    fn sqrt(&self, x: f32) -> f32 {
        x.sqrt()
    }
    fn exp(&self, x: f32) -> f32 {
        x.exp()
    }
    fn sin(&self, x: f32) -> f32 {
        x.sin()
    }
    fn cos(&self, x: f32) -> f32 {
        x.cos()
    }
    fn powf(&self, x: f32, y: f32) -> f32 {
        x.powf(y)
    }
}

fn timing_line(
    load_ms: f64,
    prompt_tokens: usize,
    prompt_ms: f64,
    gen_tokens: usize,
    gen_ms: f64,
) -> String {
    format!(
        "{{\"load_ms\": {load_ms:.3}, \"prompt_tokens\": {prompt_tokens}, \"prompt_ms\": {prompt_ms:.3}, \"gen_tokens\": {gen_tokens}, \"gen_ms\": {gen_ms:.3}}}"
    )
}

/// Token IDs from "[1, 2, 3]", "1,2,3", or "1 2 3".
fn parse_ids(text: &str) -> Result<Vec<usize>, String> {
    let ids: Result<Vec<usize>, _> = text
        .split(|c: char| c == ',' || c == '[' || c == ']' || c.is_whitespace())
        .filter(|t| !t.is_empty())
        .map(str::parse)
        .collect();
    match ids {
        Ok(ids) if !ids.is_empty() => Ok(ids),
        _ => Err(format!(
            "the prompt must be token IDs such as \"[7985, 825]\", got '{text}'"
        )),
    }
}

fn run_gguf(args: &[String], bytes: &[u8], start: Instant) -> Result<(), String> {
    let [_, model_path, ids, n] = args else {
        return Err("usage: pharos-infer <model.gguf> <token IDs> <n>".into());
    };
    let n: usize = n
        .parse()
        .map_err(|_| format!("n must be a number, got '{n}'"))?;
    let prompt = parse_ids(ids)?;
    let g = Gguf::parse(bytes).map_err(|e| format!("{model_path}: {e}"))?;
    let tokens = g
        .strings(b"tokenizer.ggml.tokens")
        .map_err(|e| format!("{model_path}: tokens: {e}"))?;
    let types = g
        .ints(b"tokenizer.ggml.token_type")
        .map_err(|e| format!("{model_path}: token types: {e}"))?;
    let model = Qwen2::load(&g, tokens.len()).map_err(|e| format!("{model_path}: {e}"))?;
    let stop: Vec<usize> = [
        &b"tokenizer.ggml.eos_token_id"[..],
        b"tokenizer.ggml.bos_token_id",
    ]
    .iter()
    .filter_map(|k| g.uint(k).ok().and_then(|v| usize::try_from(v).ok()))
    .collect();
    if let Some(bad) = prompt.iter().find(|&&t| t >= tokens.len()) {
        return Err(format!(
            "token ID {bad} is outside the vocabulary of {} tokens",
            tokens.len()
        ));
    }
    let positions = prompt.len() + n;
    if positions > model.config.context {
        return Err(format!(
            "the prompt plus {n} tokens exceeds the model's context of {}",
            model.config.context
        ));
    }
    let load_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mut state = Qwen2State::new(&model.config, positions);
    let t0 = Instant::now();
    let mut logits = Vec::new();
    for (pos, &t) in prompt.iter().enumerate() {
        logits = model.forward(&mut state, t, pos, &Std).to_vec();
    }
    let prompt_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let t1 = Instant::now();
    let mut out = std::io::stdout().lock();
    let mut generated = Vec::new();
    for pos in prompt.len()..positions {
        let next = argmax(&logits);
        generated.push(next);
        if stop.contains(&next) {
            break;
        }
        // Control tokens (type 3) are hidden, as llama.cpp prints by default.
        if types.get(next) != Some(&3) {
            let bytes = decode_byte_level(tokens[next]).unwrap_or_else(|| tokens[next].to_vec());
            out.write_all(&bytes).map_err(|e| e.to_string())?;
        }
        if pos + 1 < positions {
            logits = model.forward(&mut state, next, pos, &Std).to_vec();
        }
    }
    let gen_ms = t1.elapsed().as_secs_f64() * 1000.0;
    writeln!(out).map_err(|e| e.to_string())?;
    writeln!(
        out,
        "{}",
        timing_line(load_ms, prompt.len(), prompt_ms, generated.len(), gen_ms)
    )
    .map_err(|e| e.to_string())?;
    eprintln!("generated ids: {generated:?}");
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    if let Some(path) = args.get(1) {
        let start = Instant::now();
        let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        if bytes.starts_with(b"GGUF") {
            return run_gguf(args, &bytes, start);
        }
    }
    let [_, model_path, tokenizer_path, prompt, steps] = args else {
        return Err("usage: pharos-infer <model.bin> <tokenizer.bin> <prompt> <n>".into());
    };
    let n: usize = steps
        .parse()
        .map_err(|_| format!("n must be a number, got '{steps}'"))?;
    let start = Instant::now();
    let read = |p: &str| std::fs::read(p).map_err(|e| format!("cannot read {p}: {e}"));
    let model = Model::parse(&read(model_path)?).map_err(|e| format!("{model_path}: {e}"))?;
    let tokenizer = Tokenizer::parse(&read(tokenizer_path)?, model.config.vocab_size)
        .map_err(|e| format!("{tokenizer_path}: {e}"))?;
    let load_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Steps 0..prompt-2 replay the prompt; the rest generate.
    let prompt_len = tokenizer.encode(prompt).len();
    let steps = prompt_len - 1 + n;
    if steps > model.config.seq_len {
        return Err(format!(
            "the prompt ({prompt_len} tokens) plus {n} generated tokens exceeds the model's context of {} tokens",
            model.config.seq_len
        ));
    }
    let mut out = std::io::stdout().lock();
    let mut step = 0;
    let mut prompt_end = None;
    let gen_start = Instant::now();
    let (_, generated) = generate(&model, &tokenizer, prompt, steps, &Std, |prev, next| {
        let bytes = tokenizer.decode(prev, next);
        let printable =
            !matches!(bytes.as_slice(), [b] if !(b.is_ascii_graphic() || b.is_ascii_whitespace()));
        if printable {
            let _ = out.write_all(&bytes);
        }
        step += 1;
        if step + 1 == prompt_len {
            prompt_end = Some(gen_start.elapsed());
        }
    });
    let total = gen_start.elapsed();
    let prompt_time = prompt_end.unwrap_or_default();
    let ms = |d: std::time::Duration| d.as_secs_f64() * 1000.0;
    writeln!(out).map_err(|e| e.to_string())?;
    writeln!(
        out,
        "{{\"load_ms\": {load_ms:.3}, \"prompt_tokens\": {}, \"prompt_ms\": {:.3}, \"gen_tokens\": {generated}, \"gen_ms\": {:.3}}}",
        prompt_len.saturating_sub(1),
        ms(prompt_time),
        ms(total - prompt_time),
    )
    .map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
