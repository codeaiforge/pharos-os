//! `pharos-infer`: runs the native engine spike on the host (M3.1, #69).
//!
//! Usage: `pharos-infer <model.bin> <tokenizer.bin> <prompt> <n>`
//!
//! Generates `n` tokens after the prompt (as llama.cpp's `-n`; llama2.c's
//! `run.c -n` counts the prompt too, so pass it the prompt length plus `n`).
//!
//! Prints the text as llama2.c's `run.c` prints it (prompt included, single
//! unprintable bytes skipped), then a newline and one JSON line with
//! `load_ms`, `prompt_tokens`, `prompt_ms`, `gen_tokens`, and `gen_ms` for
//! `scripts/bench-inference.py --engine native`.

use std::io::Write;
use std::process::ExitCode;
use std::time::Instant;

use pharos_infer::{Math, Model, Tokenizer, generate};

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

fn run(args: &[String]) -> Result<(), String> {
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
