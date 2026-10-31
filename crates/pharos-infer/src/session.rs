//! Generation sessions: a loaded model with its tokenizer ([`Engine`]), and
//! one request on it ([`Session`]): the prompt in blocks, then greedy
//! decoding one token at a time, each token's text decoded as llama.cpp
//! prints it (control tokens hidden), stopping at an end-of-text token or
//! the token limit. The inference service and the host's reference outputs
//! run this same code (#88).

use alloc::vec::Vec;

use crate::bpe;
use crate::gguf::Gguf;
use crate::qwen2::{MAX_BATCH, Qwen2, Qwen2State, decode_byte_level};
use crate::{Error, Math, argmax};

/// Token type of control tokens (`<|im_start|>`, `<|endoftext|>`).
const CONTROL: i128 = 3;

/// A Qwen2 model with its tokenizer; borrows the file's bytes.
pub struct Engine<'a> {
    pub model: Qwen2<'a>,
    pub tokenizer: bpe::Tokenizer<'a>,
    pieces: Vec<&'a [u8]>,
    types: Vec<i128>,
    /// End-of-text tokens: generation stops at them.
    pub(crate) stop: Vec<usize>,
}

impl<'a> Engine<'a> {
    /// Loads the model and its tokenizer from a parsed GGUF file.
    pub fn load(g: &Gguf<'a>) -> Result<Self, Error> {
        let pieces = g.strings(b"tokenizer.ggml.tokens")?;
        let types = g.ints(b"tokenizer.ggml.token_type")?;
        let model = Qwen2::load(g, pieces.len())?;
        let tokenizer = bpe::Tokenizer::from_gguf(g)?;
        let stop = [
            &b"tokenizer.ggml.eos_token_id"[..],
            b"tokenizer.ggml.bos_token_id",
        ]
        .iter()
        .filter_map(|k| g.uint(k).ok().and_then(|v| usize::try_from(v).ok()))
        .collect();
        Ok(Self {
            model,
            tokenizer,
            pieces,
            types,
            stop,
        })
    }

    /// Appends the bytes token `t` adds to the text (none for control
    /// tokens).
    fn text(&self, t: usize, out: &mut Vec<u8>) {
        if self.types.get(t) == Some(&CONTROL) {
            return;
        }
        let piece = self.pieces[t];
        match decode_byte_level(piece) {
            Some(bytes) => out.extend_from_slice(&bytes),
            None => out.extend_from_slice(piece),
        }
    }
}

/// Why generation ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// The model produced an end-of-text token (not part of the text).
    EndOfText,
    /// The requested number of tokens was generated.
    TokenLimit,
}

/// One generation: the key/value cache and the next token's logits.
pub struct Session<'e, 'a> {
    engine: &'e Engine<'a>,
    state: Qwen2State,
    logits: Vec<f32>,
    pos: usize,
    max_new: usize,
    generated: usize,
    stop: Option<Stop>,
}

impl<'e, 'a> Session<'e, 'a> {
    /// Runs `prompt` (non-empty, every token in the vocabulary) and gets
    /// ready to generate up to `max_new` (at least 1) tokens. The prompt
    /// plus `max_new` must fit the model's context; the cache is allocated
    /// for exactly that many positions.
    pub fn new(
        engine: &'e Engine<'a>,
        prompt: &[u32],
        max_new: usize,
        m: &impl Math,
    ) -> Result<Self, Error> {
        let c = &engine.model.config;
        let positions = prompt.len().checked_add(max_new).ok_or(Error::BadConfig)?;
        if prompt.is_empty()
            || max_new == 0
            || positions > c.context
            || prompt.iter().any(|&t| t as usize >= c.vocab_size)
        {
            return Err(Error::BadConfig);
        }
        let mut state = Qwen2State::new(c, positions);
        let ids: Vec<usize> = prompt.iter().map(|&t| t as usize).collect();
        let mut logits = Vec::new();
        for (i, block) in ids.chunks(MAX_BATCH).enumerate() {
            logits = engine
                .model
                .forward_batch(&mut state, block, i * MAX_BATCH, m)
                .to_vec();
        }
        Ok(Self {
            engine,
            state,
            logits,
            pos: prompt.len(),
            max_new,
            generated: 0,
            stop: None,
        })
    }

    /// Generates one token and appends its text to `out`. Returns false
    /// once generation has ended (then [`Session::stop`] says why).
    pub fn step(&mut self, out: &mut Vec<u8>, m: &impl Math) -> bool {
        if self.stop.is_some() {
            return false;
        }
        let next = argmax(&self.logits);
        if self.engine.stop.contains(&next) {
            self.stop = Some(Stop::EndOfText);
            return false;
        }
        self.engine.text(next, out);
        self.generated += 1;
        if self.generated == self.max_new {
            self.stop = Some(Stop::TokenLimit);
            return false;
        }
        self.logits = self
            .engine
            .model
            .forward(&mut self.state, next, self.pos, m)
            .to_vec();
        self.pos += 1;
        true
    }

    /// Tokens generated so far (end-of-text not counted).
    pub fn generated(&self) -> usize {
        self.generated
    }

    pub fn stop(&self) -> Option<Stop> {
        self.stop
    }
}
