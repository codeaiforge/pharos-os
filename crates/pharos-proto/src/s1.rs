//! Scenario S1 with the model driving an agent (#190, testing.md "S1 end
//! to end"): the prompts, in Qwen2.5-Instruct's own tool template, that
//! the `s1` agent on Pharos and `cargo xtask s1` on the host both build.
//! Turn 1 offers `read_file`; the model's call runs through the runtime's
//! `TOOL`; turn 2 is turn 1, the model's text, and the file as the tool's
//! response.

/// Turn 1: the system prompt with the tool, and the user's request.
pub const PROMPT: &str = include_str!("s1-prompt.txt");
/// After the model's turn-1 text, before the file.
pub const RESPONSE_BEFORE: &str = "<|im_end|>\n<|im_start|>user\n<tool_response>\n";
/// After the file.
pub const RESPONSE_AFTER: &str = "\n</tool_response><|im_end|>\n<|im_start|>assistant\n";
/// New tokens for each turn: the call (21 tokens on the host), the answer.
pub const CALL_TOKENS: u16 = 32;
pub const ANSWER_TOKENS: u16 = 128;

/// The text between the model's `<tool_call>` tags, or `None`.
pub fn call(text: &[u8]) -> Option<&[u8]> {
    let (open, close) = (b"<tool_call>", b"</tool_call>");
    let start = text.windows(open.len()).position(|w| w == open)? + open.len();
    let len = text[start..]
        .windows(close.len())
        .position(|w| w == close)?;
    Some(&text[start..start + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_call_is_between_the_tags() {
        let text = b"<tool_call>\n{\"name\": \"read_file\"}\n</tool_call>";
        assert_eq!(call(text), Some(&b"\n{\"name\": \"read_file\"}\n"[..]));
        assert_eq!(call(b"no call"), None);
        assert_eq!(call(b"<tool_call>{} unclosed"), None);
        assert!(PROMPT.ends_with("<|im_start|>assistant\n"));
    }
}
