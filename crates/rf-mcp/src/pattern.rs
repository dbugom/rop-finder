//! ECO-01's `search` parameter — a ropper-style wildcard matcher over a
//! gadget's INSTRUCTION SEQUENCE, not over its rendered text.
//!
//! `--re` / `search_gadgets_by_pattern` already matches a regex against the
//! joined text, and that is the wrong shape for the question people
//! actually ask. `pop rdi ; ret` written as a regex has to worry about the
//! ` ; ` separator, about whether the gadget starts there, and about `[`
//! and `+` inside memory operands being regex metacharacters. Ropper's
//! answer is a tiny glob language over instructions, and it is what an
//! exploit developer already knows how to type:
//!
//! * instructions are separated by `;`
//! * `?` matches exactly one character inside an instruction
//! * `%` matches any run of characters (including none) inside one
//!   instruction, so a bare `%` is "any single instruction"
//!
//! The pattern matches a gadget when its instructions appear as a
//! CONTIGUOUS run somewhere in the gadget — `pop rdi; ret` therefore
//! matches both `pop rdi ; ret` and `xor eax, eax ; pop rdi ; ret`. Anchor
//! the tail by writing the terminator, which is what the examples do.
//!
//! Matching is case-insensitive and whitespace-insensitive: both sides are
//! normalized to `mnemonic op, op` with single spaces, so `mov rax,rbx`
//! and `MOV  RAX , RBX` are the same pattern.

/// A compiled `search` pattern: one glob per instruction, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqPattern {
    insns: Vec<Vec<Tok>>,
}

/// One token of an instruction glob.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// A literal run, already normalized and lowercased.
    Lit(String),
    /// `?` — exactly one character.
    Any,
    /// `%` — any run, including empty.
    Star,
}

/// Normalize an instruction (or one instruction of a pattern) so that
/// spacing and case cannot make two spellings of the same instruction
/// differ: lowercase, single spaces, exactly one space after each comma
/// and none before it.
///
/// Applied to BOTH sides, so it can never make a pattern match something a
/// reader would not call the same instruction.
#[must_use]
pub fn normalize_insn(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for ch in s.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if c == ',' {
            // Never a space before a comma.
            pending_space = false;
            out.push(',');
            continue;
        }
        if pending_space || out.ends_with(',') {
            if !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
        }
        out.push(c);
    }
    out
}

impl SeqPattern {
    /// Compile a `search` string. An empty pattern (or one that is only
    /// separators) is rejected: it would match every gadget and is far more
    /// likely a mistake than a request.
    pub fn parse(pattern: &str) -> Result<SeqPattern, String> {
        let mut insns = Vec::new();
        for part in pattern.split(';') {
            let norm = normalize_insn(part);
            if norm.is_empty() {
                continue;
            }
            insns.push(Self::compile_one(&norm));
        }
        if insns.is_empty() {
            return Err(format!(
                "search pattern {pattern:?} contains no instructions; write something like \
                 \"pop rdi; ret\" (`?` = one character, `%` = any run)"
            ));
        }
        Ok(SeqPattern { insns })
    }

    fn compile_one(norm: &str) -> Vec<Tok> {
        let mut toks: Vec<Tok> = Vec::new();
        let mut lit = String::new();
        for c in norm.chars() {
            match c {
                '?' | '%' => {
                    if !lit.is_empty() {
                        toks.push(Tok::Lit(std::mem::take(&mut lit)));
                    }
                    toks.push(if c == '?' { Tok::Any } else { Tok::Star });
                }
                _ => lit.push(c),
            }
        }
        if !lit.is_empty() {
            toks.push(Tok::Lit(lit));
        }
        toks
    }

    /// Number of instructions in the pattern.
    #[must_use]
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// Does this gadget contain the pattern as a contiguous instruction
    /// run? `insns` are the gadget's instructions as the engine rendered
    /// them; they are normalized here, not by the caller.
    #[must_use]
    pub fn matches(&self, insns: &[String]) -> bool {
        if self.insns.len() > insns.len() {
            return false;
        }
        let norm: Vec<String> = insns.iter().map(|i| normalize_insn(i)).collect();
        let last = norm.len() - self.insns.len();
        (0..=last).any(|start| {
            self.insns.iter().enumerate().all(|(k, pat)| {
                norm.get(start + k)
                    .is_some_and(|actual| glob_match(pat, actual))
            })
        })
    }
}

/// Match one instruction glob against one normalized instruction.
///
/// Iterative backtracking over `Star`, which is bounded by the token count
/// and the instruction length — both tiny — so there is no pathological
/// input here the way there is for a regex.
fn glob_match(pat: &[Tok], text: &str) -> bool {
    fn go(pat: &[Tok], text: &str) -> bool {
        let Some((first, rest)) = pat.split_first() else {
            return text.is_empty();
        };
        match first {
            Tok::Lit(l) => match text.strip_prefix(l.as_str()) {
                Some(tail) => go(rest, tail),
                None => false,
            },
            Tok::Any => {
                let mut it = text.chars();
                match it.next() {
                    Some(_) => go(rest, it.as_str()),
                    None => false,
                }
            }
            Tok::Star => {
                // Every split point, shortest first.
                if go(rest, text) {
                    return true;
                }
                let mut it = text.chars();
                while it.next().is_some() {
                    if go(rest, it.as_str()) {
                        return true;
                    }
                }
                false
            }
        }
    }
    go(pat, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insns(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn normalization_makes_spacing_and_case_irrelevant() {
        assert_eq!(normalize_insn("MOV  RAX , RBX"), "mov rax, rbx");
        assert_eq!(normalize_insn("mov rax,rbx"), "mov rax, rbx");
        assert_eq!(normalize_insn("  ret "), "ret");
        assert_eq!(
            normalize_insn("mov qword ptr [rdi + 8], rsi"),
            "mov qword ptr [rdi + 8], rsi"
        );
    }

    /// The example from the shared query spec, and the contiguity rule.
    #[test]
    fn the_canonical_pattern_matches_the_canonical_gadget() {
        let p = SeqPattern::parse("pop rdi; ret").unwrap();
        assert_eq!(p.len(), 2);
        assert!(!p.matches(&insns(&["pop", "rdi"])));
        assert!(p.matches(&insns(&["pop rdi", "ret"])));
        // A prefix in front is fine; the run is contiguous.
        assert!(p.matches(&insns(&["xor eax, eax", "pop rdi", "ret"])));
        // A gap is not.
        assert!(!p.matches(&insns(&["pop rdi", "nop", "ret"])));
        assert!(!p.matches(&insns(&["pop rsi", "ret"])));
    }

    #[test]
    fn question_mark_is_one_character_and_percent_is_a_run() {
        let p = SeqPattern::parse("pop r?i; ret").unwrap();
        assert!(p.matches(&insns(&["pop rdi", "ret"])));
        assert!(p.matches(&insns(&["pop rsi", "ret"])));
        assert!(!p.matches(&insns(&["pop rdx", "ret"])));
        // `?` is exactly one, so it does not span two.
        assert!(!SeqPattern::parse("pop ?; ret")
            .unwrap()
            .matches(&insns(&["pop rdi", "ret"])));

        let p = SeqPattern::parse("pop %; ret").unwrap();
        assert!(p.matches(&insns(&["pop rdi", "ret"])));
        assert!(p.matches(&insns(&["pop r15", "ret"])));

        // A bare `%` is any single instruction.
        let p = SeqPattern::parse("%; ret").unwrap();
        assert!(p.matches(&insns(&["pop rdi", "ret"])));
        assert!(p.matches(&insns(&["ret", "ret"])));
        assert!(!p.matches(&insns(&["ret"])));
    }

    #[test]
    fn memory_operands_are_literal_not_regex() {
        // `[`, `+` and `*` would all be metacharacters to a regex.
        let p = SeqPattern::parse("mov qword ptr [rdi + 8], rsi; ret").unwrap();
        assert!(p.matches(&insns(&["mov qword ptr [rdi + 8], rsi", "ret"])));
        assert!(!p.matches(&insns(&["mov qword ptr [rdi + 9], rsi", "ret"])));
    }

    #[test]
    fn an_empty_pattern_is_refused_rather_than_matching_everything() {
        for bad in ["", "   ", ";;", " ; ; "] {
            assert!(SeqPattern::parse(bad).is_err(), "{bad:?} was accepted");
        }
    }

    /// Trailing/leading separators are tolerated, because a human writing
    /// `pop rdi; ret;` means the same thing.
    #[test]
    fn stray_separators_are_tolerated() {
        let p = SeqPattern::parse(" ; pop rdi ;; ret ; ").unwrap();
        assert_eq!(p.len(), 2);
        assert!(p.matches(&insns(&["pop rdi", "ret"])));
    }

    /// A star next to a literal backtracks correctly instead of taking the
    /// first split it finds.
    #[test]
    fn star_backtracks() {
        let p = SeqPattern::parse("mov %, rax").unwrap();
        assert!(p.matches(&insns(&["mov rdi, rax"])));
        assert!(p.matches(&insns(&["mov qword ptr [rbx + 8], rax"])));
        assert!(!p.matches(&insns(&["mov rdi, rbx"])));
    }
}
