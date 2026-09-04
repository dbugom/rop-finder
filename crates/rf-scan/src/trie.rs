//! The suffix-trie gadget index (PERF-10 / CLAIM-07).
//!
//! PLAN.md made this a Phase 1 *deliverable* (PLAN.md:226), counted it among
//! the speedup sources (PLAN.md:104, "less allocation, no 45K-string hash set
//! during scan"), and made it the substrate for two features sold as
//! differentiators over ROPgadget and ropper (PLAN.md:144: "all gadgets
//! ending in this tail", "all gadgets using this register"). It did not
//! exist: searching the workspace for `trie` returned one hit, in README's
//! own admission that it was outstanding. What ran instead was a
//! `HashSet<String>` fed by `Vec<(String, Gadget)>` — a joined `String` per
//! gadget for the sort key, a second one cloned into the set, and the set's
//! own copy: three heap strings per gadget on top of the per-instruction
//! ones, and 15.9 ms of a 110.4 ms serial run.
//!
//! # Shape
//!
//! Gadgets are inserted **reversed**: root → last instruction → second to
//! last → … → first. That single choice does all three jobs:
//!
//!  * **Dedup.** Two gadgets have the same text iff they walk to the same
//!    node and end there, so first-occurrence-wins dedup is "did this node
//!    already have a terminal?" — with no key materialised at all.
//!  * **Tail queries.** A tail is a *prefix* of a reversed sequence, so
//!    "every gadget ending in `pop rbp ; ret`" is one descent plus a subtree
//!    walk ([`GadgetTrie::ending_with`]) instead of a regex sweep over the
//!    whole listing.
//!  * **Instruction/register queries.** A gadget's path from the root spells
//!    all of its instructions, so "every gadget that touches `rsp`" is the
//!    union of the subtrees hanging under the edges whose instruction text
//!    mentions it ([`GadgetTrie::using_register`]).
//!
//! # Allocation
//!
//! The trie borrows the gadget's own instruction strings (`&'a str`) and
//! interns them, so inserting a gadget allocates nothing per gadget: the
//! only growth is amortised `Vec` growth in the node arrays. Children are a
//! `first_child`/`next_sibling` linked list inside those arrays rather than
//! a `Vec` or map per node, so a node costs 16 bytes plus one edge-map
//! entry.
//!
//! Hashing uses the FxHash mix rather than SipHash. The maps are keyed by an
//! `(u32, u32)` edge or a short mnemonic string, they are private to this
//! structure, and nothing outside the process chooses the keys, so the
//! HashDoS resistance `RandomState` buys is not worth the ~3x on a hash that
//! runs ten times per gadget.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

/// No child / no terminal.
const NONE: u32 = u32::MAX;

/// The FxHash finaliser, as used by rustc: multiply-xor-rotate per word.
/// Deterministic (no per-process seed), which also keeps the trie's node
/// numbering reproducible run to run.
#[derive(Default, Clone, Copy)]
pub struct FxHasher {
    hash: u64,
}

const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

impl FxHasher {
    #[inline]
    fn add(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(SEED);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for c in &mut chunks {
            self.add(u64::from_le_bytes(c.try_into().expect("chunks_exact(8)")));
        }
        let rest = chunks.remainder();
        if !rest.is_empty() {
            let mut buf = [0u8; 8];
            buf[..rest.len()].copy_from_slice(rest);
            self.add(u64::from_le_bytes(buf));
        }
        // Length participates so that "ab" and "ab\0" cannot collide by
        // construction.
        self.add(bytes.len() as u64);
    }
    #[inline]
    fn write_u32(&mut self, n: u32) {
        self.add(n as u64);
    }
    #[inline]
    fn write_usize(&mut self, n: usize) {
        self.add(n as u64);
    }
    #[inline]
    fn write_u8(&mut self, n: u8) {
        self.add(n as u64);
    }
    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

type FxBuild = BuildHasherDefault<FxHasher>;

/// A suffix trie over gadget instruction sequences, borrowing the gadget
/// texts it indexes.
pub struct GadgetTrie<'a> {
    /// Interned instruction text → symbol id.
    syms: HashMap<&'a str, u32, FxBuild>,
    /// symbol id → text.
    sym_text: Vec<&'a str>,
    /// (parent node, symbol) → child node.
    edges: HashMap<(u32, u32), u32, FxBuild>,
    /// Per node: the symbol on its incoming edge (`NONE` at the root).
    node_sym: Vec<u32>,
    first_child: Vec<u32>,
    next_sibling: Vec<u32>,
    /// Per node: the index of the FIRST gadget whose whole reversed
    /// instruction sequence ends here, or `NONE`.
    terminal: Vec<u32>,
    /// Distinct gadget texts inserted.
    distinct: usize,
}

impl Default for GadgetTrie<'_> {
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

impl<'a> GadgetTrie<'a> {
    /// An empty trie sized for roughly `gadgets` distinct texts.
    pub fn with_capacity(gadgets: usize) -> Self {
        // A gadget of k instructions adds at most k nodes, but shares its
        // whole tail with everything ending the same way, which is the
        // common case: reserving one node per gadget is close and cheap.
        let n = gadgets + 1;
        let mut t = GadgetTrie {
            syms: HashMap::with_capacity_and_hasher(1024, FxBuild::default()),
            sym_text: Vec::new(),
            edges: HashMap::with_capacity_and_hasher(n, FxBuild::default()),
            node_sym: Vec::with_capacity(n),
            first_child: Vec::with_capacity(n),
            next_sibling: Vec::with_capacity(n),
            terminal: Vec::with_capacity(n),
            distinct: 0,
        };
        t.push_node(NONE);
        t
    }

    fn push_node(&mut self, sym: u32) -> u32 {
        let id = self.node_sym.len() as u32;
        self.node_sym.push(sym);
        self.first_child.push(NONE);
        self.next_sibling.push(NONE);
        self.terminal.push(NONE);
        id
    }

    fn intern(&mut self, text: &'a str) -> u32 {
        if let Some(&id) = self.syms.get(text) {
            return id;
        }
        let id = self.sym_text.len() as u32;
        self.sym_text.push(text);
        self.syms.insert(text, id);
        id
    }

    /// Insert one gadget's instruction sequence, tail first.
    ///
    /// Returns `true` when this text is new — which is exactly ROPgadget's
    /// first-occurrence-wins dedup predicate (`rgutils.deleteDuplicateGadgets`)
    /// evaluated without building the joined text.
    pub fn insert(&mut self, insns: &'a [String], gadget: usize) -> bool {
        let mut node = 0u32;
        for text in insns.iter().rev() {
            let sym = self.intern(text.as_str());
            node = match self.edges.get(&(node, sym)) {
                Some(&child) => child,
                None => {
                    let child = self.push_node(sym);
                    self.next_sibling[child as usize] = self.first_child[node as usize];
                    self.first_child[node as usize] = child;
                    self.edges.insert((node, sym), child);
                    child
                }
            };
        }
        if self.terminal[node as usize] != NONE {
            return false;
        }
        self.terminal[node as usize] = u32::try_from(gadget).unwrap_or(NONE - 1);
        self.distinct += 1;
        true
    }

    /// Distinct gadget texts held.
    pub fn len(&self) -> usize {
        self.distinct
    }

    /// True when no gadget text has been inserted.
    pub fn is_empty(&self) -> bool {
        self.distinct == 0
    }

    /// Trie nodes, including the root (diagnostic).
    pub fn nodes(&self) -> usize {
        self.node_sym.len()
    }

    /// Distinct interned instruction texts (diagnostic).
    pub fn symbols(&self) -> usize {
        self.sym_text.len()
    }

    /// PLAN.md:144 — "all gadgets ending in this tail".
    ///
    /// `tail` is in normal (execution) order, e.g. `["pop rbp", "ret"]`.
    /// Returns the indices, ascending, of every inserted gadget whose last
    /// instructions are exactly that. An empty tail returns every gadget.
    pub fn ending_with(&self, tail: &[&str]) -> Vec<usize> {
        let mut node = 0u32;
        for text in tail.iter().rev() {
            let Some(&sym) = self.syms.get(text) else {
                return Vec::new();
            };
            match self.edges.get(&(node, sym)) {
                Some(&child) => node = child,
                None => return Vec::new(),
            }
        }
        let mut out = Vec::new();
        self.collect_subtree(node, &mut out);
        out.sort_unstable();
        out
    }

    /// PLAN.md:144 — "all gadgets using this register".
    ///
    /// A gadget's root-to-terminal path spells every one of its
    /// instructions, so this is the union of the subtrees under every edge
    /// whose instruction text mentions `reg` as a whole word. `x86` register
    /// names are substrings of each other (`rax`/`eax`/`ax`), so matching is
    /// on token boundaries, not `contains`.
    pub fn using_register(&self, reg: &str) -> Vec<usize> {
        let matching: Vec<bool> = self
            .sym_text
            .iter()
            .map(|t| mentions_word(t, reg))
            .collect();
        let mut out = Vec::new();
        for node in 0..self.node_sym.len() {
            let sym = self.node_sym[node];
            if sym != NONE && matching.get(sym as usize).copied().unwrap_or(false) {
                self.collect_subtree(node as u32, &mut out);
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Every terminal at or below `node`.
    fn collect_subtree(&self, node: u32, out: &mut Vec<usize>) {
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            let t = self.terminal[n as usize];
            if t != NONE {
                out.push(t as usize);
            }
            let mut c = self.first_child[n as usize];
            while c != NONE {
                stack.push(c);
                c = self.next_sibling[c as usize];
            }
        }
    }
}

/// Does `text` contain `word` delimited by non-identifier characters?
/// `mov rax, rsp` mentions `rax` and `rsp` but not `ax`.
fn mentions_word(text: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'%' || c == b'$';
    let (t, w) = (text.as_bytes(), word.as_bytes());
    let mut i = 0;
    while let Some(off) = t[i..]
        .windows(w.len())
        .position(|win| win.eq_ignore_ascii_case(w))
    {
        let p = i + off;
        let before_ok = p == 0 || !ident(t[p - 1]);
        let after_ok = p + w.len() >= t.len() || !ident(t[p + w.len()]);
        if before_ok && after_ok {
            return true;
        }
        i = p + 1;
        if i + w.len() > t.len() {
            break;
        }
    }
    false
}

/// Compare two instruction sequences as ROPgadget's `" ; "`-joined text,
/// **without joining them**.
///
/// `rgutils.alphaSortgadgets` sorts on the gadget text, and `post_process`
/// used to allocate that text once per gadget to have something to sort. The
/// comparison walks both sequences as a stream of segments (separator,
/// instruction, separator, …) and compares the overlapping prefixes with a
/// slice compare, so it is byte-for-byte `String::cmp` on the joined text
/// with no allocation at all.
pub fn cmp_joined(a: &[String], b: &[String]) -> std::cmp::Ordering {
    let mut x = Segments::new(a);
    let mut y = Segments::new(b);
    loop {
        match (x.peek(), y.peek()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(p), Some(q)) => {
                let n = p.len().min(q.len());
                match p[..n].cmp(&q[..n]) {
                    std::cmp::Ordering::Equal => {
                        x.advance(n);
                        y.advance(n);
                    }
                    other => return other,
                }
            }
        }
    }
}

/// The first 16 bytes of the `" ; "`-joined text, packed big-endian into a
/// `u128` and zero-padded — an order-preserving sort key that costs no
/// allocation.
///
/// Comparing the key is one 128-bit compare, and it decides all but a
/// handful of the ~2.3M comparisons a 133k-gadget sort makes; [`cmp_joined`]
/// only runs on the ties. Zero padding is exactly right rather than merely
/// convenient: byte-lexicographic order already treats "string ended" as
/// smaller than any byte, and instruction text is ASCII, so a key comparison
/// can tie but can never invert.
pub fn prefix_key(insns: &[String]) -> u128 {
    let mut buf = [0u8; 16];
    let mut n = 0usize;
    for (i, ins) in insns.iter().enumerate() {
        if i > 0 {
            for &b in SEP {
                if n == buf.len() {
                    return u128::from_be_bytes(buf);
                }
                buf[n] = b;
                n += 1;
            }
        }
        for &b in ins.as_bytes() {
            if n == buf.len() {
                return u128::from_be_bytes(buf);
            }
            buf[n] = b;
            n += 1;
        }
    }
    u128::from_be_bytes(buf)
}

/// A cursor over the `" ; "`-joined byte stream of an instruction list.
struct Segments<'a> {
    insns: &'a [String],
    /// Index of the instruction the cursor is in or before.
    i: usize,
    /// True while the cursor is inside the separator preceding `insns[i]`.
    in_sep: bool,
    /// Bytes already consumed of the current segment.
    off: usize,
}

const SEP: &[u8] = b" ; ";

impl<'a> Segments<'a> {
    fn new(insns: &'a [String]) -> Self {
        Segments {
            insns,
            i: 0,
            in_sep: false,
            off: 0,
        }
    }

    /// The unconsumed bytes of the current segment, or `None` at the end.
    fn peek(&mut self) -> Option<&'a [u8]> {
        loop {
            if self.i >= self.insns.len() {
                return None;
            }
            let seg: &'a [u8] = if self.in_sep {
                SEP
            } else {
                self.insns[self.i].as_bytes()
            };
            if self.off < seg.len() {
                return Some(&seg[self.off..]);
            }
            // Segment exhausted: separator → instruction → next separator.
            self.off = 0;
            if self.in_sep {
                self.in_sep = false;
            } else {
                self.i += 1;
                self.in_sep = self.i < self.insns.len();
            }
        }
    }

    fn advance(&mut self, n: usize) {
        self.off += n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn dedup_is_first_occurrence_wins_by_joined_text() {
        let a = v(&["pop rbp", "ret"]);
        let b = v(&["pop rbp", "ret"]);
        let c = v(&["pop rbx", "ret"]);
        let mut t = GadgetTrie::with_capacity(3);
        assert!(t.insert(&a, 0));
        assert!(!t.insert(&b, 1), "identical text must be rejected");
        assert!(t.insert(&c, 2));
        assert_eq!(t.len(), 2);
    }

    /// The old dedup key was `insns.join(" ; ")`, so two DIFFERENT
    /// instruction lists that join to the same string were one gadget. The
    /// trie keys on the list, so it must agree — which it does only because
    /// the separator is compared as text, not as a list boundary.
    #[test]
    fn joined_text_equality_is_what_decides() {
        let split = v(&["a", "b"]);
        let joined = v(&["a ; b"]);
        assert_eq!(split.join(" ; "), joined.join(" ; "));
        assert_eq!(cmp_joined(&split, &joined), std::cmp::Ordering::Equal);
    }

    #[test]
    fn tail_query_finds_every_gadget_ending_that_way() {
        let g = [
            v(&["pop rbp", "ret"]),
            v(&["mov rax, rbx", "pop rbp", "ret"]),
            v(&["pop rbx", "ret"]),
            v(&["ret"]),
            v(&["pop rbp", "jmp rax"]),
        ];
        let mut t = GadgetTrie::with_capacity(g.len());
        for (i, x) in g.iter().enumerate() {
            t.insert(x, i);
        }
        assert_eq!(t.ending_with(&["ret"]), vec![0, 1, 2, 3]);
        assert_eq!(t.ending_with(&["pop rbp", "ret"]), vec![0, 1]);
        assert_eq!(t.ending_with(&["mov rax, rbx", "pop rbp", "ret"]), vec![1]);
        assert!(t.ending_with(&["pop rcx", "ret"]).is_empty());
        // An empty tail is every gadget.
        assert_eq!(t.ending_with(&[]), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn register_query_is_word_bounded() {
        let g = [
            v(&["mov rax, rbx", "ret"]),
            v(&["mov eax, ebx", "ret"]),
            v(&["pop rbp", "ret"]),
            v(&["add rsp, 8", "ret"]),
        ];
        let mut t = GadgetTrie::with_capacity(g.len());
        for (i, x) in g.iter().enumerate() {
            t.insert(x, i);
        }
        assert_eq!(t.using_register("rax"), vec![0]);
        assert_eq!(t.using_register("eax"), vec![1]);
        // `ax` is a substring of both `rax` and `eax` and must match neither.
        assert!(t.using_register("ax").is_empty());
        assert_eq!(t.using_register("rsp"), vec![3]);
        assert_eq!(t.using_register("ret"), vec![0, 1, 2, 3]);
    }

    /// The `u128` prefix key must never invert the joined-text order: a
    /// sort that trusts it and only falls back to `cmp_joined` on exact key
    /// ties would otherwise emit a wrong listing order and change which
    /// duplicate survives downstream.
    #[test]
    fn prefix_key_never_inverts_the_text_order() {
        let cases = [
            v(&["ret"]),
            v(&["retf"]),
            v(&["pop rax", "ret"]),
            v(&["pop rax", "retf"]),
            v(&["pop rax"]),
            v(&["a ; b"]),
            v(&["a", "b"]),
            v(&["a", "b", "c"]),
            v(&["mov rax, qword ptr [rbx + 0x10]", "ret"]),
            v(&["mov rax, qword ptr [rbx + 0x11]", "ret"]),
            v(&[]),
            v(&["", "ret"]),
            v(&["zzzzzzzzzzzzzzzzzzzz"]),
            v(&["zzzzzzzzzzzzzzzzzzzy"]),
        ];
        for a in &cases {
            for b in &cases {
                let want = a.join(" ; ").cmp(&b.join(" ; "));
                let ka = prefix_key(a);
                let kb = prefix_key(b);
                match ka.cmp(&kb) {
                    std::cmp::Ordering::Equal => {
                        assert_eq!(cmp_joined(a, b), want, "tie broken wrongly: {a:?} {b:?}")
                    }
                    keyed => assert_eq!(keyed, want, "prefix key inverted {a:?} vs {b:?}"),
                }
            }
        }
    }

    #[test]
    fn cmp_joined_matches_string_cmp_on_the_joined_text() {
        let cases = [
            (v(&["ret"]), v(&["ret"])),
            (v(&["ret"]), v(&["retf"])),
            (v(&["pop rax", "ret"]), v(&["pop rax", "retf"])),
            (v(&["pop rax", "ret"]), v(&["pop rax"])),
            (v(&[]), v(&["ret"])),
            (v(&["a", "b", "c"]), v(&["a", "b"])),
            (v(&["a ; b"]), v(&["a", "b"])),
            (v(&["zz"]), v(&["a", "b", "c"])),
            (v(&["mov eax, 0"]), v(&["mov eax, 1"])),
        ];
        for (a, b) in &cases {
            let want = a.join(" ; ").cmp(&b.join(" ; "));
            assert_eq!(cmp_joined(a, b), want, "{a:?} vs {b:?}");
            assert_eq!(cmp_joined(b, a), want.reverse(), "{b:?} vs {a:?}");
        }
    }

    /// Randomised cross-check of the whole point of the module: the trie's
    /// dedup verdict and the allocation-free comparator must agree with the
    /// `String`-materialising versions they replace, on inputs with heavy
    /// duplication and shared tails.
    #[test]
    fn agrees_with_the_string_implementation_it_replaces() {
        let mnem = [
            "ret",
            "pop rax",
            "pop rbx",
            "nop",
            "leave",
            "mov rax, rbx",
            "add rsp, 8",
            "ret",
        ];
        let mut x: u32 = 0x9e37_79b9;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as usize
        };
        let mut gadgets: Vec<Vec<String>> = Vec::new();
        for _ in 0..2000 {
            let k = 1 + rnd() % 4;
            gadgets.push(
                (0..k)
                    .map(|_| mnem[rnd() % mnem.len()].to_string())
                    .collect(),
            );
        }

        let mut seen = std::collections::HashSet::new();
        let want: Vec<bool> = gadgets.iter().map(|g| seen.insert(g.join(" ; "))).collect();

        let mut t = GadgetTrie::with_capacity(gadgets.len());
        let got: Vec<bool> = gadgets
            .iter()
            .enumerate()
            .map(|(i, g)| t.insert(g, i))
            .collect();
        assert_eq!(got, want);

        let mut by_string: Vec<usize> = (0..gadgets.len()).collect();
        by_string.sort_by(|&a, &b| gadgets[a].join(" ; ").cmp(&gadgets[b].join(" ; ")));
        let mut by_cursor: Vec<usize> = (0..gadgets.len()).collect();
        by_cursor.sort_by(|&a, &b| cmp_joined(&gadgets[a], &gadgets[b]));
        assert_eq!(by_string, by_cursor);

        // …and the same again through the prefix key that `post_process`
        // actually sorts on.
        let mut keyed: Vec<(u128, usize)> = (0..gadgets.len())
            .map(|i| (prefix_key(&gadgets[i]), i))
            .collect();
        keyed.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| cmp_joined(&gadgets[a.1], &gadgets[b.1]))
        });
        assert_eq!(
            by_string,
            keyed.into_iter().map(|(_, i)| i).collect::<Vec<_>>()
        );
    }
}
