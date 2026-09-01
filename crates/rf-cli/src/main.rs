//! rop-finder — ROPgadget-compatible CLI (Phase 0: x86/x64 ELF).
//!
//! Exit codes: 0 success, 1 usage error, 2 malformed/unsupported binary.

use std::process::ExitCode;

use clap::Parser;
use rf_core::{Binary, ElfClass};
use rf_scan::{Gadget, ScanOptions};
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(
    name = "rop-finder",
    version,
    about = "Fast Rust ROP/JOP/SYS gadget finder (ROPgadget rewrite)"
)]
struct Cli {
    /// Specify a binary filename to analyze
    #[arg(long)]
    binary: String,

    /// Depth for search engine (default 10)
    #[arg(long, default_value_t = 10)]
    depth: usize,

    /// Disable ROP search engine
    #[arg(long)]
    norop: bool,

    /// Disable JOP search engine
    #[arg(long)]
    nojop: bool,

    /// Disable SYS search engine
    #[arg(long)]
    nosys: bool,

    /// Enable multiple branch gadgets
    #[arg(long)]
    multibr: bool,

    /// Only show specific instructions (e.g. "pop|ret|mov")
    #[arg(long)]
    only: Option<String>,

    /// Suppress specific mnemonics (suffix match, e.g. "leave|enter")
    #[arg(long)]
    filter: Option<String>,

    /// Search between two addresses (0x...-0x...)
    #[arg(long)]
    range: Option<String>,

    /// Rejects specific bytes in the gadget's address (e.g. "0a|0d" or "00-1f")
    #[arg(long)]
    badbytes: Option<String>,

    /// Specify an offset for gadget addresses (hex)
    #[arg(long)]
    offset: Option<String>,

    /// Rebase the binary to this image base at load time (hex)
    #[arg(long)]
    base: Option<String>,

    /// Emit a JSON array of {vaddr, bytes, text} instead of human output
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct JsonGadget {
    vaddr: String,
    bytes: String,
    text: String,
}

fn parse_hex(s: &str, what: &str) -> Result<u64, String> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).map_err(|e| format!("invalid {what} {s:?}: {e}"))
}

/// ROPgadget --range syntax: "0xSTART-0xEND". "0x0-0x0" means no range.
fn parse_range(s: &str) -> Result<Option<(u64, u64)>, String> {
    let (a, b) = s
        .split_once('-')
        .ok_or_else(|| format!("invalid --range {s:?} (expected 0x...-0x...)"))?;
    let start = parse_hex(a, "--range start")?;
    let end = parse_hex(b, "--range end")?;
    if start == 0 && end == 0 {
        return Ok(None);
    }
    if start > end {
        return Err(format!("invalid --range {s:?} (start > end)"));
    }
    Ok(Some((start, end)))
}

/// ROPgadget --badbytes syntax: "bb|bb|lo-hi" (hex bytes, ranges inclusive).
fn parse_badbytes(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for part in s.split('|') {
        if part.is_empty() {
            continue; // ROPgadget ignores empty items
        }
        if let Some((lo, hi)) = part.split_once('-') {
            let lo = parse_hex(lo, "--badbytes range low")?;
            let hi = parse_hex(hi, "--badbytes range high")?;
            if lo > 0xff || hi > 0xff || lo > hi {
                return Err(format!("invalid --badbytes range {part:?}"));
            }
            out.extend((lo as u8)..=(hi as u8));
        } else {
            let b = parse_hex(part, "--badbytes byte")?;
            if b > 0xff {
                return Err(format!("invalid --badbytes byte {part:?}"));
            }
            out.push(b as u8);
        }
    }
    Ok(out)
}

fn run(cli: Cli) -> Result<i32, String> {
    if cli.depth < 2 {
        return Err("--depth must be >= 2".to_string());
    }
    let bytes = std::fs::read(&cli.binary)
        .map_err(|e| format!("cannot read {}: {e}", cli.binary))?;

    let mut bin = match Binary::parse(&bytes) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[Error] {e}");
            return Ok(2);
        }
    };
    if let Some(base) = &cli.base {
        bin.rebase(parse_hex(base, "--base")?);
    }

    let opts = ScanOptions {
        depth: cli.depth,
        rop: !cli.norop,
        jop: !cli.nojop,
        sys: !cli.nosys,
        multibr: cli.multibr,
        only: cli
            .only
            .as_deref()
            .map(|s| s.split('|').map(|x| x.to_string()).collect()),
        range: match &cli.range {
            Some(r) => parse_range(r)?,
            None => None,
        },
        badbytes: match &cli.badbytes {
            Some(b) => parse_badbytes(b)?,
            None => Vec::new(),
        },
        filter: cli
            .filter
            .as_deref()
            .map(|s| s.split('|').map(|x| x.to_string()).collect())
            .unwrap_or_default(),
        offset: match &cli.offset {
            Some(o) => parse_hex(o, "--offset")?,
            None => 0,
        },
    };

    let gadgets = match rf_scan::scan_binary(&bin, &opts) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("[Error] {e}");
            return Ok(2);
        }
    };

    if cli.json {
        print_json(&gadgets, bin.class());
    } else {
        print_human(&gadgets, bin.class());
    }
    Ok(0)
}

fn fmt_addr(vaddr: u64, class: ElfClass) -> String {
    match class {
        ElfClass::Bit32 => format!("0x{vaddr:08x}"),
        ElfClass::Bit64 => format!("0x{vaddr:016x}"),
    }
}

fn print_human(gadgets: &[Gadget], class: ElfClass) {
    println!("Gadgets information");
    println!("============================================================");
    for g in gadgets {
        println!("{} : {}", fmt_addr(g.vaddr, class), g.text());
    }
    println!("\nUnique gadgets found: {}", gadgets.len());
}

fn print_json(gadgets: &[Gadget], class: ElfClass) {
    let out: Vec<JsonGadget> = gadgets
        .iter()
        .map(|g| JsonGadget {
            vaddr: fmt_addr(g.vaddr, class),
            bytes: g.bytes_hex(),
            text: g.text(),
        })
        .collect();
    // Serialization of this simple structure cannot fail.
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // clap exit code 2 -> our usage exit code 1
            let _ = e.print();
            return ExitCode::from(1);
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code as u8),
        Err(msg) => {
            eprintln!("[Error] {msg}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn badbytes_parsing() {
        assert_eq!(parse_badbytes("0a|0d").unwrap(), vec![0x0a, 0x0d]);
        assert_eq!(parse_badbytes("00-03|ff").unwrap(), vec![0, 1, 2, 3, 0xff]);
        assert_eq!(parse_badbytes("0a|").unwrap(), vec![0x0a]); // trailing | ok
        assert!(parse_badbytes("0x100").is_err());
        assert!(parse_badbytes("zz").is_err());
    }

    #[test]
    fn range_parsing() {
        assert_eq!(parse_range("0x0-0x0").unwrap(), None);
        assert_eq!(parse_range("0x1000-0x2000").unwrap(), Some((0x1000, 0x2000)));
        assert!(parse_range("0x2000-0x1000").is_err());
        assert!(parse_range("nonsense").is_err());
    }

    #[test]
    fn hex_parsing() {
        assert_eq!(parse_hex("0x41414141", "x").unwrap(), 0x41414141);
        assert_eq!(parse_hex("ff", "x").unwrap(), 0xff);
        assert!(parse_hex("0xz", "x").is_err());
    }
}
