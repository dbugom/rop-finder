//! Phase 6: ROPgadget's interactive console (core.py:264-656, a
//! `cmd.Cmd` REPL). Prompt, messages ("setted" typo included), empty-line
//! repeat, and EOF=quit semantics mirror the oracle, which was verified
//! empirically against scripted stdin.
//!
//! Extensions over the oracle (documented in MANUAL.md): `string`,
//! `opcode`, and `memstr` commands run the corresponding search
//! immediately (the oracle only lists them in `settings`).

use std::io::{BufRead, Write};

use rf_core::{Arch, Image};
use rf_scan::Gadget;

use crate::search;
use crate::{
    load_target, parse_hex, prepare_view, print_human, request_options, Cli, RawSpec, ScanRequest,
    ScanResult, Target,
};

/// Console session state: the mutable search-engine options (core.py's
/// `self.__options`), plus the loaded binary and gadget list.
pub struct Console {
    depth: usize,
    rop: bool,
    jop: bool,
    sys: bool,
    multibr: bool,
    only: Option<String>,
    filter: Option<String>,
    range: Option<String>,
    badbytes: Option<String>,
    offset: Option<String>,
    thumb: bool,
    all: bool,
    re: Option<String>,
    call_preceded: bool,
    dump: bool,
    noinstr: bool,
    silent: bool,
    // settings-display only (no console setters in the oracle either).
    string_s: Option<String>,
    opcode_s: Option<String>,
    memstr_s: Option<String>,
    mipsrop_s: Option<String>,
    ropchain: bool,
    raw_arch: Option<String>,
    raw_mode: Option<String>,
    raw_endian: Option<String>,
    // Session state.
    raw: Option<RawSpec>,
    binary_path: Option<String>,
    /// do_load tests `self.__binary is None` — a FAILED binary command
    /// still creates the oracle's Binary wrapper, so load "works" (and
    /// finds nothing) afterwards. This flag reproduces that.
    binary_attempted: bool,
    target: Option<Target>,
    gadgets: Vec<Gadget>,
    addr_size: usize,
    universal_arch: Option<Arch>,
    /// ROB-06 input cap, inherited from `--max-file-size`.
    max_file_size: u64,
    /// CORE-03 `--arch` fat-Mach-O slice, inherited from the command line.
    arch: Option<String>,
    /// `--compat`: ROPgadget bug-for-bug fat-Mach-O handling.
    compat: bool,
}

impl Console {
    /// Build the session from the CLI. With --binary the binary is
    /// preloaded (core.py:232-236); a preload failure aborts before the
    /// REPL starts, like the oracle's analyze() returning False.
    pub fn from_cli(cli: &Cli) -> Result<Console, String> {
        let raw = crate::parse_raw_spec(cli)?;
        let mut c = Console {
            depth: cli.depth,
            rop: !cli.norop,
            jop: !cli.nojop,
            sys: !cli.nosys,
            multibr: cli.multibr,
            only: cli.only.clone(),
            filter: cli.filter.clone(),
            range: cli.range.clone(),
            badbytes: cli.badbytes.clone(),
            offset: cli.offset.clone(),
            thumb: cli.thumb,
            all: cli.all,
            re: cli.re.clone(),
            call_preceded: cli.call_preceded,
            dump: cli.dump,
            noinstr: cli.noinstr,
            silent: cli.silent,
            string_s: cli.string.clone(),
            opcode_s: cli.opcode.clone(),
            memstr_s: cli.memstr.clone(),
            mipsrop_s: cli.mipsrop.clone(),
            ropchain: cli.ropchain,
            raw_arch: cli.raw_arch.clone(),
            raw_mode: cli.raw_mode.clone(),
            raw_endian: cli.raw_endian.clone(),
            raw,
            binary_path: cli.binary.clone(),
            binary_attempted: cli.binary.is_some(),
            target: None,
            gadgets: Vec::new(),
            addr_size: 8,
            universal_arch: None,
            max_file_size: crate::parse_size(&cli.max_file_size, "--max-file-size")?,
            arch: cli.arch.clone(),
            compat: cli.compat,
        };
        if let Some(path) = &cli.binary {
            // ROB-06: the console reads whatever path the user types, so it
            // needs the same stat-first bound as the one-shot CLI.
            let bytes = crate::read_input_file(path, c.max_file_size)
                .map_err(|_| LOAD_FAIL_MSG.to_string())?;
            let target = load_target(&bytes, raw).map_err(|e| format!("{LOAD_FAIL_MSG} ({e})"))?;
            c.set_target(target);
        }
        Ok(c)
    }

    fn set_target(&mut self, target: Target) {
        let view = crate::build_view(&target);
        self.addr_size = view.addr_size();
        self.universal_arch = view.universal.then_some(view.arch());
        self.target = Some(target);
    }

    fn scan_request(&self) -> ScanRequest {
        ScanRequest {
            depth: self.depth,
            rop: self.rop,
            jop: self.jop,
            sys: self.sys,
            multibr: self.multibr,
            only: self.only.clone(),
            filter: self.filter.clone(),
            range: self.range.clone(),
            badbytes: self.badbytes.clone(),
            offset: self.offset.clone(),
            base: None,
            section: Vec::new(),
            thumb: self.thumb,
            cfg_aware: false,
            align: None,
            call_preceded: self.call_preceded,
            all: self.all,
            noinstr: self.noinstr,
            arch: self.arch.clone(),
            max_gadgets: None,
            max_memory: None,
            compat: self.compat,
        }
    }

    /// `load` — full gadget scan with the current options, then the
    /// --re / --callPreceded post-filters (options.py runs inside
    /// __getGadgets, so the "Filtered out" line prints here).
    fn do_load(&mut self, out: &mut dyn Write) {
        if !self.binary_attempted {
            let _ = writeln!(out, "[-] No binary loaded.");
            return;
        }
        let _ = writeln!(out, "[+] Loading gadgets, please wait...");
        if let Some(target) = &self.target {
            let req = self.scan_request();
            let loaded = (|| -> Result<Vec<Gadget>, String> {
                let opts = request_options(&req, self.raw).map_err(|e| e.to_string())?;
                let prepared = prepare_view(target, None, &[], self.arch.as_deref(), self.compat)
                    .map_err(|e| e.to_string())?;
                let view = prepared.view;
                self.addr_size = view.addr_size();
                self.universal_arch = view.universal.then_some(view.arch());
                let mut gadgets = rf_scan::scan_binary(&view, &opts).map_err(|e| e.to_string())?;
                crate::apply_post_filters(
                    &mut gadgets,
                    &self.re,
                    self.call_preceded,
                    view.arch(),
                    // The console is a human REPL with no --json mode, so the
                    // oracle's "Filtered out" line belongs on stdout with the
                    // rest of the session transcript.
                    false,
                    out,
                )?;
                Ok(gadgets)
            })();
            match loaded {
                Ok(g) => self.gadgets = g,
                Err(e) => {
                    let _ = writeln!(out, "[Error] {e}");
                    self.gadgets = Vec::new();
                }
            }
        }
        let _ = writeln!(out, "[+] Gadgets loaded !");
    }

    fn arch_width8(&self) -> bool {
        match &self.target {
            Some(t) => search::search_width8(t, self.target_arch()),
            None => self.addr_size == 4,
        }
    }

    fn target_arch(&self) -> Arch {
        self.universal_arch.unwrap_or(match &self.target {
            Some(Target::Elf(b)) => Image::arch(b),
            Some(Target::Pe(b)) => Image::arch(b),
            Some(Target::MachO(b)) => Image::arch(b),
            Some(Target::Raw(b)) => Image::arch(b),
            Some(Target::Universal(u)) => u.slices()[0].arch(),
            None => Arch::X64,
        })
    }

    /// Console-extension search commands: run the search immediately
    /// against the loaded binary (range/offset honoured).
    fn do_search_mode(&mut self, which: &str, arg: &str, out: &mut dyn Write) {
        if arg.is_empty() {
            let _ = writeln!(out, "Syntax: {which} <value>");
            return;
        }
        match which {
            "string" => self.string_s = Some(arg.to_string()),
            "opcode" => self.opcode_s = Some(arg.to_string()),
            "memstr" => self.memstr_s = Some(arg.to_string()),
            _ => unreachable!(),
        }
        let Some(target) = &self.target else {
            let _ = writeln!(out, "[-] You have to load a binary");
            return;
        };
        let range = self
            .range
            .as_deref()
            .map(crate::parse_range)
            .transpose()
            .ok()
            .flatten()
            .flatten();
        let offset = self
            .offset
            .as_deref()
            .map(|o| parse_hex(o, "--offset"))
            .transpose()
            .ok()
            .flatten()
            .unwrap_or(0);
        let width8 = self.arch_width8();
        match which {
            "string" => match search::find_string(target, 0, offset, range, arg, None) {
                Ok(hits) => search::print_string_hits(&hits, width8, out),
                Err(e) => {
                    let _ = writeln!(out, "[Error] {e}");
                }
            },
            "opcode" => match search::find_opcode(target, 0, offset, range, arg) {
                Ok(hits) => search::print_opcode_hits(&hits, arg, width8, out),
                Err(e) => {
                    let _ = writeln!(out, "[Error] {e}");
                }
            },
            "memstr" => {
                let hits = search::find_memstr(target, 0, offset, range, arg, None);
                search::print_memstr_hits(&hits, width8, out);
            }
            _ => unreachable!(),
        }
    }

    fn do_settings(&self, out: &mut dyn Write) {
        let py = |o: &Option<String>| o.clone().unwrap_or_else(|| "None".to_string());
        let pyb = |b: bool| if b { "True" } else { "False" };
        let range = self.range.clone().unwrap_or_else(|| "0x0-0x0".to_string());
        let _ = writeln!(out, "All:         {}", pyb(self.all));
        let _ = writeln!(out, "Badbytes:    {}", py(&self.badbytes));
        let _ = writeln!(out, "Binary:      {}", py(&self.binary_path));
        let _ = writeln!(out, "Depth:       {}", self.depth);
        let _ = writeln!(out, "Filter:      {}", py(&self.filter));
        let _ = writeln!(out, "Memstr:      {}", py(&self.memstr_s));
        let _ = writeln!(out, "MultiBr:     {}", pyb(self.multibr));
        let _ = writeln!(out, "NoJOP:       {}", pyb(!self.jop));
        let _ = writeln!(out, "NoROP:       {}", pyb(!self.rop));
        let _ = writeln!(out, "NoSYS:       {}", pyb(!self.sys));
        let _ = writeln!(out, "Offset:      {}", py(&self.offset));
        let _ = writeln!(out, "Only:        {}", py(&self.only));
        let _ = writeln!(out, "Opcode:      {}", py(&self.opcode_s));
        let _ = writeln!(out, "ROPchain:    {}", pyb(self.ropchain));
        let _ = writeln!(out, "Range:       {range}");
        let _ = writeln!(out, "RawArch:     {}", py(&self.raw_arch));
        let _ = writeln!(out, "RawMode:     {}", py(&self.raw_mode));
        let _ = writeln!(out, "RawEndian:   {}", py(&self.raw_endian));
        let _ = writeln!(out, "Re:          {}", py(&self.re));
        let _ = writeln!(out, "String:      {}", py(&self.string_s));
        let _ = writeln!(out, "Thumb:       {}", pyb(self.thumb));
        let _ = writeln!(out, "Mipsrop:     {}", py(&self.mipsrop_s));
    }
}

const LOAD_FAIL_MSG: &str = "Can't open the binary or binary not found";

/// Entry point for `--console` (cli.binary optional). `out` is the
/// process-wide buffered stdout; `run_repl` flushes it before every read,
/// so the prompt still appears before the user types (PERF-07).
pub fn run_console(cli: &Cli, out: &mut dyn Write) -> Result<i32, String> {
    let mut console = Console::from_cli(cli)?;
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    Ok(run_repl(&mut console, &mut input, out))
}

/// The REPL, factored for tests: prompt → read → dispatch; EOF or
/// `quit` exits; an empty line repeats the last non-empty command
/// (cmd.Cmd.emptyline, verified empirically).
pub fn run_repl(console: &mut Console, input: &mut dyn BufRead, out: &mut dyn Write) -> i32 {
    let mut lastcmd = String::new();
    loop {
        let _ = write!(out, "(ROPgadget)> ");
        let _ = out.flush();
        let mut line = String::new();
        match input.read_line(&mut line) {
            Ok(0) | Err(_) => return 0, // EOF = quit
            Ok(_) => {}
        }
        let line = line.trim_end_matches(['\n', '\r']);
        let line = if line.trim().is_empty() {
            if lastcmd.is_empty() {
                continue;
            }
            lastcmd.clone()
        } else {
            line.to_string()
        };
        if dispatch(console, &line, out) {
            return 0;
        }
        lastcmd = line;
    }
}

/// Execute one command line; returns true to quit.
fn dispatch(c: &mut Console, line: &str, out: &mut dyn Write) -> bool {
    let mut parts = line.splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("");
    let arg = parts.next().unwrap_or("").trim();
    match cmd {
        "quit" | "EOF" => return true,
        "binary" => {
            if arg.is_empty() {
                let _ = writeln!(out, "Syntax: binary <file> -- Load a binary");
            } else {
                // do not split the filename: it might contain whitespaces.
                c.binary_path = Some(arg.to_string());
                c.binary_attempted = true;
                match crate::read_input_file(arg, c.max_file_size)
                    .and_then(|b| load_target(&b, c.raw).map_err(|e| e.to_string()))
                {
                    Ok(t) => {
                        c.set_target(t);
                        let _ = writeln!(out, "[+] Binary loaded");
                    }
                    Err(_) => {
                        c.target = None;
                        let _ = writeln!(out, "[Error] {LOAD_FAIL_MSG}");
                    }
                }
            }
        }
        "load" => c.do_load(out),
        "display" => {
            if c.target.is_some() && !c.silent {
                let res = ScanResult {
                    gadgets: std::mem::take(&mut c.gadgets),
                    addr_size: c.addr_size,
                    universal_arch: c.universal_arch,
                    selected_sections: None,
                };
                print_human(&res, c.noinstr, c.dump, out);
                c.gadgets = res.gadgets;
            }
        }
        "depth" => match arg.parse::<i64>() {
            Ok(d) if d > 0 => {
                c.depth = d as usize;
                let _ = writeln!(out, "[+] Depth updated. You have to reload gadgets");
            }
            Ok(_) => {
                let _ = writeln!(out, "[-] The depth value must be > 0");
            }
            Err(_) => {
                let _ = writeln!(out, "Syntax: depth <value> -- Set the depth search engine");
            }
        },
        "badbytes" => {
            if arg.is_empty() {
                let _ = writeln!(out, "Syntax: badbytes <badbyte1|badbyte2...> -- ");
            } else {
                c.badbytes = Some(arg.to_string());
                let _ = writeln!(out, "[+] Bad bytes updated. You have to reload gadgets");
            }
        }
        "search" => {
            if arg.is_empty() {
                let _ = writeln!(
                    out,
                    "Syntax: search <keyword1 keyword2 keyword3...> -- Filter with or without keywords"
                );
                let _ = writeln!(out, "keyword  = with");
                let _ = writeln!(out, "!keyword = without");
            } else if c.target.is_none() {
                let _ = writeln!(out, "[-] You have to load a binary");
            } else {
                let mut with_k = Vec::new();
                let mut without_k = Vec::new();
                for a in arg.split_whitespace() {
                    if let Some(rest) = a.strip_prefix('!') {
                        without_k.push(rest.to_string());
                    } else {
                        with_k.push(a.to_string());
                    }
                }
                for g in &c.gadgets {
                    let text = g.text();
                    if with_k.iter().all(|k| text.contains(k))
                        && !without_k.iter().any(|k| text.contains(k))
                    {
                        let _ =
                            writeln!(out, "{} : {}", crate::fmt_addr(g.vaddr, c.addr_size), text);
                    }
                }
            }
        }
        "count" => {
            let _ = writeln!(out, "[+] {} loaded gadgets.", c.gadgets.len());
        }
        "filter" => {
            if arg.is_empty() {
                let _ = writeln!(
                    out,
                    "Syntax: filter <filter1|filter2|...> - Suppress specific mnemonics"
                );
            } else {
                c.filter = Some(arg.to_string());
                let _ = writeln!(out, "[+] Filter setted. You have to reload gadgets");
            }
        }
        "only" => {
            if arg.is_empty() {
                let _ = writeln!(
                    out,
                    "Syntax: only <only1|only2|...> - Only show specific instructions"
                );
            } else {
                c.only = if arg.eq_ignore_ascii_case("none") {
                    None
                } else {
                    Some(arg.to_string())
                };
                let _ = writeln!(out, "[+] Only setted. You have to reload gadgets");
            }
        }
        "range" => {
            let parsed = arg
                .split_once('-')
                .and_then(|(a, b)| parse_hex(a, "").ok().zip(parse_hex(b, "").ok()));
            match parsed {
                None => {
                    let _ = writeln!(
                        out,
                        "Syntax: range <start-and> - Search between two addresses (0x...-0x...)"
                    );
                }
                Some((s, e)) if s > e => {
                    let _ = writeln!(
                        out,
                        "[-] The start value must be greater than the end value"
                    );
                }
                Some(_) => {
                    c.range = Some(arg.to_string());
                    let _ = writeln!(out, "[+] Range setted. You have to reload gadgets");
                }
            }
        }
        "re" => {
            if arg.is_empty() {
                let _ = writeln!(
                    out,
                    "Syntax: re <pattern1 | pattern2 |...> - Regular expression"
                );
            } else {
                c.re = if arg.eq_ignore_ascii_case("none") {
                    None
                } else {
                    Some(arg.to_string())
                };
                let _ = writeln!(out, "[+] Re setted. You have to reload gadgets");
            }
        }
        "settings" => c.do_settings(out),
        "nojop" | "norop" | "nosys" | "thumb" => {
            let name = match cmd {
                "nojop" => "NoJOP",
                "norop" => "NoROP",
                "nosys" => "NoSYS",
                _ => "Thumb",
            };
            match arg {
                "enable" | "disable" => {
                    let on = arg == "enable";
                    match cmd {
                        "nojop" => c.jop = !on,
                        "norop" => c.rop = !on,
                        "nosys" => c.sys = !on,
                        _ => c.thumb = on,
                    }
                    let _ = writeln!(out, "[+] {name} {arg}. You have to reload gadgets");
                }
                _ => {
                    let _ = writeln!(
                        out,
                        "Syntax: {cmd} <enable|disable> - {}",
                        match cmd {
                            "thumb" => "Use the thumb mode for the search engine (ARM only)",
                            _ => "Disable the search engine",
                        }
                    );
                }
            }
        }
        "all" => match arg {
            "enable" | "disable" => {
                c.all = arg == "enable";
                let word = if c.all { "enabled" } else { "disabled" };
                let _ = writeln!(
                    out,
                    "[+] Showing all gadgets {word}. You have to reload gadgets"
                );
            }
            _ => {
                let _ = writeln!(
                    out,
                    "Syntax: all <enable|disable - Show all gadgets (disable removing duplicate gadgets)"
                );
            }
        },
        "multibr" => match arg {
            "enable" | "disable" => {
                c.multibr = arg == "enable";
                let word = if c.multibr { "enabled" } else { "disabled" };
                let _ = writeln!(
                    out,
                    "[+] Multiple branch gadgets {word}. You have to reload gadgets"
                );
            }
            _ => {
                let _ = writeln!(
                    out,
                    "Syntax: multibr <enable|disable> - Enable/Disable multiple branch gadgets"
                );
            }
        },
        // Console EXTENSION (the oracle has no do_string/do_opcode/
        // do_memstr): run the search immediately.
        "string" | "opcode" | "memstr" => c.do_search_mode(cmd, arg, out),
        "help" => {
            let _ = writeln!(
                out,
                "Commands: binary load display depth badbytes search count filter only range re \
                 settings nojop norop nosys thumb all multibr string opcode memstr quit"
            );
        }
        _ => {
            let _ = writeln!(out, "*** Unknown syntax: {line}");
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(name: &str) -> String {
        format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    fn cli_for(binary: Option<String>) -> Cli {
        Cli {
            binary,
            depth: 10,
            norop: false,
            nojop: false,
            nosys: false,
            multibr: false,
            only: None,
            filter: None,
            range: None,
            badbytes: None,
            offset: None,
            base: None,
            info: false,
            ropchain: false,
            chain: "linux-execve".into(),
            api_addr: None,
            shellcode_addr: None,
            shellcode_size: None,
            cfg_aware: false,
            section: Vec::new(),
            thumb: false,
            raw_arch: None,
            raw_mode: None,
            raw_endian: None,
            json: false,
            classify: false,
            rank: false,
            cache: false,
            cache_purge: false,
            string: None,
            opcode: None,
            memstr: None,
            re: None,
            call_preceded: false,
            noinstr: false,
            dump: false,
            silent: false,
            align: None,
            mipsrop: None,
            all: false,
            console: true,
            arch: None,
            max_file_size: "512M".to_string(),
            max_gadgets: None,
            max_memory: None,
            compat: false,
        }
    }

    fn run_script(console: &mut Console, script: &str) -> String {
        let mut input = script.as_bytes();
        let mut out: Vec<u8> = Vec::new();
        let code = run_repl(console, &mut input, &mut out);
        assert_eq!(code, 0);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn repl_core_flow() {
        let mut c = Console::from_cli(&cli_for(None)).unwrap();
        let out = run_script(
            &mut c,
            &format!(
                "settings\nbinary {}\nload\ncount\nsearch pop !call\ndepth 5\nrange 0x2000-0x1000\nquit\n",
                fixture_path("elf-Linux-x86")
            ),
        );
        assert!(
            out.starts_with("(ROPgadget)> All:         False\n"),
            "{out}"
        );
        assert!(out.contains("Range:       0x0-0x0\n"), "{out}");
        assert!(out.contains("Mipsrop:     None\n"), "{out}");
        assert!(out.contains("(ROPgadget)> [+] Binary loaded\n"), "{out}");
        assert!(
            out.contains("[+] Loading gadgets, please wait...\n[+] Gadgets loaded !\n"),
            "{out}"
        );
        assert!(out.contains(" loaded gadgets.\n"), "{out}");
        // search prints "0x........ : text" lines containing pop, no count
        assert!(out.contains(" : pop"), "{out}");
        assert!(
            out.contains("[+] Depth updated. You have to reload gadgets\n"),
            "{out}"
        );
        assert!(
            out.contains("[-] The start value must be greater than the end value\n"),
            "{out}"
        );
    }

    #[test]
    fn repl_empty_line_repeats_and_unknown_syntax() {
        let mut c = Console::from_cli(&cli_for(None)).unwrap();
        let out = run_script(&mut c, "count\n\nboguscmd\n\nquit\n");
        assert!(
            out.contains("[+] 0 loaded gadgets.\n(ROPgadget)> [+] 0 loaded gadgets.\n"),
            "{out}"
        );
        assert!(
            out.matches("*** Unknown syntax: boguscmd").count() == 2,
            "{out}"
        );
    }

    #[test]
    fn repl_load_without_binary_and_eof() {
        let mut c = Console::from_cli(&cli_for(None)).unwrap();
        let out = run_script(&mut c, "load\n");
        assert!(out.contains("[-] No binary loaded.\n"), "{out}");
        // EOF right after the prompt quits silently.
        assert!(out.ends_with("(ROPgadget)> "), "{out}");
    }

    #[test]
    fn repl_preload_and_search_extension() {
        let mut c = Console::from_cli(&cli_for(Some(fixture_path("elf-Linux-x86")))).unwrap();
        let out = run_script(
            &mut c,
            "load\nstring main\nopcode c3\nmemstr /bin\nsettings\nquit\n",
        );
        assert!(out.contains("Strings information\n"), "{out}");
        assert!(out.contains("Opcodes information\n"), "{out}");
        assert!(out.contains("Memory bytes information\n"), "{out}");
        assert!(out.contains("String:      main\n"), "{out}");
        assert!(out.contains("Opcode:      c3\n"), "{out}");
        assert!(out.contains("Memstr:      /bin\n"), "{out}");
    }
}
