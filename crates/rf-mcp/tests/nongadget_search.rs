//! CLI-05 / ECO-02 on the real server — `find_string` and `find_bytes`,
//! and the property that makes them safe to expose: the search reads only
//! bytes inside MAPPED sections.
//!
//! The v0.2 allowlist refuses `--string` and `--memstr` as a file-read
//! leak. The reasoning did not survive contact with `find_gadgets`, which
//! already hands the agent every executable byte of the confined file. What
//! actually holds the line is the SCOPE of the search, and these tests are
//! where that scope stops being a claim in a doc comment: a byte that is in
//! the file but in no mapped section must not be findable, and the response
//! must name exactly which sections were read.

mod support;

use serde_json::{json, Value};

use support::{fixtures_dir, structured, McpChild};

fn hits(body: &Value) -> &Vec<Value> {
    body["hits"].as_array().expect("hits")
}

/// The question the finding is named for — "where does this string live?"
/// — checked against the ORACLE's own answer.
///
/// ROPgadget's `--string GLIBC` reports exactly one address on each of
/// these two fixtures, measured with the vendored oracle:
///   elf-Linux-x86 -> 0x080e32ef, elf-Linux-x64 -> 0x00000000004acbc3.
/// (No fixture in this repository contains "/bin/sh"; the oracle finds
/// none either, which is why the test is written against a string that is
/// really there.)
#[tokio::test]
async fn find_string_agrees_with_the_oracle() {
    let mut mcp = McpChild::spawn().await;
    for (id, fixture, want_addr, want_hex) in [
        (1u64, "elf-Linux-x86", 0x080e_32efu64, "0x080e32ef"),
        (2, "elf-Linux-x64", 0x004a_cbc3, "0x00000000004acbc3"),
    ] {
        let r = mcp
            .call_tool(
                id,
                "find_string",
                json!({"binary_path": fixtures_dir().join(fixture), "string": "GLIBC"}),
            )
            .await;
        assert_eq!(r["result"]["isError"], false, "{fixture}: {r}");
        let body = structured(&r);
        println!(
            "find_string GLIBC on {fixture}: {} hits (oracle: 1 at {want_hex})",
            body["total_count"]
        );
        for h in hits(body) {
            println!(
                "  {} {:<10} len {} w={} x={} {:?}",
                h["vaddr"].as_str().unwrap(),
                h["section"].as_str().unwrap_or("(unnamed)"),
                h["length"],
                h["writable"],
                h["executable"],
                h["preview"].as_str().unwrap()
            );
        }
        assert_eq!(body["total_count"], 1, "{body}");
        let h = &hits(body)[0];
        assert_eq!(h["vaddr_u64"], want_addr, "{h}");
        // The address column matches the oracle's width rule too: 8 hex
        // digits on a 32-bit target, 16 on a 64-bit one.
        assert_eq!(h["vaddr"], want_hex, "{h}");
        assert_eq!(h["preview"], "GLIBC", "{h}");
        assert_eq!(h["length"], 5, "{h}");
        assert_eq!(h["bytes"], "474c494243", "{h}");
        // `--string` reads DATA sections, so nothing here is executable.
        assert_eq!(h["executable"], false, "{h}");
        assert!(h["matched_char"].is_null(), "{h}");
        assert_eq!(body["mode"], "string");
        assert_eq!(body["query"], "GLIBC");
    }
}

/// The oracle's `--string` reports `len(pattern)` bytes from the match
/// start, not the match's own length, so a regex is a real regex and the
/// preview is a fixed-width window.
#[tokio::test]
async fn a_regex_pattern_reports_a_pattern_width_window() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x86");
    let r = mcp
        .call_tool(
            1,
            "find_string",
            json!({"binary_path": elf, "string": "GL.BC"}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    println!("find_string 'GL.BC': {} hits", body["total_count"]);
    assert!(body["total_count"].as_u64().unwrap() >= 1, "{body}");
    for h in hits(body) {
        assert_eq!(h["length"], 5, "the window is the PATTERN's length: {h}");
    }
}

/// The confinement property, made observable: every hit lies inside a
/// section the response NAMES, and that section is one the loader maps.
#[tokio::test]
async fn every_hit_is_inside_a_section_the_response_names() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");

    // The mapped section table, from the tool that publishes it.
    let info = mcp
        .call_tool(1, "get_binary_info", json!({"binary_path": elf}))
        .await;
    let sections: Vec<(String, u64, u64)> = structured(&info)["sections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["name"].as_str().unwrap().to_string(),
                u64::from_str_radix(s["vaddr"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap(),
                s["size"].as_u64().unwrap(),
            )
        })
        .collect();

    let mut checked = 0;
    for (id, tool, args) in [
        (
            2u64,
            "find_string",
            json!({"binary_path": elf, "string": "lib", "max_results": 200}),
        ),
        (
            3,
            "find_bytes",
            json!({"binary_path": elf, "opcode": "c3", "max_results": 200}),
        ),
    ] {
        let r = mcp.call_tool(id, tool, args).await;
        assert_eq!(r["result"]["isError"], false, "{tool}: {r}");
        let body = structured(&r);
        let named: Vec<&str> = body["sections_searched"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(!named.is_empty(), "{tool} named no sections: {body}");
        for h in hits(body) {
            let at = h["vaddr_u64"].as_u64().unwrap();
            let sec = h["section"].as_str();
            // The hit's own section is one the response said it searched.
            if let Some(name) = sec {
                assert!(
                    named.contains(&name),
                    "{tool}: hit in {name}, which sections_searched does not list: {named:?}"
                );
            }
            // ...and the address really is inside SOME mapped section.
            assert!(
                sections
                    .iter()
                    .any(|(_, v, size)| at >= *v && at < v.saturating_add(*size)),
                "{tool}: hit at 0x{at:x} is outside every mapped section"
            );
            checked += 1;
        }
    }
    println!("every_hit_is_inside_a_section_the_response_names: {checked} hits checked");
    assert!(checked > 20, "only {checked} hits examined");
}

/// The negative half of the scope claim: a byte that is in the FILE but in
/// no mapped section is not findable. The ELF magic at file offset 0 is the
/// cleanest example — it is the header, which no section covers.
#[tokio::test]
async fn bytes_outside_every_mapped_section_are_unreachable() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");

    // `\x7fELF` is at file offset 0 of every ELF here. On a statically
    // linked ELF the first PT_LOAD starts at the header, so the magic can
    // legitimately be mapped; assert instead on the two things that are
    // unconditionally true — no hit may be at an address outside every
    // section, and the section list is the only input.
    let r = mcp
        .call_tool(
            1,
            "find_string",
            json!({"binary_path": elf, "string": "\\x7fELF", "max_results": 100}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    let searched: Vec<&str> = body["sections_searched"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    println!(
        "find_string \\x7fELF: {} hits; windows read: {searched:?}",
        body["total_count"]
    );
    // `--string` reads DATA sections only, so a header hit is impossible
    // by construction: an executable or header region is not in this set.
    for h in hits(body) {
        assert_eq!(h["executable"], false, "{h}");
        assert!(
            h["section"].as_str().is_some_and(|s| searched.contains(&s)),
            "{h}"
        );
    }

    // And there is no way to ASK for a file offset: no search tool declares
    // any parameter that names one. (rmcp ignores an undeclared argument
    // rather than rejecting it, so the claim has to be made against the
    // declared inputSchema, which is the contract an agent reads.)
    let list = mcp.rpc(2, "tools/list", json!({})).await;
    for t in list["result"]["tools"].as_array().unwrap() {
        let name = t["name"].as_str().unwrap();
        if !matches!(name, "find_string" | "find_bytes") {
            continue;
        }
        let props: Vec<&str> = t["inputSchema"]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        println!("{name} parameters: {props:?}");
        for banned in [
            "file_offset",
            "offset_in_file",
            "raw",
            "whole_file",
            "compat",
        ] {
            assert!(
                !props.contains(&banned),
                "{name} declares {banned}, which would widen the confinement boundary"
            );
        }
    }
}

/// `find_bytes` searches the EXECUTABLE regions, and its `??` wildcard
/// covers a whole byte.
#[tokio::test]
async fn find_bytes_matches_opcodes_with_wildcards() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");

    let exact = mcp
        .call_tool(
            1,
            "find_bytes",
            json!({"binary_path": elf, "opcode": "c9c3", "max_results": 20}),
        )
        .await;
    assert_eq!(exact["result"]["isError"], false, "{exact}");
    let body = structured(&exact);
    let n_exact = body["total_count"].as_u64().unwrap();
    println!("find_bytes c9c3 (leave ; ret): {n_exact} hits (oracle: 29)");
    // Oracle parity, measured with the vendored ROPgadget:
    //   ROPgadget.py --binary tests/fixtures/elf-Linux-x64 --opcode c9c3  -> 29
    assert_eq!(n_exact, 29, "{body}");
    for h in hits(body) {
        assert_eq!(h["bytes"], "c9c3", "{h}");
        assert_eq!(h["length"], 2, "{h}");
        assert_eq!(h["executable"], true, "{h}");
        assert_eq!(h["preview"], "\\xc9\\xc3", "{h}");
    }

    // `ff??e0` is `jmp rax` .. `jmp r15`; the wildcard must widen the set.
    let wild = mcp
        .call_tool(
            2,
            "find_bytes",
            json!({"binary_path": elf, "opcode": "c9??", "max_results": 20}),
        )
        .await;
    let n_wild = structured(&wild)["total_count"].as_u64().unwrap();
    println!("find_bytes c9??: {n_wild} hits");
    assert!(
        n_wild >= n_exact,
        "the wildcard narrowed the set: {n_wild} < {n_exact}"
    );

    // A nibble wildcard is refused rather than silently widened.
    let bad = mcp
        .call_tool(3, "find_bytes", json!({"binary_path": elf, "opcode": "c?"}))
        .await;
    assert_eq!(bad["result"]["isError"], true, "{bad}");
    let e = &structured(&bad)["error"];
    assert_eq!(e["code"], "usage_error", "{e}");
    assert!(e["message"].as_str().unwrap().contains("whole byte"), "{e}");
}

/// `memstr`: each character located once, first hit wins, exec before data.
#[tokio::test]
async fn memstr_locates_each_character_once() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x86");
    let r = mcp
        .call_tool(
            1,
            "find_string",
            json!({"binary_path": elf, "string": "/bin/sh", "memstr": true}),
        )
        .await;
    // `/bin/sh` is NOT present contiguously in this fixture — the oracle
    // finds nothing for `--string /bin/sh` either — which is exactly the
    // situation `--memstr` exists for: locate the characters one at a time
    // and assemble the string yourself.
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    assert_eq!(body["mode"], "memstr", "{body}");
    println!(
        "memstr /bin/sh on elf-Linux-x86: {} hits (the contiguous string is absent)",
        body["total_count"]
    );
    for h in hits(body) {
        println!(
            "  {:?} at {} in {}",
            h["matched_char"].as_str().unwrap(),
            h["vaddr"].as_str().unwrap(),
            h["section"].as_str().unwrap_or("(unnamed)")
        );
        assert!(h["matched_char"].is_string(), "{h}");
        assert_eq!(h["length"], 1, "{h}");
    }
    // Oracle parity, character for character and address for address:
    //   ROPgadget.py --binary tests/fixtures/elf-Linux-x86 --memstr "/bin/sh"
    // (run with MSYS_NO_PATHCONV=1 so the shell does not rewrite the
    // argument into a Windows path).
    let got: Vec<(String, u64)> = hits(body)
        .iter()
        .map(|h| {
            (
                h["matched_char"].as_str().unwrap().to_string(),
                h["vaddr_u64"].as_u64().unwrap(),
            )
        })
        .collect();
    let want: Vec<(String, u64)> = [
        ("/", 0x0804_87eau64),
        ("b", 0x0804_8b59),
        ("i", 0x0804_94d3),
        ("n", 0x0804_8b2e),
        ("/", 0x0804_87ea),
        ("s", 0x0804_85c6),
        ("h", 0x0804_81e6),
    ]
    .iter()
    .map(|(c, a)| ((*c).to_string(), *a))
    .collect();
    assert_eq!(got, want, "memstr diverged from the oracle");
}

/// ECO-09: a large search pages with a cursor and names a streamable NDJSON
/// resource holding the whole match set, rather than returning a monolith.
#[tokio::test]
async fn a_large_search_pages_and_names_an_ndjson_resource() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-x64-bash-v4.1.5.1");
    let q = json!({"binary_path": elf, "opcode": "c3", "max_results": 10});

    let first = mcp.call_tool(1, "find_bytes", q.clone()).await;
    assert_eq!(first["result"]["isError"], false, "{first}");
    let body = structured(&first);
    let total = body["total_count"].as_u64().unwrap();
    println!("find_bytes c3 on elf-x64-bash: {total} hits, page of 10 (oracle: 3690)");
    // Oracle parity: --binary tests/fixtures/elf-x64-bash-v4.1.5.1 --opcode c3 -> 3690
    assert_eq!(total, 3690, "the paged search must find the oracle's set");
    assert_eq!(body["returned"], 10, "{body}");
    assert_eq!(body["truncated"], true, "{body}");
    let uri = body["resource_uri"]
        .as_str()
        .unwrap_or_else(|| panic!("no resource_uri: {body}"))
        .to_string();
    assert!(uri.starts_with("ropfinder://search/"), "{uri}");
    let cursor = body["next_cursor"].as_str().expect("cursor").to_string();

    // Page two continues, and does not repeat page one.
    let mut second = q.clone();
    second["cursor"] = json!(cursor.clone());
    let r = mcp.call_tool(2, "find_bytes", second).await;
    let body2 = structured(&r);
    assert_eq!(body2["offset"], 10, "{body2}");
    let a: Vec<u64> = hits(body)
        .iter()
        .map(|h| h["vaddr_u64"].as_u64().unwrap())
        .collect();
    let b: Vec<u64> = hits(body2)
        .iter()
        .map(|h| h["vaddr_u64"].as_u64().unwrap())
        .collect();
    assert!(
        a.iter().all(|v| !b.contains(v)),
        "pages overlap: {a:?} {b:?}"
    );

    // The resource holds the WHOLE set, one JSON object per line.
    let res = mcp.rpc(3, "resources/read", json!({"uri": uri})).await;
    let text = res["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no resource body: {res}"));
    let lines: Vec<&str> = text.lines().collect();
    println!("resource {uri}: {} lines for {total} hits", lines.len());
    assert_eq!(
        lines.len() as u64,
        total,
        "the resource is not the whole set"
    );
    let first_line: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first_line["vaddr_u64"], json!(a[0]), "{first_line}");
    assert_eq!(
        res["result"]["contents"][0]["mimeType"],
        "application/x-ndjson"
    );

    // A cursor from a DIFFERENT query is refused rather than spliced in.
    let mut wrong = q;
    wrong["opcode"] = json!("c9c3");
    wrong["cursor"] = json!(cursor);
    let r = mcp.call_tool(4, "find_bytes", wrong).await;
    assert_eq!(r["result"]["isError"], true, "{r}");
    assert_eq!(structured(&r)["error"]["code"], "cursor_expired");
}

/// A search obeys the same confinement, caps and error taxonomy as every
/// other tool: a path outside the allowlist is one `path_denied`.
#[tokio::test]
async fn a_search_outside_the_allowlist_is_path_denied() {
    let mut mcp = McpChild::spawn().await;
    let outside = mcp.cwd.path().join("probe.bin");
    for (id, tool, args) in [
        (
            1u64,
            "find_string",
            json!({"binary_path": outside, "string": "x"}),
        ),
        (
            2,
            "find_bytes",
            json!({"binary_path": outside, "opcode": "c3"}),
        ),
        (3, "get_mitigations", json!({"binary_path": outside})),
    ] {
        let r = mcp.call_tool(id, tool, args).await;
        assert_eq!(r["result"]["isError"], true, "{tool}: {r}");
        assert_eq!(
            structured(&r)["error"]["code"],
            "path_denied",
            "{tool}: {r}"
        );
    }
}

/// `range` narrows a search and cannot widen it.
#[tokio::test]
async fn range_only_narrows() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let all = mcp
        .call_tool(
            1,
            "find_bytes",
            json!({"binary_path": elf, "opcode": "c3", "max_results": 1}),
        )
        .await;
    let total = structured(&all)["total_count"].as_u64().unwrap();
    // Oracle parity, measured with the vendored ROPgadget:
    //   --binary tests/fixtures/elf-Linux-x64 --opcode c3 -> 2443
    assert_eq!(total, 2443, "the unrestricted count must match the oracle");

    let narrowed = mcp
        .call_tool(
            2,
            "find_bytes",
            json!({"binary_path": elf, "opcode": "c3",
                   "range": "0x401000-0x401100", "max_results": 1}),
        )
        .await;
    let n = structured(&narrowed)["total_count"].as_u64().unwrap();
    println!("find_bytes c3: {total} unrestricted, {n} in 0x401000-0x401100");
    assert!(n < total, "range did not narrow: {n} vs {total}");

    // A range outside the image finds nothing at all, rather than falling
    // back to the whole file.
    let empty = mcp
        .call_tool(
            3,
            "find_bytes",
            json!({"binary_path": elf, "opcode": "c3",
                   "range": "0xdead0000-0xdead1000"}),
        )
        .await;
    assert_eq!(structured(&empty)["total_count"], 0, "{empty}");
}
