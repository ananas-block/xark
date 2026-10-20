//! `xark` frontend subcommands: `init` (scaffold), `build` (Rust → wasm32 →
//! R1CS), `test` and `check` (editor-facing validation). The backend subcommands
//! (`setup`/`prove`/`verify`/`export`/`ceremony`/`inspect`) live in the
//! [`crate::commands`] module; these keep their hand-rolled argument parsing
//! (driven from the clap layer in `commands`).

use std::path::PathBuf;
use std::process::Command;

/// `xark build <crate-dir> [--out DIR] [--field F]`
///
/// Builds the circuit crate for wasm32 with `cargo` (any stable toolchain), then
/// lowers the module with `xark-frontend`.
pub fn cmd_build(args: &[String]) -> i32 {
    cmd_build_impl(args, false)
}

/// The `xark build` command: [`cmd_build`], then what to run next. (The builds
/// other commands run first — `test`, `profile`, `prove`'s — stay quiet about
/// it.)
pub fn cmd_build_command(args: &[String]) -> i32 {
    let code = cmd_build(args);
    if code == 0 {
        let dir = args.first().map_or(".", String::as_str);
        eprintln!(
            "\n{}",
            crate::style::next_steps(&[(
                format!("xark setup {dir}"),
                "generate the proving/verifying keys",
            )])
        );
    }
    code
}

/// Like [`cmd_build`], but injects `--profile` so the extractor additionally
/// writes `profile.json` (per-constraint source/function/kind attribution). Used
/// by `xark profile`; a normal `xark build` never emits it.
pub fn cmd_build_profile(args: &[String]) -> i32 {
    cmd_build_impl(args, true)
}

fn cmd_build_impl(args: &[String], profile: bool) -> i32 {
    let mut crate_dir: Option<String> = None;
    let mut out: Option<String> = None;
    let mut field = "bn254".to_string();
    // `--emit-json`: also write the human-readable `circuit.json`. Off by default;
    // the prover/checker load `circuit.xbc`, so a normal build skips the (multi-GB
    // on large circuits) JSON serialization.
    let mut emit_json = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out = it.next().cloned(),
            "--field" => {
                if let Some(f) = it.next() {
                    field = f.clone();
                }
            }
            "--emit-json" => emit_json = true,
            _ if crate_dir.is_none() => crate_dir = Some(a.clone()),
            _ => {}
        }
    }
    let Some(crate_dir) = crate_dir else {
        eprintln!("error: `xark build <crate-dir>` requires a crate directory");
        return 2;
    };
    let crate_dir = PathBuf::from(crate_root(&crate_dir));
    let cwd = std::env::current_dir().expect("cwd");
    // Normalized: `.` leaves no `/./` in the paths printed below.
    let crate_abs: PathBuf = cwd.join(&crate_dir).components().collect();
    if !crate_abs.join("Cargo.toml").is_file() {
        let what = if crate_abs.is_dir() {
            "no Cargo.toml in"
        } else {
            "no such directory:"
        };
        eprintln!(
            "xark: {what} {} (expected a circuit crate)",
            crate_dir.display()
        );
        return 1;
    }
    // Named after the directory (`.` resolved) when `Cargo.toml` has no package.
    let name = crate_abs
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().and_then(|s| s.to_str()).map(str::to_string))
        .unwrap_or_else(|| "circuit".to_string());
    // xark's artifacts live under the crate's `target/xark/`, and the wasm32 /
    // `--cfg xark` build cache under `target/xark-wasm/` — both apart from the
    // crate's normal `target/` so they don't thrash the one `cargo` and
    // rust-analyzer use. Each circuit's artifacts land in a name-scoped
    // `target/xark/<pkg-name>/`, the package name from `Cargo.toml`
    // (`[package] name`) falling back to the directory name.
    let xark_dir = crate_abs.join("target/xark");
    let pkg_name = crate::xark_project::read_pkg_name(&crate_abs).unwrap_or_else(|| name.clone());
    let out_abs = out
        .map(|o| cwd.join(o))
        .unwrap_or_else(|| xark_dir.join(&pkg_name));

    build_stable(&crate_abs, &out_abs, &pkg_name, &field, profile, emit_json)
}

/// Everything `xark build` writes (beside the keys and proofs of later commands).
const BUILD_OUTPUTS: [&str; 8] = [
    "circuit.xbc",
    "circuit.json",
    "r1cs.json",
    "graph.dot",
    "profile.json",
    "entry",
    "digest",
    "schema.json",
];

/// `xark build`: `cargo` (any toolchain) builds the circuit
/// for wasm32, then `xark-frontend` runs it to lower the circuit.
fn build_stable(
    crate_abs: &std::path::Path,
    out_abs: &std::path::Path,
    name: &str,
    field: &str,
    profile: bool,
    emit_json: bool,
) -> i32 {
    eprintln!("{} building circuit `{name}`", crate::style::tag());
    // Clear the previous build's outputs first: if this build fails, `prove`,
    // `setup` and `export` must not go on with the old circuit, and a build
    // without `--emit-json`/`--profile` must not leave stale views beside it.
    // Keys stay: `prove` checks them against the circuit they were made for.
    for f in BUILD_OUTPUTS {
        let path = out_abs.join(f);
        if let Err(e) = std::fs::remove_file(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("xark: removing {}: {e}", path.display());
            return 1;
        }
    }
    // Every build carries DWARF line tables (free; see `BuildOptions`), so errors
    // and `--profile` attribution name source lines.
    let (target_dir, opts) = (
        crate_abs.join("target/xark-wasm"),
        xark_frontend::BuildOptions::default(),
    );
    let wasm = match xark_frontend::build_crate_with(crate_abs, &target_dir, &opts) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("xark: {e}");
            return 1;
        }
    };
    let mut lowered = match xark_frontend::lower_module(
        &wasm,
        xark_ir::FieldSpec::named(field),
        profile,
        emit_json,
    ) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{} {e}", crate::style::err("error:"));
            return 1;
        }
    };
    // The R1CS digest: what the proving/verifying keys depend on, and the same
    // under every supported rustc (docs/toolchain.md).
    let digest = lowered
        .output
        .function_xbc
        .as_deref()
        .map(|x| format!("{:032x}", xark_ir::function_decode::stream_digest(x)));
    if profile {
        xark_frontend::relativize_profile(&mut lowered.output, crate_abs);
    }
    if let Err(e) =
        xark_frontend::write_outputs_in(out_abs, &lowered.output, emit_json, profile, crate_abs)
    {
        eprintln!("xark: writing {}: {e}", out_abs.display());
        return 1;
    }
    if let Some(entry) = &lowered.entry {
        let _ = std::fs::write(out_abs.join("entry"), entry);
    }
    if let Some(d) = &digest {
        let _ = std::fs::write(out_abs.join("digest"), format!("{d}\n"));
    }
    let _ = std::fs::write(
        out_abs.join("schema.json"),
        serde_json::to_string_pretty(&lowered.schema).unwrap_or_default() + "\n",
    );
    let p = &lowered.output.primitive;
    eprintln!(
        "{} {} vars, {} constraints, {} witness-gen ops",
        crate::style::tag(),
        p.vars.len(),
        lowered.output.r1cs.constraints.len(),
        p.witness_gen.len(),
    );
    if let Some(d) = &digest {
        eprintln!("{} circuit digest {d}", crate::style::tag());
    }
    eprintln!(
        "{} wrote {}",
        crate::style::tag(),
        crate::style::brand(&out_abs.display().to_string())
    );
    0
}

/// `xark clean` — remove **every** xark output tree under the current directory:
/// each circuit crate's `target/xark/` (emitted artifacts, keys, proofs) and
/// `target/xark-wasm/` (the wasm build cache). Takes no arguments.
pub fn cmd_clean(_args: &[String]) -> i32 {
    fn walk(dir: &std::path::Path, removed: &mut u32, errors: &mut u32) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            // Not through symlinks: they can lead outside the current directory
            // (or loop).
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let path = entry.path();
            match path.file_name().and_then(|s| s.to_str()) {
                // Remove `target/xark{,-wasm}` here; don't descend into `target/`.
                Some("target") => {
                    for xark in [path.join("xark"), path.join("xark-wasm")] {
                        if !xark.is_dir() {
                            continue;
                        }
                        match std::fs::remove_dir_all(&xark) {
                            Ok(()) => {
                                eprintln!("xark: removed {}", xark.display());
                                *removed += 1;
                            }
                            Err(e) => {
                                eprintln!("xark: failed to remove {}: {e}", xark.display());
                                *errors += 1;
                            }
                        }
                    }
                }
                Some(".git" | "node_modules") => {} // never holds a circuit build
                _ => walk(&path, removed, errors),
            }
        }
    }
    let root = std::env::current_dir().expect("cwd");
    let (mut removed, mut errors) = (0u32, 0u32);
    walk(&root, &mut removed, &mut errors);
    if removed == 0 && errors == 0 {
        eprintln!(
            "xark: nothing to clean (no target/xark or target/xark-wasm under {})",
            root.display()
        );
    } else {
        eprintln!(
            "xark: cleaned {removed} xark target director{}",
            if removed == 1 { "y" } else { "ies" }
        );
    }
    (errors > 0) as i32
}

/// `xark test [crate-dir] [-- <cargo test args>]`
///
/// One-shot circuit testing: build the crate (`xark build`) so its
/// `target/xark/<pkg>/` artifacts exist, then run `cargo test` in the crate so
/// the in-crate `xark_prover::circuit(..).check(..)` tests can load them.
pub fn cmd_test(args: &[String]) -> i32 {
    // `args[0]` is the crate dir; the rest goes to `cargo test` verbatim, so
    // `xark test . -- --include-ignored` is `cargo test -- --include-ignored`.
    let crate_dir = crate_root(args.first().map_or(".", String::as_str));
    let forwarded = args.get(1..).unwrap_or(&[]);
    let build_argv = vec![crate_dir.clone()];

    // Build first so the tests' artifacts are present + current. Build with
    // `--profile` (also writes `profile.json`, leaving the other artifacts
    // byte-identical): the test harness reads it to explain which source line /
    // function a failing constraint came from.
    let code = cmd_build_profile(&build_argv);
    if code != 0 {
        eprintln!("xark: build failed; skipping tests");
        return code;
    }

    // Run in `--release`: circuit tests drive a full Groth16 setup+prove+verify,
    // 10–50× slower in debug (minutes vs seconds on a large hash/EC circuit), so
    // release is the sensible default. The other arguments go to `cargo test`
    // as given.
    eprintln!("xark: running `cargo test --release` in {crate_dir}");
    let status = Command::new("cargo")
        .arg("test")
        .arg("--release")
        .args(forwarded)
        .current_dir(&crate_dir)
        .status();
    match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("xark: failed to run cargo test: {e}");
            1
        }
    }
}

/// The circuit crate for a directory argument: `dir` itself, or, as cargo
/// finds it, the nearest enclosing package of the current directory (`xark
/// test` from `src/`). A named directory is taken as given, as cargo takes a
/// manifest path. Unchanged when there's none, for the caller to report.
fn crate_root(dir: &str) -> String {
    let p = std::path::Path::new(dir);
    if dir != "." || p.join("Cargo.toml").is_file() {
        return dir.to_string();
    }
    p.canonicalize()
        .ok()
        .and_then(|abs| {
            abs.ancestors()
                .skip(1)
                .find(|a| crate::xark_project::read_pkg_name(a).is_some())
                .map(|a| a.display().to_string())
        })
        .unwrap_or_else(|| dir.to_string())
}

/// `xark check <crate-dir>`
///
/// Fast, artifact-free validation of a circuit crate for editor diagnostics (see
/// `check_stable`). `--message-format=json` emits JSON diagnostics on stdout, the
/// shape `rust-analyzer`'s `check.overrideCommand` consumes.
pub fn cmd_check(args: &[String]) -> i32 {
    let mut crate_dir: Option<String> = None;
    let mut json = false;
    for a in args {
        match a.as_str() {
            // Emit machine-readable JSON diagnostics (for editors / rust-analyzer).
            "--message-format=json" | "--json" => json = true,
            _ if crate_dir.is_none() => crate_dir = Some(a.clone()),
            _ => {}
        }
    }
    let Some(crate_dir) = crate_dir else {
        eprintln!("error: `xark check <crate-dir>` requires a crate directory");
        return 2;
    };
    let crate_dir = PathBuf::from(crate_root(&crate_dir));
    let crate_abs = std::env::current_dir().expect("cwd").join(&crate_dir);
    check_stable(&crate_abs, json)
}

/// `xark check`: build the circuit for wasm32 (with line
/// tables, so a rejection points at its source line), then lower it. Cargo's own
/// diagnostics pass through; a lowering rejection is reported like a rustc error —
/// with `--message-format=json`, as a cargo `compiler-message` on stdout (what
/// rust-analyzer's `check.overrideCommand` reads).
fn check_stable(crate_abs: &std::path::Path, json: bool) -> i32 {
    // For an editor, xark check *replaces* rust-analyzer's `cargo check`, so it
    // runs one first: the circuit build below sees only the circuit (wasm32,
    // `cfg(xark)`), never the tests or other host-only code.
    let mut skip_rendered = std::collections::HashSet::new();
    if json {
        match host_check_json(crate_abs) {
            Some((true, seen)) => skip_rendered = seen,
            // Errors: reported; the circuit build would only repeat them.
            Some((false, _)) => return 1,
            None => {}
        }
    }
    let opts = xark_frontend::BuildOptions {
        json_diagnostics: json,
        skip_rendered,
        ..Default::default()
    };
    let target_dir = crate_abs.join("target/xark-wasm");
    let wasm = match xark_frontend::build_crate_with(crate_abs, &target_dir, &opts) {
        Ok(w) => w,
        // Cargo already reported why (on stdout as JSON when asked).
        Err(e) => {
            if !json {
                eprintln!("xark: {e}");
            }
            return 1;
        }
    };
    // Field-agnostic check: lower over BN254 (rejections don't depend on the field).
    match xark_frontend::lower_module(&wasm, xark_ir::FieldSpec::named("bn254"), false, false) {
        Ok(_) => {
            if !json {
                eprintln!("{} circuit ok", crate::style::tag());
            }
            0
        }
        Err(e) => {
            if json {
                println!("{}", check_diagnostic_json(crate_abs, &e));
            } else {
                eprintln!("{} {e}", crate::style::err("error:"));
            }
            1
        }
    }
}

/// `cargo check --all-targets` of the crate on the host, its JSON diagnostics
/// relayed to stdout: `(passed, the diagnostics' rendered text)`, or `None` if
/// cargo couldn't be run. Its `build-finished` line is held back unless it
/// failed (the circuit check after it then reports its own).
fn host_check_json(
    crate_abs: &std::path::Path,
) -> Option<(bool, std::collections::HashSet<String>)> {
    let out = Command::new("cargo")
        .args([
            "check",
            "--all-targets",
            "--message-format=json-diagnostic-rendered-ansi",
        ])
        .current_dir(crate_abs)
        .stderr(std::process::Stdio::inherit())
        .output()
        .ok()?;
    let ok = out.status.success();
    let mut seen = std::collections::HashSet::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let v = serde_json::from_str::<serde_json::Value>(line).ok();
        let reason = v.as_ref().and_then(|v| v["reason"].as_str());
        if ok && reason == Some("build-finished") {
            continue;
        }
        if let Some(r) = v.as_ref().and_then(|v| v["message"]["rendered"].as_str()) {
            seen.insert(r.to_string());
        }
        println!("{line}");
    }
    Some((ok, seen))
}

/// A frontend rejection as a cargo `compiler-message` (rustc's JSON diagnostic
/// shape), with the primary span at the error's source line when known.
fn check_diagnostic_json(crate_abs: &std::path::Path, e: &xark_frontend::CompileError) -> String {
    let package_id = std::fs::read_to_string(crate_abs.join("Cargo.toml"))
        .ok()
        .and_then(|m| {
            m.lines()
                .skip_while(|l| l.trim() != "[package]")
                .find_map(|l| {
                    let v = l
                        .trim()
                        .strip_prefix("name")?
                        .trim_start()
                        .strip_prefix('=')?;
                    Some(v.trim().trim_matches('"').to_string())
                })
        })
        .unwrap_or_default();
    let spans: Vec<serde_json::Value> = e
        .site
        .iter()
        .filter_map(|s| s.span.as_ref())
        .map(|(file, line, col)| {
            let col = (*col).max(1);
            serde_json::json!({
                "file_name": file,
                "byte_start": 0,
                "byte_end": 0,
                "line_start": line,
                "line_end": line,
                "column_start": col,
                "column_end": col + 1,
                "is_primary": true,
                "text": [],
                "label": null,
                "suggested_replacement": null,
                "suggestion_applicability": null,
                "expansion": null,
            })
        })
        .collect();
    let children: Vec<serde_json::Value> = e
        .notes
        .iter()
        .map(|n| ("note", n))
        .chain(e.help.iter().map(|h| ("help", h)))
        .map(|(level, m)| {
            serde_json::json!({
                "message": m, "code": null, "level": level, "spans": [],
                "children": [], "rendered": null,
            })
        })
        .collect();
    serde_json::json!({
        "reason": "compiler-message",
        "package_id": package_id,
        "manifest_path": crate_abs.join("Cargo.toml").display().to_string(),
        "target": { "name": package_id, "kind": ["lib"], "src_path": crate_abs.join("src/lib.rs").display().to_string() },
        "message": {
            "message": e.message,
            "code": { "code": "xark", "explanation": null },
            "level": "error",
            "spans": spans,
            "children": children,
            "rendered": format!("error: {e}\n"),
        },
    })
    .to_string()
}

/// `xark init [name]` — scaffold a ready-to-edit circuit crate, pre-wired for
/// rust-analyzer so unsupported constructs surface inline as you type (via
/// `xark check`). With no name, initializes the current directory.
pub fn cmd_init(args: &[String]) -> i32 {
    let name_arg = args.iter().find(|a| !a.starts_with('-')).cloned();
    let cwd = std::env::current_dir().expect("cwd");
    // The argument may be a path (`xark init circuits/demo`): the crate is named
    // after its last component.
    let dir = name_arg
        .as_ref()
        .map_or_else(|| cwd.clone(), |n| cwd.join(n));
    let name = dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("circuit")
        .to_string();
    if let Err(why) = check_crate_name(&name) {
        eprintln!(
            "error: can't name a crate `{name}`: {why}\n  \
             pick another directory name, e.g. `xark init {}`",
            suggest_crate_name(&name)
        );
        return 2;
    }

    // Pin the published `xark`/`xark-prover` deps to this CLI's own major.minor
    // (the whole workspace releases together), so the scaffold never suggests a
    // version older than the CLI you ran it with.
    let full = env!("CARGO_PKG_VERSION");
    let ver = full.rsplit_once('.').map_or(full, |(mm, _)| mm);
    let cargo_toml = format!(
        "[package]\n\
         name = \"{name}\"\n\
         version = \"0.1.0\"\n\
         edition = \"2024\"\n\n\
         [lib]\n\
         crate-type = [\"lib\"]\n\n\
         [dependencies]\n\
         xark = {{ version = \"{ver}\", default-features = false }}\n\
         # From git:               xark = {{ git = \"https://github.com/blueshift-gg/xark\", default-features = false }}\n\
         # From a local checkout:  xark = {{ path = \"../xark/crates/lang\", default-features = false }}\n\n\
         # `xark-prover` powers the in-crate `cargo test` circuit tests below. It's a\n\
         # host-only dependency rather than a dev-dependency because the code\n\
         # `#[circuit]` generates uses it outside tests too; `cfg(not(xark))` keeps it\n\
         # out of the circuit build.\n\
         [target.'cfg(not(xark))'.dependencies]\n\
         xark-prover = \"{ver}\"\n\
         # From git:               xark-prover = {{ git = \"https://github.com/blueshift-gg/xark\" }}\n\
         # From a local checkout:  xark-prover = {{ path = \"../xark/crates/prover\" }}\n\n\
         # `xark` is set only by the circuit build; declare it so rustc's `unexpected_cfgs`\n\
         # lint (1.80+) stays quiet.\n\
         [lints.rust]\n\
         unexpected_cfgs = {{ level = \"warn\", check-cfg = ['cfg(xark)'] }}\n"
    );
    let fn_ident = ident_of(&name);
    let lib_rs = format!(
        "{}{}",
        LIB_TEMPLATE.replace("__FN__", &fn_ident),
        tests_template(&fn_ident)
    );
    // Both files set the same rust-analyzer override: `rust-analyzer.toml` is the
    // editor-agnostic form; `.vscode/settings.json` covers VS Code specifically.
    let ra_cmd = "[\"xark\", \"check\", \".\", \"--message-format=json\"]";
    let files: [(&str, String); 5] = [
        ("Cargo.toml", cargo_toml),
        ("src/lib.rs", lib_rs),
        (
            "rust-analyzer.toml",
            format!(
                "# Run xark's subset validator on save so unsupported constructs show inline.\n\
                 # Needs `xark` on PATH. Replaces rust-analyzer's `cargo check`, which\n\
                 # `xark check` runs too.\n\
                 [check]\n\
                 overrideCommand = {ra_cmd}\n"
            ),
        ),
        (
            ".vscode/settings.json",
            format!("{{\n  \"rust-analyzer.check.overrideCommand\": {ra_cmd}\n}}\n"),
        ),
        (".gitignore", "/target\n".to_string()),
    ];

    let mut created = 0u32;
    for (rel, contents) in &files {
        let path = dir.join(rel);
        if path.exists() {
            eprintln!("xark: keeping existing {rel}");
            continue;
        }
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            eprintln!("xark: failed to create {}: {e}", parent.display());
            return 1;
        }
        if let Err(e) = std::fs::write(&path, contents) {
            eprintln!("xark: failed to write {rel}: {e}");
            return 1;
        }
        created += 1;
    }

    eprintln!(
        "xark: scaffolded circuit `{name}` ({created} files) in {}",
        dir.display()
    );
    let where_ = if let Some(n) = &name_arg {
        n.as_str()
    } else {
        "."
    };
    eprintln!(
        "{}",
        crate::style::next_steps(&[
            (
                format!("xark build {where_}"),
                "compile the circuit to R1CS"
            ),
            (
                format!("xark setup {where_}"),
                "generate the proving/verifying keys"
            ),
            (
                format!("xark prove {where_} --inputs '{{\"secret\": 3, \"result\": 9}}'"),
                "produce your first proof",
            ),
        ])
    );
    0
}

/// Refuse names `cargo new` refuses: the crate (and its `#[circuit]` fn, named
/// after it) must be a valid, non-keyword Rust identifier once `-` becomes `_`.
fn check_crate_name(name: &str) -> Result<(), &'static str> {
    const KEYWORDS: &[&str] = &[
        "_", "Self", "abstract", "as", "async", "await", "become", "box", "break", "const",
        "continue", "crate", "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for",
        "gen", "if", "impl", "in", "let", "loop", "macro", "match", "mod", "move", "mut",
        "override", "priv", "pub", "ref", "return", "self", "static", "struct", "super", "trait",
        "true", "try", "type", "typeof", "unsafe", "unsized", "use", "virtual", "where", "while",
        "yield",
    ];
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("only letters, digits, `-` and `_` are allowed");
    }
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        return Err("it starts with a digit");
    }
    if KEYWORDS.contains(&name.replace('-', "_").as_str()) {
        return Err("it is a Rust keyword");
    }
    Ok(())
}

/// A valid name close to a refused one: `type` → `type_circuit`,
/// `1st` → `circuit_1st`, `a b` → `a_b`.
fn suggest_crate_name(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.trim_matches('_').is_empty() {
        "circuit".to_string()
    } else if s.starts_with(|c: char| c.is_ascii_digit()) {
        format!("circuit_{s}")
    } else if check_crate_name(&s).is_err() {
        format!("{s}_circuit")
    } else {
        s
    }
}

/// Turn a crate name into a valid Rust identifier for the scaffolded entry fn
/// (`my-circuit` → `my_circuit`); falls back to `circuit`.
fn ident_of(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if s.is_empty() {
        return "circuit".to_string();
    }
    if s.starts_with(|c: char| c.is_ascii_digit()) {
        s.insert(0, '_');
    }
    s
}

/// The starter circuit written by `xark init`. The `#[cfg(test)] mod tests`
/// block ([`tests_template`]) is appended with the crate's own name filled in.
///
/// `no_std` applies to the real circuit build (via `xark build`) but is dropped
/// under `cargo test` so the `xark-prover` test harness (which uses `std`) can
/// link.
const LIB_TEMPLATE: &str = "\
#![cfg_attr(xark, no_std)]
use xark::prelude::*;

#[circuit]
pub fn __FN__(secret: Private<Field>, result: Public<Field>) {
    // prove knowledge of a square root: secret * secret == result
    require_eq(secret * secret, result);
}
";

/// The `#[cfg(test)] mod tests` appended to the scaffolded `src/lib.rs`.
///
/// They call the validator `#[circuit]` generates under the entry's name: the same
/// parameters, each taking anything that converts (`2` for a `Field`). These tests
/// load the built artifacts; `cargo test` builds them when needed.
fn tests_template(name: &str) -> String {
    format!(
        "\n\
         #[cfg(test)]\n\
         mod tests {{\n\
         \x20   use super::*;\n\
         \n\
         \x20   #[test]\n\
         \x20   fn accepts_valid() {{\n\
         \x20       {name}(2, 4).unwrap(); // 2 * 2 == 4\n\
         \x20   }}\n\
         \n\
         \x20   #[test]\n\
         \x20   fn rejects_invalid() {{\n\
         \x20       assert!({name}(3, 4).is_err()); // 3 * 3 != 4\n\
         \x20   }}\n\
         }}\n"
    )
}
