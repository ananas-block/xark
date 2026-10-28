//! The TypeScript target: one `.ts` file holding what's specific to the circuit, over
//! the shared runtime `@blueshift-gg/xark-wasm/client` (`Field`, `Proof`, `Circuit`).
//!
//! * per enum, its variants as constants and their type (`Country.US`, or `"US"`);
//! * an interface per input struct, every value in its natural TypeScript form;
//! * the inputs, the public inputs as given, and as decoded from a proof;
//! * the circuit, a runtime `Circuit` that makes its provers and verifiers
//!   (`Zkyc.prover(wasm, url)`), with their types (`ZkycProver`, `ZkycProof`);
//! * the crate's Rust functions (`#[input] impl`), run from `client.wasm`.
//!
//! | standard type          | as given                      | decoded       |
//! |------------------------|-------------------------------|---------------|
//! | field                  | `FieldInput` (`Field`, an integer) | `Field`  |
//! | `uN`                   | `number` (`bigint` past 32)   | `number`/`bigint` |
//! | bool                   | `boolean`                     | `boolean`     |
//! | bytes                  | `Uint8Array`                  | `Uint8Array`  |
//! | number (limbed)        | an integer, or bytes          | `bigint`      |
//! | date                   | `Date` (its UTC day)          | `Date`        |
//! | text                   | `string`                      | `string`      |
//! | choice of `E`          | `E` (a variant name)          | `E`           |
//! | set of `E`             | `E \| readonly E[]`           | `E[]`         |
//! | array, tuple, struct   | arrays, an interface          | the same      |

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use anyhow::Result;
use xark_schema::camel;

use super::MARKER;
use super::model::{Export, Model, Ty};

/// `zkyc_circuit` → `ZkycCircuit`.
pub fn pascal(s: &str) -> String {
    let c = camel(s);
    let mut chars = c.chars();
    match chars.next() {
        Some(f) => f.to_uppercase().chain(chars).collect(),
        None => "Circuit".into(),
    }
}

/// A TS property key for a field: `camelCase`, bare when it's an identifier, quoted
/// otherwise (tuple-struct `0`).
fn ts_key(name: &str) -> String {
    prop(&camel(name))
}

/// Property `key` (a [`ts_key`]) of `obj`: `obj.key`, or `obj["0"]` for a quoted one.
fn member(obj: &str, key: &str) -> String {
    if key.starts_with('"') {
        format!("{obj}[{key}]")
    } else {
        format!("{obj}.{key}")
    }
}

/// `name` as a TS property key, unchanged: bare when it's an identifier.
fn prop(name: &str) -> String {
    let ident = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$');
    if ident {
        name.into()
    } else {
        format!("{name:?}")
    }
}

/// One namespace for imports, generated circuit exports, schema types and decoders.
/// Circuit exports keep their familiar names; colliding application types use a
/// `Struct` suffix. Reserve every free application name before assigning suffixes,
/// so a renamed type cannot take another application's existing name.
struct Names {
    circuit: String,
    inputs: String,
    public_inputs: String,
    public_values: String,
    structs: String,
    proof: String,
    prover: String,
    verifier: String,
    application: BTreeMap<String, String>,
    values: BTreeMap<String, String>,
    decoders: BTreeMap<String, String>,
    used: BTreeSet<String>,
}

fn allocate(used: &mut BTreeSet<String>, preferred: &str, suffix: &str) -> String {
    if used.insert(preferred.to_string()) {
        return preferred.to_string();
    }
    let base = format!("{preferred}{suffix}");
    if used.insert(base.clone()) {
        return base;
    }
    for number in 2.. {
        let name = format!("{base}{number}");
        if used.insert(name.clone()) {
            return name;
        }
    }
    unreachable!("the identifier namespace is unbounded")
}

impl Names {
    fn new(m: &Model) -> Self {
        let mut used: BTreeSet<String> = [
            "CheckFailed",
            "Circuit",
            "Field",
            "InputError",
            "fromHex",
            "toHex",
            "Day",
            "FieldInput",
            "Json",
            "Proof",
            "Prover",
            "Text",
            "U128",
            "U16",
            "U32",
            "U64",
            "U8",
            "Verifier",
            "schema",
            "decodePublic",
            "Date",
            "BigInt",
            "Uint8Array",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let circuit = allocate(&mut used, &pascal(&m.circuit), "Circuit");
        let inputs = allocate(&mut used, &format!("{circuit}Inputs"), "Circuit");
        let public_inputs = allocate(&mut used, &format!("{circuit}PublicInputs"), "Circuit");
        let public_values = allocate(&mut used, &format!("{circuit}PublicValues"), "Circuit");
        let structs = allocate(&mut used, &format!("{circuit}Structs"), "Circuit");
        let proof = allocate(&mut used, &format!("{circuit}Proof"), "Circuit");
        let prover = allocate(&mut used, &format!("{circuit}Prover"), "Circuit");
        let verifier = allocate(&mut used, &format!("{circuit}Verifier"), "Circuit");
        let originals: BTreeSet<_> = m
            .structs
            .keys()
            .chain(m.enums.keys())
            .chain(m.exports.iter().map(|export| &export.ty))
            .cloned()
            .collect();
        let mut application = BTreeMap::new();
        for original in &originals {
            if used.insert(original.clone()) {
                application.insert(original.clone(), original.clone());
            }
        }
        for original in originals {
            application
                .entry(original.clone())
                .or_insert_with(|| allocate(&mut used, &original, "Struct"));
        }
        let mut values = BTreeMap::new();
        let mut decoders = BTreeMap::new();
        for original in m.structs.keys() {
            let name = application.get(original).expect("allocated schema struct");
            values.insert(
                original.clone(),
                allocate(&mut used, &format!("{name}Value"), "Decoded"),
            );
        }
        for original in m.structs.keys() {
            let name = application.get(original).expect("allocated schema struct");
            decoders.insert(
                original.clone(),
                allocate(&mut used, &format!("decode{name}"), "Value"),
            );
        }
        Self {
            circuit,
            inputs,
            public_inputs,
            public_values,
            structs,
            proof,
            prover,
            verifier,
            application,
            values,
            decoders,
            used,
        }
    }

    fn application(&self, original: &str) -> &str {
        self.application
            .get(original)
            .expect("allocated schema type")
    }

    fn value(&self, original: &str) -> &str {
        self.values.get(original).expect("allocated decoded struct")
    }

    fn decoder(&self, original: &str) -> &str {
        self.decoders
            .get(original)
            .expect("allocated struct decoder")
    }

    /// Preserve user parameter names where possible, then name the receiver in
    /// the same scope. Neither may shadow a binding used by the generated body.
    fn parameters(&self, export: &Export) -> (Vec<String>, Option<String>) {
        let mut used = self.used.clone();
        used.extend(
            [
                "arguments",
                "await",
                "break",
                "case",
                "catch",
                "class",
                "const",
                "continue",
                "debugger",
                "default",
                "delete",
                "do",
                "else",
                "enum",
                "eval",
                "export",
                "extends",
                "false",
                "finally",
                "for",
                "function",
                "if",
                "implements",
                "import",
                "in",
                "instanceof",
                "interface",
                "let",
                "new",
                "null",
                "package",
                "private",
                "protected",
                "public",
                "return",
                "static",
                "super",
                "switch",
                "this",
                "throw",
                "true",
                "try",
                "typeof",
                "var",
                "void",
                "while",
                "with",
                "yield",
            ]
            .into_iter()
            .map(str::to_string),
        );
        let mut claimed = used.clone();
        let preferred: Vec<String> = export.params.iter().map(|p| camel(&p.name)).collect();
        used.extend(preferred.iter().cloned());
        let params = preferred
            .into_iter()
            .map(|name| {
                if claimed.insert(name.clone()) {
                    name
                } else {
                    allocate(&mut used, &name, "Param")
                }
            })
            .collect();
        let receiver = export.receiver.map(|_| {
            allocate(
                &mut used,
                &camel(&self.application(&export.ty).to_lowercase()),
                "Self",
            )
        });
        (params, receiver)
    }
}

/// The TS type a caller passes for `ty`.
fn input(ty: &Ty, names: &Names) -> String {
    match ty {
        Ty::Field => "FieldInput".into(),
        Ty::Uint(w @ (8 | 16 | 32 | 64 | 128)) => format!("U{w}"),
        Ty::Uint(w) if *w <= 32 => "number".into(),
        Ty::Uint(_) => "bigint | number".into(),
        Ty::Bool => "boolean".into(),
        Ty::Bytes { .. } => "Uint8Array".into(),
        Ty::Number { .. } => "bigint | number | string | Uint8Array".into(),
        Ty::Date => "Day".into(),
        Ty::Text { max: TEXT } => "Text".into(),
        Ty::Text { .. } => "string".into(),
        Ty::Choice(e) => names.application(e).to_string(),
        Ty::Set(e) => {
            let e = names.application(e);
            format!("{e} | readonly {e}[]")
        }
        Ty::Array(t, n) if *n as usize <= TUPLE => {
            format!(
                "readonly [{}]",
                vec![input(t, names); *n as usize].join(", ")
            )
        }
        Ty::Array(t, _) => format!("readonly {}[]", paren(&input(t, names))),
        Ty::Tuple(ts) => {
            let parts: Vec<String> = ts.iter().map(|t| input(t, names)).collect();
            format!("readonly [{}]", parts.join(", "))
        }
        Ty::Struct(r) => names.application(r).to_string(),
    }
}

/// The TS type of `ty` decoded from a proof; notes the structs it needs decoders for.
fn value(ty: &Ty, structs: &mut BTreeSet<String>, names: &Names) -> String {
    match ty {
        Ty::Field => "Field".into(),
        Ty::Number { .. } => "bigint".into(),
        Ty::Uint(w) if *w <= 53 => "number".into(),
        Ty::Uint(_) => "bigint".into(),
        Ty::Bool => "boolean".into(),
        Ty::Bytes { .. } => "Uint8Array".into(),
        Ty::Date => "Day".into(),
        Ty::Text { max: TEXT } => "Text".into(),
        Ty::Text { .. } => "string".into(),
        Ty::Choice(e) => names.application(e).to_string(),
        Ty::Set(e) => format!("{}[]", names.application(e)),
        Ty::Array(t, n) if *n as usize <= TUPLE => {
            format!(
                "[{}]",
                vec![value(t, structs, names); *n as usize].join(", ")
            )
        }
        Ty::Array(t, _) => format!("{}[]", paren(&value(t, structs, names))),
        Ty::Tuple(ts) => {
            let parts: Vec<String> = ts.iter().map(|t| value(t, structs, names)).collect();
            format!("[{}]", parts.join(", "))
        }
        Ty::Struct(r) => {
            structs.insert(r.clone());
            names.value(r).to_string()
        }
    }
}

/// An expression converting `e` (the decoded JSON for `ty`) to its TS value.
fn revive(ty: &Ty, e: &str, names: &Names) -> String {
    match ty {
        Ty::Field => format!("new Field({e})"),
        Ty::Number { .. } => format!("BigInt({e})"),
        Ty::Uint(w) if *w > 53 => format!("BigInt({e})"),
        Ty::Uint(_) | Ty::Bool | Ty::Text { .. } | Ty::Choice(_) | Ty::Set(_) => e.into(),
        Ty::Bytes { .. } => format!("fromHex({e})"),
        Ty::Date => format!("new Date({e})"),
        // Element by element, so a fixed length stays a tuple.
        Ty::Array(t, n) if *n as usize <= TUPLE => {
            let parts: Vec<String> = (0..*n)
                .map(|i| revive(t, &format!("{e}[{i}]"), names))
                .collect();
            format!("[{}]", parts.join(", "))
        }
        Ty::Array(t, _) => format!("{e}.map((x) => {})", revive(t, "x", names)),
        Ty::Tuple(ts) => {
            let parts: Vec<String> = ts
                .iter()
                .enumerate()
                .map(|(i, t)| revive(t, &format!("{e}[{i}]"), names))
                .collect();
            format!("[{}]", parts.join(", "))
        }
        Ty::Struct(r) => format!("{}({e})", names.decoder(r)),
    }
}

/// A doc line for what the TS type doesn't say (widths, lengths, limits).
fn note(ty: &Ty) -> Option<String> {
    Some(match ty {
        // Named aliases (`U64`, `Day`, `Text`) carry their own docs, and a tuple its length.
        Ty::Uint(8 | 16 | 32 | 64 | 128) | Ty::Date | Ty::Text { max: TEXT } => return None,
        Ty::Array(_, n) if *n as usize <= TUPLE => return None,
        Ty::Choice(_) => return None,
        Ty::Uint(w) => format!("`u{w}`: an integer in [0, 2^{w})."),
        Ty::Bytes {
            of: None,
            len: Some(n),
        } => format!("`[u8; {n}]`: exactly {n} bytes."),
        Ty::Bytes {
            of: Some(r),
            len: Some(n),
        } => format!("`{r}`: its {n} bytes."),
        Ty::Bytes {
            of: Some(r),
            len: None,
        } => format!("`{r}`: its bytes."),
        Ty::Bytes { .. } => return None,
        Ty::Number { of } => format!("`{of}`: the number, or its little-endian bytes."),
        Ty::Text { max } => format!("Text: at most {max} UTF-8 bytes."),
        Ty::Set(e) => format!("A set of `{e}`: one, or a list of them."),
        Ty::Array(_, n) => format!("Exactly {n} elements."),
        Ty::Field | Ty::Bool | Ty::Tuple(_) | Ty::Struct(_) => return None,
    })
}

/// The client functions (`#[input]` on an `impl`): per type, an object of typed functions
/// running the Rust code in `client.wasm` (`Policy.default()`). Also returned: per type,
/// its `self` methods as class members of its decoded value, so they chain on
/// whatever a function returns (`Policy.default().on(day).minAge(18)`).
fn exports_ts(
    m: &Model,
    value_structs: &mut BTreeSet<String>,
    allocated: &Names,
) -> (String, BTreeMap<String, String>) {
    let mut out = String::new();
    let mut methods: BTreeMap<String, String> = BTreeMap::new();
    let circuit = &allocated.circuit;
    let mut types: Vec<&str> = Vec::new();
    for e in &m.exports {
        if !types.contains(&e.ty.as_str()) {
            types.push(&e.ty);
        }
    }
    let jsdoc = |doc: &str, indent: &str| {
        if doc.is_empty() {
            return String::new();
        }
        let mut d = format!("{indent}/**\n");
        for line in doc.lines() {
            let _ = writeln!(d, "{indent} * {line}");
        }
        let _ = writeln!(d, "{indent} */");
        d
    };
    for original in types {
        let t = allocated.application(original);
        let _ = writeln!(
            out,
            "/** `{original}`'s Rust functions (`#[input] impl {original}`), run from `client.wasm`. */\nexport const {t} = {{"
        );
        for e in m.exports.iter().filter(|e| e.ty == original) {
            let (names, receiver) = allocated.parameters(e);
            let params: Vec<String> = e
                .params
                .iter()
                .zip(&names)
                .map(|(p, name)| format!("{name}: {}", input(&p.ty, allocated)))
                .collect();
            let mut all_params = params.clone();
            let mut all_names = names.clone();
            if let Some(this) = receiver {
                all_params.insert(0, format!("{this}: {t}"));
                all_names.insert(0, this);
            }
            let ret = value(&e.returns, value_structs, allocated);
            let call = format!(
                "{circuit}.call<Json<{ret}>>({:?}, [{}])",
                e.export,
                all_names.join(", ")
            );
            out.push_str(&jsdoc(&e.doc, "  "));
            let _ = writeln!(
                out,
                "  {}({}): {ret} {{\n    return {};\n  }},",
                camel(&e.name),
                all_params.join(", "),
                revive(&e.returns, &call, allocated)
            );
            // Field names and class/JSON hooks keep their value semantics. A
            // conflicting Rust method stays available as `Type.method(value, …)`.
            let method_name = camel(&e.name);
            let shares_field = m
                .structs
                .get(original)
                .is_some_and(|fields| fields.iter().any(|field| camel(&field.name) == method_name));
            if e.receiver.is_some()
                && !shares_field
                && !matches!(method_name.as_str(), "constructor" | "toJSON")
            {
                let body = methods.entry(original.to_string()).or_default();
                body.push_str(&jsdoc(&e.doc, "  "));
                let _ = writeln!(
                    body,
                    "  {n}({p}): {ret} {{\n    return {t}.{n}(this{a});\n  }}\n",
                    n = camel(&e.name),
                    p = params.join(", "),
                    a = names.iter().map(|n| format!(", {n}")).collect::<String>(),
                );
            }
        }
        out.push_str("};\n\n");
    }
    (out, methods)
}

/// `a | b` → `(a | b)` where it needs the parentheses (an array element).
fn paren(t: &str) -> String {
    if t.contains(' ') {
        format!("({t})")
    } else {
        t.into()
    }
}

/// The generated TypeScript module for `m`.
/// The circuit's `schema.json` as a module the client imports: the same JSON as its
/// default export, so the client needs no JSON-import settings.
pub fn schema_module(circuit: &str, schema: &serde_json::Value) -> Result<String> {
    Ok(format!(
        "// {MARKER}: the `{circuit}` circuit's schema.json, which its client imports.\n\
         const schema = {};\n\
         export default schema;\n",
        serde_json::to_string_pretty(schema)?
    ))
}

/// The allocated circuit export, for the CLI's generated usage instructions.
pub(super) fn circuit_name(m: &Model) -> String {
    Names::new(m).circuit
}

/// The client, importing its schema from `schema_import` (`./zkyc.schema`, the `.ts`).
pub fn generate(m: &Model, schema_import: &str) -> Result<String> {
    let circuit = m.circuit.as_str();
    let names = Names::new(m);
    let name = &names.circuit;
    let inputs = &names.inputs;
    let public_inputs = &names.public_inputs;
    let public_values = &names.public_values;
    let proof = &names.proof;
    let prover = &names.prover;
    let verifier = &names.verifier;
    let mut out = String::new();

    // Where this came from.
    let sig: Vec<String> = m
        .inputs
        .iter()
        .map(|(f, public)| {
            let vis = if *public { "Public" } else { "Private" };
            format!("{}: {vis}<{}>", f.name, f.rust)
        })
        .collect();
    let _ = writeln!(
        out,
        "// {MARKER} from `schema.json`: a typed client for the `{circuit}` circuit.\n\
         //\n\
         //   #[circuit]\n\
         //   fn {circuit}({})\n\
         //\n\
         // `xark build` records the circuit's parameter types in target/xark/{circuit}/schema.json\n\
         // and `xark client` turns them into the types below. Don't edit this file: change\n\
         // the circuit, then rebuild and rerun `xark client`. Values go in their natural\n\
         // forms (dates, strings, variant names, bytes); xark-wasm encodes them against the\n\
         // schema (in `{schema_import}.ts`, written with this file), exactly as `xark prove\n\
         // --inputs` does.\n",
        sig.join(", "),
    );

    // The runtime's imports go here, once the body says which it uses.
    let head = std::mem::take(&mut out);

    // Enums: the variants as constants (`Country.US`) and their type (`"AD" | …`), so
    // a value is checked, and either form passes.
    for (original, variants) in &m.enums {
        let e = names.application(original);
        let _ = writeln!(
            out,
            "/** A `{original}` (an enum in the circuit): `{e}.{v}`, or its name, `{v:?}`. */\n\
             export const {e} = {{",
            v = variants.first().map_or("", String::as_str),
        );
        for chunk in variants.chunks(8) {
            let row: Vec<String> = chunk
                .iter()
                .map(|v| format!("{}: {v:?},", prop(v)))
                .collect();
            let _ = writeln!(out, "  {}", row.join(" "));
        }
        let _ = writeln!(
            out,
            "}} as const;\nexport type {e} = (typeof {e})[keyof typeof {e}];\n"
        );
    }

    // Input structs.
    for (r, fields) in &m.structs {
        let emitted = names.application(r);
        let _ = writeln!(
            out,
            "/** {} `{r}` (an input struct). */\nexport interface {emitted} {{",
            article(r)
        );
        for f in fields {
            if let Some(n) = note(&f.ty) {
                let _ = writeln!(out, "  /** {n} */");
            }
            let _ = writeln!(out, "  {}: {};", ts_key(&f.name), input(&f.ty, &names));
        }
        out.push_str("}\n\n");
    }

    // The inputs.
    let fields = |out: &mut String, public_only: bool| {
        for (f, public) in &m.inputs {
            if public_only && !public {
                continue;
            }
            if let Some(n) = note(&f.ty) {
                let _ = writeln!(out, "  /** {n} */");
            }
            let _ = writeln!(out, "  {}: {};", ts_key(&f.name), input(&f.ty, &names));
        }
    };
    let _ = writeln!(
        out,
        "/** Every input of `{circuit}`. */\nexport interface {inputs} {{"
    );
    fields(&mut out, false);
    out.push_str("}\n\n");
    let _ = writeln!(
        out,
        "/** The public inputs: what a verifier supplies, and what a proof reveals. */\n\
         export interface {public_inputs} {{"
    );
    fields(&mut out, true);
    out.push_str("}\n\n");

    // The public inputs as decoded.
    let mut value_structs = BTreeSet::new();
    let mut body = String::new();
    let _ = writeln!(
        body,
        "/** The public inputs, decoded from a proof. */\nexport interface {public_values} {{"
    );
    let mut decode = String::new();
    let _ = writeln!(
        decode,
        "function decodePublic(v: Json<{public_values}>): {public_values} {{\n  return {{"
    );
    for f in m.public() {
        let k = ts_key(&f.name);
        let _ = writeln!(body, "  {k}: {};", value(&f.ty, &mut value_structs, &names));
        let _ = writeln!(
            decode,
            "    {k}: {},",
            revive(&f.ty, &member("v", &k), &names)
        );
    }
    body.push_str("}\n\n");
    decode.push_str("  };\n}\n\n");
    // The client functions (their decoders join the ones below).
    let (exports, methods) = exports_ts(m, &mut value_structs, &names);

    // Decoded structs (closed over what the public inputs and exports reach): a
    // class when the type has Rust methods, so they chain on its values.
    let mut done = BTreeSet::new();
    let mut structs = String::new();
    while let Some(r) = value_structs.iter().find(|r| !done.contains(*r)).cloned() {
        done.insert(r.clone());
        let decoded = names.value(&r);
        let decoder = names.decoder(&r);
        let mut fields = String::new();
        let mut revived = String::new();
        for f in &m.structs[&r] {
            let k = ts_key(&f.name);
            let _ = writeln!(
                fields,
                "  {k}: {};",
                value(&f.ty, &mut value_structs, &names)
            );
            let _ = writeln!(
                revived,
                "    {k}: {},",
                revive(&f.ty, &member("v", &k), &names)
            );
        }
        let (doc, open, close) = match methods.get(&r) {
            Some(_) => (
                format!("A `{r}`, decoded, with its Rust methods"),
                format!("new {decoded}({{"),
                "})",
            ),
            None => (format!("A `{r}`, decoded"), "{".to_string(), "}"),
        };
        let _ = writeln!(
            decode,
            "function {decoder}(v: Json<{decoded}>): {decoded} {{\n  return {open}\n{revived}  }}{};\n}}\n",
            &close[1..],
        );
        match methods.get(&r) {
            Some(_)
                if m.structs[&r]
                    .iter()
                    .any(|f| ts_key(&f.name) == "constructor") =>
            {
                anyhow::bail!(
                    "`{r}` has a field named `constructor` and Rust methods: its client \
                     class can't have that field. Rename the field"
                );
            }
            Some(body) => {
                let assign: String = m.structs[&r]
                    .iter()
                    .map(|f| {
                        let k = ts_key(&f.name);
                        format!("    {} = {};\n", member("this", &k), member("v", &k))
                    })
                    .collect();
                let _ = writeln!(
                    structs,
                    "/** {doc}. */\nexport class {decoded} {{\n{fields}\n  \
                     constructor(v: {{\n{inner}  }}) {{\n{assign}  }}\n\n{body}}}\n",
                    inner = fields
                        .lines()
                        .map(|l| format!("  {l}\n"))
                        .collect::<String>(),
                    body = body.trim_end_matches('\n').to_string() + "\n",
                );
            }
            None => {
                let _ = writeln!(
                    structs,
                    "/** {doc}. */\nexport interface {decoded} {{\n{fields}}}\n"
                );
            }
        }
    }
    out.push_str(&structs);
    out.push_str(&body);

    // The structs `fields` takes, by name.
    let structs = if m.structs.is_empty() {
        "{}".to_string()
    } else {
        let _ = writeln!(
            out,
            "/** The input structs, by name: what `fields` takes. */\nexport interface {} {{",
            names.structs
        );
        for r in m.structs.keys() {
            let _ = writeln!(out, "  {}: {};", prop(r), names.application(r));
        }
        out.push_str("}\n\n");
        names.structs.clone()
    };

    // The circuit.
    let _ = writeln!(
        out,
        "/**\n \
         * `{circuit}`: make a prover or verifier from a URL serving a copy of\n \
         * `target/xark/{circuit}/` (relative to the page in a browser) or from the bytes:\n \
         *\n \
         * ```ts\n \
         * const prover = await {name}.prover(\"/circuits/{circuit}/\");\n \
         * const proof = prover.prove(inputs);\n \
         * send(proof.toBytes()); // the proof; an exported Solana verifier reads it as is\n \
         * const verifier = await {name}.verifier(vkBytes);\n \
         * verifier.verify(bytes, publicInputs); // true: it proves the public inputs you require\n \
         * ```\n \
         */\n\
         export const {name} = new Circuit<{inputs}, {public_inputs}, {public_values}, {structs}>({{\n  \
         name: {circuit:?},\n  \
         schema,\n  \
         decodePublic,\n  \
         client: {},\n{}\
         }});\n\n\
         export type {prover} = Prover<{inputs}, {public_inputs}, {public_values}, {structs}>;\n\
         export type {verifier} = Verifier<{public_inputs}, {public_values}, {structs}>;\n\
         export type {proof} = Proof<{public_values}>;\n",
        !m.exports.is_empty(),
        m.digest
            .as_ref()
            .map_or(String::new(), |d| format!("  digest: {d:?},\n")),
    );
    out.push_str(&exports);
    out.push_str(&decode);
    let out = out.trim_end().to_string() + "\n";

    // Import what the body uses from the runtime, and re-export `Field`.
    let values = [
        "CheckFailed",
        "Circuit",
        "Field",
        "InputError",
        "fromHex",
        "toHex",
    ];
    // The runtime's types the body names (outside comments).
    let code: String = out
        .lines()
        .filter(|l| !l.trim_start().starts_with("//") && !l.trim_start().starts_with('*'))
        .collect::<Vec<_>>()
        .join("\n");
    let names = |name: &str| {
        code.match_indices(name).any(|(i, _)| {
            let ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$';
            !code[..i].ends_with(ident) && !code[i + name.len()..].starts_with(ident)
        })
    };
    let mut types: Vec<&str> = [
        "Day",
        "FieldInput",
        "Json",
        "Proof",
        "Prover",
        "Text",
        "U128",
        "U16",
        "U32",
        "U64",
        "U8",
        "Verifier",
    ]
    .into_iter()
    .filter(|t| matches!(*t, "Json" | "Proof" | "Prover" | "Verifier") || names(t))
    .collect();
    types.sort();
    let imports: Vec<String> = values
        .iter()
        .map(|v| v.to_string())
        .chain(types.iter().map(|t| format!("type {t}")))
        .collect();
    Ok(format!(
        "{head}\
         import {{ {} }} from \"{RUNTIME}\";\n\
         import schema from \"./{schema_import}\";\n\
         export {{ CheckFailed, Field, InputError, fromHex, toHex }};\n\n\
         {out}",
        imports.join(", ")
    ))
}

/// "A" or "An", for a name.
fn article(name: &str) -> &'static str {
    match name.chars().next().map(|c| c.to_ascii_lowercase()) {
        Some('a' | 'e' | 'i' | 'o' | 'u') => "An",
        _ => "A",
    }
}

/// `Text`'s length, the standard one the runtime's `Text` alias documents.
const TEXT: u64 = 31;
/// Arrays up to this long are tuples (`readonly [Field, Field, Field, Field]`), so a
/// wrong length doesn't compile; longer ones are arrays checked when encoded.
const TUPLE: usize = 16;

/// The module every generated client imports: `Field`, `Proof`, `Circuit`.
const RUNTIME: &str = "@blueshift-gg/xark-wasm/client";

#[cfg(test)]
#[path = "../../../tests/unit/client_names.rs"]
mod tests;
