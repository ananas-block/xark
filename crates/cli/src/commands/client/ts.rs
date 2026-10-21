//! The TypeScript target: one `.ts` file over the xark-wasm module you pass in.
//!
//! * per enum, its variants as constants and their type (`Country.US`, or `"US"`);
//! * an interface per input struct, every value in its natural TypeScript form;
//! * the inputs, the public inputs as given, and as decoded from a proof;
//! * a class with `prove`, `verify`, the public-input encode/decode, `load` (the
//!   build output from a URL) and `fields` (a value's field elements, to hash it).
//!
//! | standard type          | as given                      | decoded       |
//! |------------------------|-------------------------------|---------------|
//! | field                  | `Field` (checked when made)   | `Field`       |
//! | `uN`                   | `number` (`bigint` past 32)   | `number`/`bigint` |
//! | bool                   | `boolean`                     | `boolean`     |
//! | bytes                  | `Uint8Array`, numbers, `0x…`  | `Uint8Array`  |
//! | number (limbed)        | an integer, or bytes          | `bigint`      |
//! | date                   | `Date` (its UTC day)          | `Date`        |
//! | text                   | `string`                      | `string`      |
//! | choice of `E`          | `E` (a variant name)          | `E`           |
//! | set of `E`             | `E \| readonly E[]`           | `E[]`         |
//! | array, tuple, struct   | arrays, an interface          | the same      |

use std::collections::BTreeSet;
use std::fmt::Write as _;

use anyhow::Result;
use xark_prover::schema::camel;

use super::MARKER;
use super::model::{Model, Ty};

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

/// The TS type a caller passes for `ty`.
fn input(ty: &Ty) -> String {
    match ty {
        Ty::Field => "Field".into(),
        Ty::Uint(w) if *w <= 32 => "number".into(),
        Ty::Uint(_) => "bigint | number".into(),
        Ty::Bool => "boolean".into(),
        Ty::Bytes { .. } => "Bytes".into(),
        Ty::Number { .. } => "bigint | number | string | Uint8Array".into(),
        Ty::Date => "Date".into(),
        Ty::Text { .. } => "string".into(),
        Ty::Choice(e) => e.clone(),
        Ty::Set(e) => format!("{e} | readonly {e}[]"),
        Ty::Array(t, _) => format!("readonly {}[]", paren(&input(t))),
        Ty::Tuple(ts) => {
            let parts: Vec<String> = ts.iter().map(input).collect();
            format!("readonly [{}]", parts.join(", "))
        }
        Ty::Struct(r) => r.clone(),
    }
}

/// The TS type of `ty` decoded from a proof; notes the structs it needs decoders for.
fn value(ty: &Ty, structs: &mut BTreeSet<String>) -> String {
    match ty {
        Ty::Field => "Field".into(),
        Ty::Number { .. } => "bigint".into(),
        Ty::Uint(w) if *w <= 53 => "number".into(),
        Ty::Uint(_) => "bigint".into(),
        Ty::Bool => "boolean".into(),
        Ty::Bytes { .. } => "Uint8Array".into(),
        Ty::Date => "Date".into(),
        Ty::Text { .. } => "string".into(),
        Ty::Choice(e) => e.clone(),
        Ty::Set(e) => format!("{e}[]"),
        Ty::Array(t, _) => format!("{}[]", paren(&value(t, structs))),
        Ty::Tuple(ts) => {
            let parts: Vec<String> = ts.iter().map(|t| value(t, structs)).collect();
            format!("[{}]", parts.join(", "))
        }
        Ty::Struct(r) => {
            structs.insert(r.clone());
            format!("{r}Value")
        }
    }
}

/// An expression converting `e` (the decoded JSON for `ty`) to its TS value.
fn revive(ty: &Ty, e: &str) -> String {
    match ty {
        Ty::Field => format!("new Field({e})"),
        Ty::Number { .. } => format!("BigInt({e})"),
        Ty::Uint(w) if *w > 53 => format!("BigInt({e})"),
        Ty::Uint(_) | Ty::Bool | Ty::Text { .. } | Ty::Choice(_) | Ty::Set(_) => e.into(),
        Ty::Bytes { .. } => format!("fromHex({e})"),
        Ty::Date => format!("new Date({e})"),
        Ty::Array(t, _) => format!("{e}.map((x: any) => {})", revive(t, "x")),
        Ty::Tuple(ts) => {
            let parts: Vec<String> = ts
                .iter()
                .enumerate()
                .map(|(i, t)| revive(t, &format!("{e}[{i}]")))
                .collect();
            format!("[{}]", parts.join(", "))
        }
        Ty::Struct(r) => format!("decode{r}({e})"),
    }
}

/// A doc line for what the TS type doesn't say (widths, lengths, limits).
fn note(ty: &Ty) -> Option<String> {
    Some(match ty {
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
        Ty::Number { of } => format!("`{of}`: the number, or its big-endian bytes."),
        Ty::Date => "A calendar day: the `Date`'s UTC day, as `toISOString()` shows it \
             (`new Date(\"1990-01-01\")`)."
            .into(),
        Ty::Text { max } => format!("`Text`: at most {max} UTF-8 bytes."),
        Ty::Choice(e) => format!("One `{e}`."),
        Ty::Set(e) => format!("A set of `{e}`: one, or a list of them."),
        Ty::Array(_, n) => format!("Exactly {n} elements."),
        Ty::Field | Ty::Bool | Ty::Tuple(_) | Ty::Struct(_) => return None,
    })
}

/// The client functions (`#[input]` on an `impl`): per type, an object of typed functions running
/// the Rust code in `client.wasm` (`Policy.on(day)`), and on values they return, the
/// type's `self` methods (`Policy.on(day).minAge(18)`). Plus the loader they share.
fn exports_ts(m: &Model, value_structs: &mut BTreeSet<String>) -> String {
    if m.exports.is_empty() {
        return String::new();
    }
    let mut out = String::from(CLIENT);
    let mut types: Vec<&str> = Vec::new();
    for e in &m.exports {
        if !types.contains(&e.ty.as_str()) {
            types.push(&e.ty);
        }
    }
    let field_named = |t: &str, name: &str| {
        m.structs
            .get(t)
            .is_some_and(|fs| fs.iter().any(|f| ts_key(&f.name) == camel(name)))
    };
    // Methods ride on values a function returns, so only a type something returns
    // gets them.
    let with_methods = |t: &str| {
        m.exports
            .iter()
            .any(|e| e.returns == Ty::Struct(t.to_string()))
            && m.exports
                .iter()
                .any(|e| e.ty == t && e.receiver.is_some() && !field_named(t, &e.name))
    };
    // A result, typed and revived (with its type's methods when it has some).
    let result = |ty: &Ty, call: String, value_structs: &mut BTreeSet<String>| match ty {
        Ty::Struct(r) if with_methods(r) => (
            format!("{} & {r}Methods", value(ty, value_structs)),
            format!("with{r}Methods({})", revive(ty, &call)),
        ),
        _ => (value(ty, value_structs), revive(ty, &call)),
    };
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
    for t in types {
        let fns: Vec<_> = m.exports.iter().filter(|e| e.ty == t).collect();
        let this = camel(&t.to_lowercase());
        let _ = writeln!(
            out,
            "/** `{t}`'s Rust functions (`#[input] impl {t}`), run from `client.wasm`. */\nexport const {t} = {{"
        );
        let mut methods = String::new();
        let mut binds = String::new();
        for e in &fns {
            let params: Vec<String> = e
                .params
                .iter()
                .map(|p| format!("{}: {}", ts_key(&p.name), input(&p.ty)))
                .collect();
            let names: Vec<String> = e.params.iter().map(|p| ts_key(&p.name)).collect();
            let mut all_params = params.clone();
            let mut all_names = names.clone();
            if e.receiver.is_some() {
                all_params.insert(0, format!("{this}: {t}"));
                all_names.insert(0, this.clone());
            }
            let call = format!("callRust({:?}, [{}])", e.export, all_names.join(", "));
            let (ret, body) = result(&e.returns, call, value_structs);
            out.push_str(&jsdoc(&e.doc, "  "));
            let _ = writeln!(
                out,
                "  {}({}): {ret} {{\n    return {body};\n  }},",
                camel(&e.name),
                all_params.join(", ")
            );
            // A method named like one of the type's fields can't sit on a value beside
            // it (in Rust they don't clash): it stays `Type.method(value, …)` only.
            if e.receiver.is_some() && !field_named(t, &e.name) {
                methods.push_str(&jsdoc(&e.doc, "  "));
                let _ = writeln!(
                    methods,
                    "  {}({}): {ret};",
                    camel(&e.name),
                    params.join(", ")
                );
                let _ = writeln!(
                    binds,
                    "    {n}: {{ value(this: {t}, {p}) {{ return {t}.{n}(this{a}); }} }},",
                    n = camel(&e.name),
                    p = params.join(", "),
                    a = names.iter().map(|n| format!(", {n}")).collect::<String>(),
                );
            }
        }
        out.push_str("};\n\n");
        if with_methods(t) {
            let _ = writeln!(
                out,
                "/**\n * `{t}`'s Rust methods, on a value its functions return: `{t}.…(…).method(…)`.\n * \
                 A method named like a field is only `{t}.method(value, …)`.\n */\n\
                 export interface {t}Methods {{\n{methods}}}\n\n\
                 function with{t}Methods<T extends object>(value: T): T & {t}Methods {{\n  \
                 return Object.defineProperties(value, {{\n{binds}  }}) as T & {t}Methods;\n}}\n\n"
            );
        }
    }
    out
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
pub fn generate(m: &Model) -> Result<String> {
    let circuit = m.circuit.as_str();
    let name = pascal(circuit);
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
         // schema, exactly as `xark prove --inputs` does.\n",
        sig.join(", ")
    );

    // Shared value types.
    out.push_str(FIELD);
    out.push_str(
        "/** Bytes: a `Uint8Array`, byte values, or a `0x`-hex string. */\n\
         export type Bytes = Uint8Array | readonly number[] | string;\n\n",
    );

    // Enums: the variants as constants (`Country.US`) and their type (`"AD" | …`), so
    // a value is checked, and either form passes.
    for (e, variants) in &m.enums {
        let _ = writeln!(
            out,
            "/** A `{e}` (an enum in the circuit): `{e}.{v}`, or its name, `{v:?}`. */\n\
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
        let _ = writeln!(
            out,
            "/** A `{r}` (an input struct). */\nexport interface {r} {{"
        );
        for f in fields {
            if let Some(n) = note(&f.ty) {
                let _ = writeln!(out, "  /** {n} */");
            }
            let _ = writeln!(out, "  {}: {};", ts_key(&f.name), input(&f.ty));
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
            let _ = writeln!(out, "  {}: {};", ts_key(&f.name), input(&f.ty));
        }
    };
    let _ = writeln!(
        out,
        "/** Every input of `{circuit}`. */\nexport interface {name}Inputs {{"
    );
    fields(&mut out, false);
    out.push_str("}\n\n");
    let _ = writeln!(
        out,
        "/** The public inputs: what a verifier supplies, and what a proof reveals. */\n\
         export interface {name}PublicInputs {{"
    );
    fields(&mut out, true);
    out.push_str("}\n\n");

    // The public inputs as decoded.
    let mut value_structs = BTreeSet::new();
    let mut body = String::new();
    let _ = writeln!(
        body,
        "/** The public inputs, decoded from a proof. */\nexport interface {name}PublicValues {{"
    );
    let mut decode = String::new();
    let _ = writeln!(
        decode,
        "function decodePublic(v: any): {name}PublicValues {{\n  return {{"
    );
    for f in m.public() {
        let k = ts_key(&f.name);
        let _ = writeln!(body, "  {k}: {};", value(&f.ty, &mut value_structs));
        let _ = writeln!(decode, "    {k}: {},", revive(&f.ty, &format!("v.{k}")));
    }
    body.push_str("}\n\n");
    decode.push_str("  };\n}\n\n");
    // The client functions (their decoders join the ones below).
    let exports = exports_ts(m, &mut value_structs);

    // Decoded structs (closed over what the public inputs and exports reach).
    let mut done = BTreeSet::new();
    let mut structs = String::new();
    while let Some(r) = value_structs.iter().find(|r| !done.contains(*r)).cloned() {
        done.insert(r.clone());
        let _ = writeln!(
            structs,
            "/** A `{r}`, decoded. */\nexport interface {r}Value {{"
        );
        let mut dec = format!("function decode{r}(v: any): {r}Value {{\n  return {{\n");
        for f in &m.structs[&r] {
            let k = ts_key(&f.name);
            let _ = writeln!(structs, "  {k}: {};", value(&f.ty, &mut value_structs));
            let _ = writeln!(dec, "    {k}: {},", revive(&f.ty, &format!("v.{k}")));
        }
        structs.push_str("}\n\n");
        dec.push_str("  };\n}\n\n");
        decode.push_str(&dec);
    }
    out.push_str(&structs);
    out.push_str(&body);

    // A value's field elements, per input struct (to hash one as the circuit does).
    let mut fields = String::new();
    if !m.structs.is_empty() {
        fields.push_str(
            "\n  /**\n   * A value's field elements in input order, as `to_fields()` gives them in\n   \
             * Rust: hash them as the circuit does (`wasm.poseidon2(fields.map(String))`).\n   \
             */\n",
        );
        for r in m.structs.keys() {
            let _ = writeln!(fields, "  fields(type: {r:?}, value: {r}): Field[];");
        }
        fields.push_str(
            "  fields(type: string, value: unknown): Field[] {\n    \
             return this.wasm.valueFields(__NAME__.schema, type, toJson(value)).map((f) => new Field(f));\n  }\n",
        );
    }

    // The class.
    let has = !m.exports.is_empty();
    let pick = |yes: &'static str| if has { yes } else { "" };
    out.push_str(
        &CLASS
            .replace("__FIELDS__", &fields)
            .replace("__CLIENT_KEY__", pick("\n  /** `client.wasm`: the Rust functions (`load` runs `initClient`). */\n  client?: Uint8Array;"))
            .replace("__CLIENT_FILE__", pick("\n  client: \"client.wasm\","))
            .replace("__CLIENT_PART__", pick(", \"client\""))
            .replace("__LOAD_DOC__", pick("\n   * `client.wasm` is loaded with `initClient`, for the Rust functions."))
            .replace("__LOAD_CLIENT__", pick("        if (part === \"client\") return initClient(await res.arrayBuffer());\n"))
            .replace("__NAME__", &name)
            .replace("__CIRCUIT__", circuit)
            .replace("__SCHEMA__", &format!("{:?}", m.schema)),
    );
    out.push_str(&exports);
    out.push_str(&decode);
    out.push_str(HELPERS);
    Ok(out)
}

const CLASS: &str = r#"/** The parts of `@blueshift-gg/xark-wasm` this client uses (any of its builds). */
export interface XarkWasm {
  prove(circuit: Uint8Array, provingKey: Uint8Array, inputs: Record<string, string>, sources?: string): { proof: Uint8Array; publicInputs: Uint8Array };
  verify(verifyingKey: Uint8Array, proof: Uint8Array, publicInputs: Uint8Array): boolean;
  encodeInputs(schema: string, inputs: string): Record<string, string>;
  encodePublicInputs(schema: string, publicInputs: string): Uint8Array;
  decodePublicValues(schema: string, publicInputs: Uint8Array): string;
  valueFields(schema: string, typeName: string, value: string): string[];
}

/** A proof, with its public inputs decoded and as the bytes `verify` takes. */
export interface __NAME__Proof {
  proof: Uint8Array;
  publicInputs: __NAME__PublicValues;
  publicInputBytes: Uint8Array;
}

/**
 * The build output a `__NAME__` works from (`target/xark/__CIRCUIT__/`): `circuit`
 * (circuit.xbc) and `provingKey` (pk.bin) to prove, `verifyingKey` (vk.bin) to
 * verify, and `sources` (sources.json, as text) so that inputs failing a check
 * name its source line.
 */
export interface __NAME__Keys {
  circuit?: Uint8Array;
  provingKey?: Uint8Array;
  verifyingKey?: Uint8Array;
  sources?: string;__CLIENT_KEY__
}

/** Each part of `__NAME__Keys` as `xark build` and `xark setup` name its file. */
const FILES = {
  circuit: "circuit.xbc",
  provingKey: "pk.bin",
  verifyingKey: "vk.bin",
  sources: "sources.json",__CLIENT_FILE__
} as const;

/**
 * Prove and verify `__CIRCUIT__` with the xark-wasm module you pass in:
 *
 * ```ts
 * import * as wasm from "@blueshift-gg/xark-wasm"; // node, web (after `await init()`), or bundler
 * const circuit = new __NAME__(wasm, { circuit: xbc, provingKey: pk, verifyingKey: vk, sources });
 * const { proof, publicInputs } = circuit.prove(inputs);
 * circuit.verify(proof, publicInputs); // true
 * ```
 */
export class __NAME__ {
  /** The circuit's `schema.json`. */
  static readonly schema = __SCHEMA__;

  constructor(
    private readonly wasm: XarkWasm,
    private readonly keys: __NAME__Keys,
  ) {}

  /**
   * Fetch the build output from `base`, a URL serving a copy of
   * `target/xark/__CIRCUIT__/` (relative to the page in a browser):
   * `await __NAME__.load(wasm, "/circuits/__CIRCUIT__/")`. `only` fetches less
   * (`["verifyingKey"]` for a verifier); a missing `sources.json` is skipped.__LOAD_DOC__
   */
  static async load(
    wasm: XarkWasm,
    base: string | URL,
    only: readonly (keyof __NAME__Keys)[] = ["circuit", "provingKey", "verifyingKey", "sources"__CLIENT_PART__],
    init?: RequestInit,
  ): Promise<__NAME__> {
    const page = (globalThis as { location?: { href: string } }).location?.href;
    if (!page && !URL.canParse(base)) {
      throw new Error(`load: ${base} is relative, and there's no page to resolve it against; pass an absolute URL`);
    }
    const root = new URL(base, page);
    if (!root.pathname.endsWith("/")) root.pathname += "/";
    const keys: Record<string, Uint8Array | string> = {};
    await Promise.all(
      only.map(async (part) => {
        const url = new URL(FILES[part], root);
        const res = await fetch(url, init);
        if (!res.ok) {
          if (part === "sources" && res.status === 404) return;
          throw new Error(`fetching ${url}: ${res.status} ${res.statusText}`);
        }
__LOAD_CLIENT__        keys[part] = part === "sources" ? await res.text() : new Uint8Array(await res.arrayBuffer());
      }),
    );
    return new __NAME__(wasm, keys as __NAME__Keys);
  }

  /**
   * Prove `inputs`. Throws if one is malformed (naming it), or if they fail a
   * check (naming its source line when `sources` was given).
   */
  prove(inputs: __NAME__Inputs): __NAME__Proof {
    const { circuit, provingKey, sources } = this.keys;
    if (!circuit || !provingKey) throw new Error("proving needs `circuit` (circuit.xbc) and `provingKey` (pk.bin)");
    const leaves = this.wasm.encodeInputs(__NAME__.schema, toJson(inputs));
    const { proof, publicInputs } = this.wasm.prove(circuit, provingKey, leaves, sources);
    return { proof: proof.slice(), publicInputs: this.decodePublicInputs(publicInputs), publicInputBytes: publicInputs.slice() };
  }

  /** Whether `proof` proves these public inputs. */
  verify(proof: Uint8Array, publicInputs: __NAME__PublicInputs | __NAME__PublicValues | Uint8Array): boolean {
    const { verifyingKey } = this.keys;
    if (!verifyingKey) throw new Error("verifying needs `verifyingKey` (vk.bin)");
    const bytes = publicInputs instanceof Uint8Array ? publicInputs : this.encodePublicInputs(publicInputs);
    try {
      return this.wasm.verify(verifyingKey, proof, bytes);
    } catch {
      return false; // malformed proof bytes
    }
  }

  /** The public inputs as the canonical bytes (`public_inputs.bin`). */
  encodePublicInputs(publicInputs: __NAME__PublicInputs | __NAME__PublicValues): Uint8Array {
    return this.wasm.encodePublicInputs(__NAME__.schema, toJson(publicInputs));
  }

  /** Canonical public-input bytes, decoded. */
  decodePublicInputs(bytes: Uint8Array): __NAME__PublicValues {
    return decodePublic(JSON.parse(this.wasm.decodePublicValues(__NAME__.schema, bytes)));
  }
__FIELDS__}

"#;

const CLIENT: &str = r#"// The Rust functions (`#[input]` on an `impl`, here or in a dependency), compiled to `client.wasm`.
let rust: { module: WebAssembly.Module; instance: WebAssembly.Instance } | undefined;

/**
 * Load `client.wasm` (`xark client` writes it beside `circuit.xbc`; `load` fetches
 * it): the circuit's Rust functions. Once, before calling them.
 */
export async function initClient(wasm: BufferSource | WebAssembly.Module): Promise<void> {
  const module = wasm instanceof WebAssembly.Module ? wasm : await WebAssembly.compile(wasm);
  rust = { module, instance: await WebAssembly.instantiate(module, {}) };
}

/** Call an exported Rust function with JSON arguments; its result, as JSON. */
function callRust(name: string, args: unknown[]): any {
  if (!rust) throw new Error("call `initClient(client.wasm)` before the circuit's Rust functions");
  const x = rust.instance.exports as any;
  const input = new TextEncoder().encode(toJson(args));
  const ptr = x.xark_alloc(input.length);
  new Uint8Array(x.memory.buffer, ptr, input.length).set(input);
  let packed: bigint;
  try {
    packed = x[name](ptr, input.length);
  } catch (e) {
    const message = take(x, x.xark_panic());
    rust.instance = new WebAssembly.Instance(rust.module, {}); // a panic may leave the heap mid-update
    throw new Error(message || String(e));
  }
  x.xark_free(ptr, input.length);
  const out = JSON.parse(take(x, packed));
  if ("err" in out) throw new Error(out.err);
  return out.ok;
}

/** The string a Rust function handed over (`ptr << 32 | len`), freed. */
function take(x: any, packed: bigint): string {
  const ptr = Number(packed >> 32n);
  const len = Number(packed & 0xffffffffn);
  const s = new TextDecoder().decode(new Uint8Array(x.memory.buffer, ptr, len));
  x.xark_free(ptr, len);
  return s;
}

"#;

/// The field element type every client shares. Structural, so a `Field` from one
/// generated client passes to another.
const FIELD: &str = r#"/**
 * A BN254 field element, checked when it's made: `new Field(x)` takes a `bigint`,
 * a safe integer, a decimal or `0x`-hex string, big-endian bytes (a `Uint8Array`
 * of at most 32), or another `Field`, and throws unless it's an integer in [0, p).
 */
export class Field {
  /** The field's modulus, p (BN254's scalar field). */
  static readonly MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  /** The element, in [0, p). */
  readonly value: bigint;

  constructor(x: Field | bigint | number | string | Uint8Array) {
    const v = fieldValue(x);
    if (v < 0n) throw new RangeError(`Field: ${v} is negative`);
    if (v >= Field.MODULUS) throw new RangeError(`Field: ${v} is not below the field's modulus`);
    this.value = v;
  }

  /** Whether `other` is the same element. */
  equals(other: Field | bigint | number | string | Uint8Array): boolean {
    return this.value === new Field(other).value;
  }

  /** The element as 32 big-endian bytes. */
  toBytes(): Uint8Array {
    const out = new Uint8Array(32);
    for (let i = 31, v = this.value; i >= 0; i--, v >>= 8n) out[i] = Number(v & 0xffn);
    return out;
  }

  /** Decimal. */
  toString(): string {
    return this.value.toString();
  }

  toJSON(): string {
    return this.value.toString();
  }
}

function fieldValue(x: unknown): bigint {
  if (typeof x === "bigint") return x;
  if (typeof x === "number") {
    if (!Number.isSafeInteger(x)) throw new RangeError(`Field: ${x} is not a safe integer (pass a bigint)`);
    return BigInt(x);
  }
  if (typeof x === "string") {
    const s = x.trim();
    if (!/^(\d+|0x[0-9a-fA-F]+)$/.test(s)) throw new SyntaxError(`Field: ${JSON.stringify(x)} is not a decimal or 0x-hex integer`);
    return BigInt(s);
  }
  if (x instanceof Uint8Array) {
    if (x.length > 32) throw new RangeError(`Field: ${x.length} bytes; at most 32`);
    return x.reduce((v, b) => (v << 8n) | BigInt(b), 0n);
  }
  // A `Field`, from this client or another.
  if (typeof x === "object" && x !== null && typeof (x as { value?: unknown }).value === "bigint") {
    return (x as { value: bigint }).value;
  }
  throw new TypeError(`Field: can't make a field element from ${typeof x}`);
}

"#;

const HELPERS: &str = r#"/** JSON for xark-wasm: `bigint`s and `Field`s as decimal, a `Date` as its UTC day (`YYYY-MM-DD`), bytes as hex. */
function toJson(value: unknown): string {
  return JSON.stringify(value, function (this: any, key: string, v: unknown) {
    const raw = this[key];
    if (raw instanceof Date) {
      if (Number.isNaN(raw.getTime())) throw new TypeError(`${key}: invalid Date`);
      return raw.toISOString().slice(0, 10);
    }
    if (typeof raw === "bigint") return raw.toString();
    if (raw instanceof Uint8Array) return "0x" + Array.from(raw, (b) => b.toString(16).padStart(2, "0")).join("");
    if (raw instanceof Set) return [...raw];
    return v;
  });
}

function fromHex(s: string): Uint8Array {
  const h = s.slice(2);
  return Uint8Array.from({ length: h.length / 2 }, (_, i) => parseInt(h.slice(2 * i, 2 * i + 2), 16));
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = r#"{
      "version": 2,
      "circuit": "kyc_check",
      "inputs": [
        {"name": "id", "visibility": "private", "type": {"ref": "Identity"}},
        {"name": "born_before", "visibility": "public", "type": {"ref": "Date"}},
        {"name": "allowed", "visibility": "public", "type": {"ref": "Bitfield<Country>"}},
        {"name": "doc", "visibility": "private", "type": {"array": {"of": {"uint": 8}, "len": 4}}},
        {"name": "commitment", "visibility": "public", "type": "field"}
      ],
      "types": {
        "Identity": {"struct": [
          {"name": "net_worth", "type": {"uint": 64}},
          {"name": "salt", "type": "field"},
          {"name": "active", "type": "bool"},
          {"name": "home", "type": {"ref": "Choice<Country>"}},
          {"name": "tier", "type": {"ref": "Choice<Tier>"}},
          {"name": "pair", "type": {"tuple": ["field", {"uint": 16}]}}]},
        "Date": {"newtype": "field", "encoding": {"date": "yyyymmdd"}},
        "Bitfield<Country>": {"newtype": "field", "encoding": {"set": "Country"}},
        "Choice<Country>": {"newtype": "field", "encoding": {"choice": "Country"}},
        "Choice<Tier>": {"newtype": "field", "encoding": {"choice": "Tier"}},
        "Country": {"enum": ["AD", "US"]},
        "Tier": {"enum": ["Retail", "Not_Set"]}
      },
      "public_inputs": ["born_before", "allowed", "commitment"]
    }"#;

    #[test]
    fn names() {
        assert_eq!(pascal("zkyc_circuit"), "ZkycCircuit");
        assert_eq!(ts_key("net_worth"), "netWorth");
        assert_eq!(ts_key("0"), "\"0\"");
    }

    #[test]
    fn generates_natural_types() {
        let m = Model::new(&serde_json::from_str(SCHEMA).unwrap()).unwrap();
        let ts = generate(&m).unwrap();
        for want in [
            "fn kyc_check(id: Private<Identity>, born_before: Public<Date>, allowed: Public<Bitfield<Country>>, doc: Private<[u8; 4]>, commitment: Public<Field>)",
            "export const Country = {\n  AD: \"AD\", US: \"US\",\n} as const;\nexport type Country = (typeof Country)[keyof typeof Country];",
            "export interface Identity {\n  /** `u64`: an integer in [0, 2^64). */\n  netWorth: bigint | number;",
            "  /** One `Country`. */\n  home: Country;",
            "  Retail: \"Retail\", Not_Set: \"Not_Set\",",
            "  pair: readonly [Field, number];",
            "  active: boolean;",
            "  bornBefore: Date;",
            "  allowed: Country | readonly Country[];",
            "  doc: Bytes;",
            "export interface KycCheckPublicValues {\n  bornBefore: Date;\n  allowed: Country[];\n  commitment: Field;\n}",
            "    bornBefore: new Date(v.bornBefore),",
            "    commitment: new Field(v.commitment),",
            "export class KycCheck {",
            "  fields(type: \"Identity\", value: Identity): Field[];",
            "static async load(",
        ] {
            assert!(ts.contains(want), "missing {want:?} in:\n{ts}");
        }
        assert!(ts.starts_with("// Generated by `xark client`"));
        assert!(!ts.contains("__NAME__") && !ts.contains("__SCHEMA__"));
    }
}
