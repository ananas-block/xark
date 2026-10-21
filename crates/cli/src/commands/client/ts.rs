//! The TypeScript target: one `.ts` file over the xark-wasm module you pass in.
//!
//! * a string union per enum (`type Country = "AD" | …`);
//! * an interface per input struct, every value in its natural TypeScript form;
//! * the inputs, the public inputs as given, and as decoded from a proof;
//! * a class with `prove`, `verify`, the public-input encode/decode, `load` (the
//!   build output from a URL) and `fields` (a value's field elements, to hash it).
//!
//! | standard type          | as given                      | decoded       |
//! |------------------------|-------------------------------|---------------|
//! | field                  | `bigint \| number \| string`  | `bigint`      |
//! | `uN`                   | `number` (`bigint` past 32)   | `number`/`bigint` |
//! | bool                   | `boolean`                     | `boolean`     |
//! | bytes                  | `Uint8Array`, numbers, `0x…`  | `Uint8Array`  |
//! | number (limbed)        | a field-like value, or bytes  | `bigint`      |
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

/// A TS property key: bare when it's an identifier, quoted otherwise (tuple-struct `0`).
fn ts_key(name: &str) -> String {
    let c = camel(name);
    let ident = c
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && c.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$');
    if ident { c } else { format!("{c:?}") }
}

/// The TS type a caller passes for `ty`.
fn input(ty: &Ty) -> String {
    match ty {
        Ty::Field => "FieldLike".into(),
        Ty::Uint(w) if *w <= 32 => "number".into(),
        Ty::Uint(_) => "bigint | number".into(),
        Ty::Bool => "boolean".into(),
        Ty::Bytes { .. } => "Bytes".into(),
        Ty::Number { .. } => "FieldLike | Uint8Array".into(),
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
        Ty::Field | Ty::Number { .. } => "bigint".into(),
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
        Ty::Field | Ty::Number { .. } => format!("BigInt({e})"),
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
    out.push_str(
        "/** A field element: a `bigint`, a safe integer, or a decimal / `0x`-hex string. */\n\
         export type FieldLike = bigint | number | string;\n\
         /** Bytes: a `Uint8Array`, byte values, or a `0x`-hex string. */\n\
         export type Bytes = Uint8Array | readonly number[] | string;\n\n",
    );

    // Enums.
    for (e, variants) in &m.enums {
        let names: Vec<String> = variants.iter().map(|s| format!("{s:?}")).collect();
        let _ = writeln!(
            out,
            "/** A `{e}` (an enum in the circuit), its variants in order. */\nexport type {e} ="
        );
        for chunk in names.chunks(12) {
            let _ = writeln!(out, "  | {}", chunk.join(" | "));
        }
        out.pop();
        out.push_str(";\n\n");
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
    // Decoded structs (closed over what the public inputs reach).
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
            let _ = writeln!(fields, "  fields(type: {r:?}, value: {r}): bigint[];");
        }
        fields.push_str(
            "  fields(type: string, value: unknown): bigint[] {\n    \
             return this.wasm.valueFields(__NAME__.schema, type, toJson(value)).map(BigInt);\n  }\n",
        );
    }

    // The class.
    out.push_str(
        &CLASS
            .replace("__FIELDS__", &fields)
            .replace("__NAME__", &name)
            .replace("__CIRCUIT__", circuit)
            .replace("__SCHEMA__", &format!("{:?}", m.schema)),
    );
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
  sources?: string;
}

/** Each part of `__NAME__Keys` as `xark build` and `xark setup` name its file. */
const FILES = {
  circuit: "circuit.xbc",
  provingKey: "pk.bin",
  verifyingKey: "vk.bin",
  sources: "sources.json",
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
   * (`["verifyingKey"]` for a verifier); a missing `sources.json` is skipped.
   */
  static async load(
    wasm: XarkWasm,
    base: string | URL,
    only: readonly (keyof __NAME__Keys)[] = ["circuit", "provingKey", "verifyingKey", "sources"],
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
        keys[part] = part === "sources" ? await res.text() : new Uint8Array(await res.arrayBuffer());
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

const HELPERS: &str = r#"/** JSON for xark-wasm: `bigint`s as decimal, a `Date` as its UTC day (`YYYY-MM-DD`), bytes as hex. */
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
          {"name": "pair", "type": {"tuple": ["field", {"uint": 16}]}}]},
        "Date": {"newtype": "field", "encoding": {"date": "yyyymmdd"}},
        "Bitfield<Country>": {"newtype": "field", "encoding": {"set": "Country"}},
        "Choice<Country>": {"newtype": "field", "encoding": {"choice": "Country"}},
        "Country": {"enum": ["AD", "US"]}
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
            "export type Country =\n  | \"AD\" | \"US\";",
            "export interface Identity {\n  /** `u64`: an integer in [0, 2^64). */\n  netWorth: bigint | number;",
            "  /** One `Country`. */\n  home: Country;",
            "  pair: readonly [FieldLike, number];",
            "  active: boolean;",
            "  bornBefore: Date;",
            "  allowed: Country | readonly Country[];",
            "  doc: Bytes;",
            "export interface KycCheckPublicValues {\n  bornBefore: Date;\n  allowed: Country[];\n  commitment: bigint;\n}",
            "    bornBefore: new Date(v.bornBefore),",
            "    commitment: BigInt(v.commitment),",
            "export class KycCheck {",
            "  fields(type: \"Identity\", value: Identity): bigint[];",
            "static async load(",
        ] {
            assert!(ts.contains(want), "missing {want:?} in:\n{ts}");
        }
        assert!(ts.starts_with("// Generated by `xark client`"));
        assert!(!ts.contains("__NAME__") && !ts.contains("__SCHEMA__"));
    }
}
