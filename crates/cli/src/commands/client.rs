//! `xark client` — generate a typed TypeScript client from `schema.json`.
//!
//! `xark build` writes `target/xark/<name>/schema.json` (the circuit's inputs, read from
//! the compiler's own view of their types), so a client can be generated straight from
//! build output: no `xark setup`, no proof. The output is one self-contained `.ts` file:
//!
//! * an interface per `#[derive(CircuitInput)]` struct, one for all inputs, and one for
//!   the public inputs (fields camelCased; the schema maps them back to leaf names);
//! * `witness(inputs)`: the flat `leaf → value` map `xark prove --inputs` and the wasm
//!   prover take, with every integer range- and array length-checked first;
//! * public-input encode/decode to and from the canonical bytes `verify` takes;
//! * a class wrapping the `xark-wasm` module with typed `prove` / `verify`.
//!
//! The wasm module is passed in rather than imported, so the same file works with the
//! Node, web, and bundler builds.

use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use serde_json::Value;

use crate::xark_project::XarkProject;

#[derive(Args, Debug)]
pub struct ClientArgs {
    /// Circuit crate directory (or its `target/xark/` output dir). Defaults to the
    /// current directory.
    #[arg(value_hint = clap::ValueHint::DirPath)]
    pub path: Option<PathBuf>,
    /// Client language.
    #[arg(long, value_enum, default_value_t = Lang::Ts)]
    pub lang: Lang,
    /// Output file. Defaults to `target/xark/<name>/<circuit>.ts`.
    #[arg(long, short, value_hint = clap::ValueHint::FilePath)]
    pub out: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum Lang {
    /// TypeScript.
    Ts,
}

pub fn run(args: ClientArgs) -> Result<()> {
    let project = XarkProject::resolve(args.path.clone())?;
    let schema_path = project.xark_dir.join("schema.json");
    let text = std::fs::read_to_string(&schema_path).map_err(|_| {
        anyhow::anyhow!(
            "no schema at {} — run `xark build {}` first (no setup or proof needed)",
            schema_path.display(),
            super::path_arg(&args.path)
        )
    })?;
    let schema =
        Schema::parse(&text).with_context(|| format!("reading {}", schema_path.display()))?;
    let Lang::Ts = args.lang;
    let out = args
        .out
        .unwrap_or_else(|| project.xark_dir.join(format!("{}.ts", schema.circuit)));
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(&out, typescript(&schema, &text))
        .with_context(|| format!("writing {}", out.display()))?;
    println!(
        "{}",
        crate::style::brand(&format!(
            "✅ TypeScript client for `{}` at {}",
            schema.circuit,
            out.display()
        ))
    );
    Ok(())
}

/// A schema type (see `input_schema` in the compiler).
#[derive(Clone, Debug, PartialEq)]
pub enum Ty {
    Field,
    Uint(u32),
    Array(Box<Ty>, usize),
    Tuple(Vec<Ty>),
    Ref(String),
}

#[derive(Debug)]
pub struct Input {
    pub name: String,
    pub public: bool,
    pub ty: Ty,
}

#[derive(Debug)]
pub struct Schema {
    pub circuit: String,
    pub inputs: Vec<Input>,
    /// Struct name → fields, in declaration order.
    pub types: Vec<(String, Vec<(String, Ty)>)>,
}

impl Schema {
    pub fn parse(text: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(text)?;
        if v["version"].as_u64() != Some(1) {
            bail!("unsupported schema version {} (expected 1)", v["version"]);
        }
        let circuit = v["circuit"]
            .as_str()
            .context("missing `circuit`")?
            .to_string();
        let inputs = v["inputs"]
            .as_array()
            .context("missing `inputs`")?
            .iter()
            .map(|i| {
                Ok(Input {
                    name: i["name"]
                        .as_str()
                        .context("input without a name")?
                        .to_string(),
                    public: i["visibility"] == "public",
                    ty: parse_ty(&i["type"])?,
                })
            })
            .collect::<Result<_>>()?;
        let types = v["types"]
            .as_object()
            .context("missing `types`")?
            .iter()
            .map(|(name, def)| {
                let fields = def["struct"]
                    .as_array()
                    .with_context(|| format!("type `{name}` is not a struct"))?
                    .iter()
                    .map(|f| {
                        Ok((
                            f["name"]
                                .as_str()
                                .context("field without a name")?
                                .to_string(),
                            parse_ty(&f["type"])?,
                        ))
                    })
                    .collect::<Result<_>>()?;
                Ok((name.clone(), fields))
            })
            .collect::<Result<_>>()?;
        Ok(Schema {
            circuit,
            inputs,
            types,
        })
    }
}

fn parse_ty(v: &Value) -> Result<Ty> {
    if v == "field" {
        return Ok(Ty::Field);
    }
    if let Some(w) = v["uint"].as_u64() {
        return Ok(Ty::Uint(w as u32));
    }
    if let Some(a) = v.get("array") {
        let len = a["len"].as_u64().context("array without `len`")? as usize;
        return Ok(Ty::Array(Box::new(parse_ty(&a["of"])?), len));
    }
    if let Some(t) = v["tuple"].as_array() {
        return Ok(Ty::Tuple(t.iter().map(parse_ty).collect::<Result<_>>()?));
    }
    if let Some(r) = v["ref"].as_str() {
        return Ok(Ty::Ref(r.to_string()));
    }
    bail!("unknown schema type {v}")
}

/// `born_before` → `bornBefore` (a leading/trailing `_` is kept).
pub fn camel(s: &str) -> String {
    let mut out = String::new();
    let mut up = false;
    for (i, c) in s.chars().enumerate() {
        if c == '_' && i > 0 && i + 1 < s.len() {
            up = true;
        } else if up {
            out.extend(c.to_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

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
    let ident = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$');
    if ident {
        name.to_string()
    } else {
        format!("{name:?}")
    }
}

/// The TS type a caller supplies for `ty`.
fn ts_type(ty: &Ty) -> String {
    match ty {
        Ty::Field => "FieldLike".into(),
        Ty::Uint(w) if *w <= 32 => "number".into(),
        Ty::Uint(_) => "bigint | number".into(),
        Ty::Array(of, _) if **of == Ty::Uint(8) => "Uint8Array | readonly number[]".into(),
        Ty::Array(of, _) => {
            let t = ts_type(of);
            if t.contains(' ') {
                format!("readonly ({t})[]")
            } else {
                format!("readonly {t}[]")
            }
        }
        Ty::Tuple(ts) => format!(
            "readonly [{}]",
            ts.iter().map(ts_type).collect::<Vec<_>>().join(", ")
        ),
        Ty::Ref(name) => name.clone(),
    }
}

/// A doc comment for a field whose TS type can't say everything (widths, lengths).
fn ts_doc(ty: &Ty) -> Option<String> {
    match ty {
        Ty::Uint(w) => Some(format!("`u{w}`: an integer in [0, 2^{w}).")),
        Ty::Array(of, n) if **of == Ty::Uint(8) => Some(format!("`[u8; {n}]`: exactly {n} bytes.")),
        Ty::Array(_, n) => Some(format!("Exactly {n} elements.")),
        _ => None,
    }
}

fn interface(out: &mut String, doc: &str, name: &str, fields: &[(String, &Ty)]) {
    let _ = writeln!(out, "/** {doc} */");
    let _ = writeln!(out, "export interface {name} {{");
    for (f, ty) in fields {
        if let Some(d) = ts_doc(ty) {
            let _ = writeln!(out, "  /** {d} */");
        }
        let _ = writeln!(out, "  {}: {};", ts_key(&camel(f)), ts_type(ty));
    }
    let _ = writeln!(out, "}}\n");
}

/// The generated TypeScript module for `schema` (`schema_text` is embedded verbatim).
pub fn typescript(schema: &Schema, schema_text: &str) -> String {
    let name = pascal(&schema.circuit);
    let n_pub = schema.inputs.iter().filter(|i| i.public).count();
    let n_priv = schema.inputs.len() - n_pub;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "// Generated by `xark client` from schema.json. Do not edit; regenerate after\n\
         // `xark build`. Circuit `{}`: {n_priv} private and {n_pub} public input(s).\n",
        schema.circuit
    );
    out.push_str(RUNTIME_TYPES);
    for (ty_name, fields) in &schema.types {
        let fs: Vec<(String, &Ty)> = fields.iter().map(|(f, t)| (f.clone(), t)).collect();
        interface(
            &mut out,
            &format!("`{ty_name}` (a circuit input struct)."),
            ty_name,
            &fs,
        );
    }
    let all: Vec<(String, &Ty)> = schema
        .inputs
        .iter()
        .map(|i| (i.name.clone(), &i.ty))
        .collect();
    interface(
        &mut out,
        "Every input the prover supplies.",
        &format!("{name}Inputs"),
        &all,
    );
    let public: Vec<(String, &Ty)> = schema
        .inputs
        .iter()
        .filter(|i| i.public)
        .map(|i| (i.name.clone(), &i.ty))
        .collect();
    interface(
        &mut out,
        "The public inputs: what a verifier supplies, and what a proof reveals.",
        &format!("{name}PublicInputs"),
        &public,
    );
    let _ = writeln!(
        out,
        "/** The circuit's `schema.json`, as written by `xark build`. */\n\
         export const {}_SCHEMA: Schema = {};\n",
        schema.circuit.to_uppercase(),
        schema_text.trim()
    );
    out.push_str(RUNTIME);
    let _ = write!(
        out,
        "{}",
        CLASS
            .replace("__NAME__", &name)
            .replace(
                "__SCHEMA__",
                &format!("{}_SCHEMA", schema.circuit.to_uppercase())
            )
            .replace("__CIRCUIT__", &schema.circuit)
    );
    out
}

const RUNTIME_TYPES: &str = r#"/** A BN254 field element: a bigint, a safe-integer number, or a decimal / 0x-hex string. */
export type FieldLike = bigint | number | string;

"#;

/// Schema-driven helpers shared by every generated client. Kept in the generated file
/// (not a package) so the output has no dependencies beyond the wasm module you pass in.
const RUNTIME: &str = r#"// ---- runtime (schema-driven; identical in every generated client) ----

export type SchemaType =
  | "field"
  | { uint: number }
  | { array: { of: SchemaType; len: number } }
  | { tuple: SchemaType[] }
  | { ref: string };

export interface Schema {
  version: number;
  circuit: string;
  inputs: { name: string; visibility: "public" | "private"; type: SchemaType }[];
  types: Record<string, { struct: { name: string; type: SchemaType }[] }>;
  public_inputs: string[];
}

/** The subset of the `xark-wasm` module these clients use (any build target). */
export interface XarkWasm {
  prove(
    circuitXbc: Uint8Array,
    provingKey: Uint8Array,
    inputs: Record<string, string>,
  ): { proof: Uint8Array; publicInputs: Uint8Array };
  verify(verifyingKey: Uint8Array, proof: Uint8Array, publicInputs: Uint8Array): boolean;
}

/** BN254 scalar field modulus. */
export const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const camel = (s: string): string =>
  s.replace(/(?!^)_([a-z0-9])(?!$)/g, (_, c: string) => c.toUpperCase());

function fieldValue(v: unknown, at: string): bigint {
  let x: bigint;
  if (typeof v === "bigint") x = v;
  else if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new RangeError(`${at}: ${v} is not a safe integer; pass a bigint or string`);
    x = BigInt(v);
  } else if (typeof v === "string") {
    try {
      x = BigInt(v.trim());
    } catch {
      throw new TypeError(`${at}: ${JSON.stringify(v)} is not a decimal or 0x-hex number`);
    }
  } else throw new TypeError(`${at}: expected a number, bigint, or string`);
  return ((x % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS;
}

/** Flatten `value` of type `ty` into `out` under the compiler's leaf names. */
function flatten(schema: Schema, ty: SchemaType, value: unknown, leaf: string, at: string, out: Record<string, string>): void {
  if (ty === "field") {
    out[leaf] = fieldValue(value, at).toString();
  } else if ("uint" in ty) {
    if (typeof value === "string" || typeof value === "object") throw new TypeError(`${at}: expected an integer`);
    const x = fieldValue(value, at);
    if (typeof value === "bigint" ? value < 0n : (value as number) < 0 || x >= 1n << BigInt(ty.uint))
      throw new RangeError(`${at}: ${String(value)} is outside u${ty.uint}`);
    out[leaf] = x.toString();
  } else if ("array" in ty) {
    const xs = value as ArrayLike<unknown>;
    if (xs == null || typeof xs.length !== "number") throw new TypeError(`${at}: expected an array`);
    if (xs.length !== ty.array.len) throw new RangeError(`${at}: expected ${ty.array.len} elements, got ${xs.length}`);
    for (let i = 0; i < xs.length; i++) flatten(schema, ty.array.of, xs[i], `${leaf}[${i}]`, `${at}[${i}]`, out);
  } else if ("tuple" in ty) {
    const xs = value as readonly unknown[];
    if (!Array.isArray(xs) || xs.length !== ty.tuple.length) throw new TypeError(`${at}: expected a ${ty.tuple.length}-tuple`);
    ty.tuple.forEach((t, i) => flatten(schema, t, xs[i], `${leaf}.${i}`, `${at}[${i}]`, out));
  } else {
    const def = schema.types[ty.ref];
    if (typeof value !== "object" || value === null) throw new TypeError(`${at}: expected a ${ty.ref} object`);
    const obj = value as Record<string, unknown>;
    for (const f of def.struct) {
      const key = camel(f.name);
      if (!(key in obj)) throw new TypeError(`${at}: missing \`${key}\``);
      flatten(schema, f.type, obj[key], `${leaf}.${f.name}`, `${at}.${key}`, out);
    }
  }
}

/** Rebuild a value of type `ty` from leaf values in flatten order. */
function unflatten(schema: Schema, ty: SchemaType, xs: bigint[], pos: { i: number }): unknown {
  if (ty === "field") return xs[pos.i++];
  if ("uint" in ty) {
    const x = xs[pos.i++];
    return ty.uint <= 32 ? Number(x) : x;
  }
  if ("array" in ty) {
    const items = Array.from({ length: ty.array.len }, () => unflatten(schema, ty.array.of, xs, pos));
    const of = ty.array.of;
    return typeof of === "object" && "uint" in of && of.uint === 8 ? Uint8Array.from(items as number[]) : items;
  }
  if ("tuple" in ty) return ty.tuple.map((t) => unflatten(schema, t, xs, pos));
  const obj: Record<string, unknown> = {};
  for (const f of schema.types[ty.ref].struct) obj[camel(f.name)] = unflatten(schema, f.type, xs, pos);
  return obj;
}

/** The flat `leaf → value` witness map for the given inputs (all of them, or only public). */
export function flattenInputs(schema: Schema, inputs: object, publicOnly = false): Record<string, string> {
  const out: Record<string, string> = {};
  const obj = inputs as Record<string, unknown>;
  for (const input of schema.inputs) {
    if (publicOnly && input.visibility !== "public") continue;
    const key = camel(input.name);
    if (!(key in obj)) throw new TypeError(`missing input \`${key}\``);
    flatten(schema, input.type, obj[key], input.name, key, out);
  }
  return out;
}

/** Public inputs → canonical compressed bytes (`public_inputs.bin`): u64 LE count, then 32-byte LE scalars. */
export function encodePublicInputs(schema: Schema, publicInputs: object): Uint8Array {
  const flat = flattenInputs(schema, publicInputs, true);
  const values = schema.public_inputs.map((leaf) => BigInt(flat[leaf]));
  const out = new Uint8Array(8 + 32 * values.length);
  new DataView(out.buffer).setBigUint64(0, BigInt(values.length), true);
  values.forEach((v, i) => {
    for (let b = 0; b < 32; b++) out[8 + 32 * i + b] = Number((v >> BigInt(8 * b)) & 0xffn);
  });
  return out;
}

/** Canonical public-input bytes → typed public inputs. */
export function decodePublicInputs(schema: Schema, bytes: Uint8Array): Record<string, unknown> {
  const n = Number(new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, true));
  if (n !== schema.public_inputs.length || bytes.length !== 8 + 32 * n)
    throw new RangeError(`expected ${schema.public_inputs.length} public inputs, got ${n}`);
  const xs = Array.from({ length: n }, (_, i) => {
    let v = 0n;
    for (let b = 31; b >= 0; b--) v = (v << 8n) | BigInt(bytes[8 + 32 * i + b]);
    return v;
  });
  const pos = { i: 0 };
  const out: Record<string, unknown> = {};
  for (const input of schema.inputs)
    if (input.visibility === "public") out[camel(input.name)] = unflatten(schema, input.type, xs, pos);
  return out;
}

"#;

const CLASS: &str = r#"// ---- `__CIRCUIT__` client ----

/** A proof with its public inputs, decoded and as the canonical bytes `verify` takes. */
export interface __NAME__Proof {
  proof: Uint8Array;
  publicInputs: __NAME__PublicInputs;
  publicInputBytes: Uint8Array;
}

/**
 * Typed prover/verifier for `__CIRCUIT__`, over the `xark-wasm` module you pass in:
 *
 * ```ts
 * import * as wasm from "xark-wasm"; // node, web (after `await init()`), or bundler build
 * const circuit = new __NAME__(wasm, { circuit: xbc, provingKey: pk, verifyingKey: vk });
 * const { proof, publicInputs } = circuit.prove(inputs);
 * circuit.verify(proof, publicInputs); // true
 * ```
 */
export class __NAME__ {
  static readonly schema: Schema = __SCHEMA__;

  constructor(
    private readonly wasm: XarkWasm,
    private readonly keys: { circuit?: Uint8Array; provingKey?: Uint8Array; verifyingKey?: Uint8Array },
  ) {}

  /** The flat witness map (`leaf → decimal`) for `xark prove --inputs` or the wasm prover. */
  static witness(inputs: __NAME__Inputs): Record<string, string> {
    return flattenInputs(__SCHEMA__, inputs);
  }

  static encodePublicInputs(publicInputs: __NAME__PublicInputs): Uint8Array {
    return encodePublicInputs(__SCHEMA__, publicInputs);
  }

  static decodePublicInputs(bytes: Uint8Array): __NAME__PublicInputs {
    return decodePublicInputs(__SCHEMA__, bytes) as unknown as __NAME__PublicInputs;
  }

  prove(inputs: __NAME__Inputs): __NAME__Proof {
    const { circuit, provingKey } = this.keys;
    if (!circuit || !provingKey) throw new Error("proving needs `circuit` (circuit.xbc) and `provingKey` (pk.bin)");
    const bundle = this.wasm.prove(circuit, provingKey, __NAME__.witness(inputs));
    const publicInputBytes = bundle.publicInputs.slice();
    return {
      proof: bundle.proof.slice(),
      publicInputs: __NAME__.decodePublicInputs(publicInputBytes),
      publicInputBytes,
    };
  }

  verify(proof: Uint8Array, publicInputs: __NAME__PublicInputs | Uint8Array): boolean {
    const { verifyingKey } = this.keys;
    if (!verifyingKey) throw new Error("verifying needs `verifyingKey` (vk.bin)");
    const bytes = publicInputs instanceof Uint8Array ? publicInputs : __NAME__.encodePublicInputs(publicInputs);
    try {
      return this.wasm.verify(verifyingKey, proof, bytes);
    } catch {
      return false; // malformed proof bytes
    }
  }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = r#"{
      "version": 1,
      "circuit": "kyc_check",
      "inputs": [
        {"name": "id", "visibility": "private", "type": {"ref": "Identity"}},
        {"name": "min_age", "visibility": "public", "type": {"uint": 8}},
        {"name": "doc", "visibility": "private", "type": {"array": {"of": {"uint": 8}, "len": 4}}},
        {"name": "commitment", "visibility": "public", "type": "field"}
      ],
      "types": {"Identity": {"struct": [
        {"name": "net_worth", "type": {"uint": 64}},
        {"name": "salt", "type": "field"},
        {"name": "pair", "type": {"tuple": ["field", {"uint": 16}]}}
      ]}},
      "public_inputs": ["min_age", "commitment"]
    }"#;

    #[test]
    fn names() {
        assert_eq!(camel("born_before"), "bornBefore");
        assert_eq!(camel("id"), "id");
        assert_eq!(pascal("zkyc_circuit"), "ZkycCircuit");
    }

    #[test]
    fn generates_typed_interfaces() {
        let s = Schema::parse(SCHEMA).unwrap();
        let ts = typescript(&s, SCHEMA);
        for want in [
            "export interface Identity {",
            "  netWorth: bigint | number;",
            "  salt: FieldLike;",
            "  pair: readonly [FieldLike, number];",
            "export interface KycCheckInputs {",
            "  id: Identity;",
            "  minAge: number;",
            "  doc: Uint8Array | readonly number[];",
            "export interface KycCheckPublicInputs {\n  /** `u8`: an integer in [0, 2^8). */\n  minAge: number;\n  commitment: FieldLike;\n}",
            "export const KYC_CHECK_SCHEMA: Schema = {",
            "export class KycCheck {",
        ] {
            assert!(ts.contains(want), "missing {want:?} in:\n{ts}");
        }
        assert!(!ts.contains("__NAME__") && !ts.contains("__SCHEMA__"));
    }

    #[test]
    fn rejects_unknown_versions() {
        assert!(Schema::parse(&SCHEMA.replace("\"version\": 1", "\"version\": 2")).is_err());
    }
}
