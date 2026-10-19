//! Turning user-supplied input values into the solver's `VarId → decimal` map.
//!
//! One resolver shared by `xark prove` / `xark check --inputs` and the wasm prover, so
//! the same inputs work everywhere. Values may be given per leaf (`id.dob`, `msg[3]`),
//! as a **logical input** that fans out to its leaves (a `0x`-hex byte string for
//! `[u8; N]`, a 32-byte hash, a 256-bit non-native scalar, …), or as a **nested value**
//! ([`InputValue::Map`] / [`InputValue::List`]) mirroring the input's Rust type, which
//! [`flatten_inputs`] turns into the compiler's structural-flatten leaf names.

use std::collections::BTreeMap;

use xark_ir::VarId;
use xark_ir::primitive::VarRole;

/// A structured input value, as parsed from JSON (CLI) or a JS object (wasm).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputValue {
    /// A scalar: decimal, `0x`-hex, or a logical value such as a hex byte string.
    Scalar(String),
    /// An array or tuple: element `i` becomes `name[i]`.
    List(Vec<InputValue>),
    /// A struct: field `f` becomes `name.f`.
    Map(Vec<(String, InputValue)>),
}

/// Flatten nested values to `leaf-name → scalar`, using the compiler's structural-flatten
/// names (`name.field`, `name[i]`). Scalars pass through under their own name, so flat and
/// nested inputs can be mixed.
pub fn flatten_inputs(
    entries: impl IntoIterator<Item = (String, InputValue)>,
) -> BTreeMap<String, String> {
    fn go(name: String, v: InputValue, out: &mut BTreeMap<String, String>) {
        match v {
            InputValue::Scalar(s) => {
                out.insert(name, s);
            }
            InputValue::List(xs) => {
                for (i, x) in xs.into_iter().enumerate() {
                    go(format!("{name}[{i}]"), x, out);
                }
            }
            InputValue::Map(fs) => {
                for (f, x) in fs {
                    go(format!("{name}.{f}"), x, out);
                }
            }
        }
    }
    let mut out = BTreeMap::new();
    for (k, v) in entries {
        go(k, v, &mut out);
    }
    out
}

fn decode_hex(h: &str) -> Option<Vec<u8>> {
    if !h.len().is_multiple_of(2) {
        return None;
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok())
        .collect()
}

/// A `0x`-prefixed hex string → raw bytes (rejects a missing prefix / odd length).
fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| format!("expected a 0x-prefixed hex string, got `{s}`"))?;
    decode_hex(h).ok_or_else(|| format!("invalid hex `{s}`"))
}

/// A 256-bit input value → big-endian bytes: a `0x`-hex string (the natural form
/// of a crypto scalar/coordinate) or a plain decimal.
fn value_to_be_bytes(v: &str) -> Result<Vec<u8>, String> {
    if v.starts_with("0x") || v.starts_with("0X") {
        parse_hex_bytes(v)
    } else {
        num_bigint::BigUint::parse_bytes(v.trim().as_bytes(), 10)
            .map(|n| n.to_bytes_be())
            .ok_or_else(|| format!("expected a decimal or `0x`-hex value, got `{v}`"))
    }
}

/// The limb bit-width for an `N`-limb non-native value: 2×128 (the packed secp
/// half form) or 3×86 (the default field-element layout).
fn limb_bits(n_limbs: usize) -> Result<u32, String> {
    match n_limbs {
        2 => Ok(128),
        3 => Ok(86),
        n => Err(format!(
            "unsupported {n}-limb layout (expected 2×128 or 3×86)"
        )),
    }
}

/// Count the `prefix.limbs[i]` leaves present in `vars` (`0` if none).
fn count_limbs(vars: &[xark_ir::primitive::Var], prefix: &str) -> usize {
    let key = format!("{prefix}.limbs");
    vars.iter()
        .filter(|v| array_index(&v.name, &key).is_some())
        .count()
}

/// The distinct `<field>` names of a compound input `prefix.<field>.limbs[i]`
/// (e.g. `["x", "y"]` for a point, `["r", "s"]` for a signature), name-sorted.
fn sub_fields(vars: &[xark_ir::primitive::Var], prefix: &str) -> Vec<String> {
    let pre = format!("{prefix}.");
    let mut fs: Vec<String> = vars
        .iter()
        .filter_map(|v| {
            let (f, tail) = v.name.strip_prefix(&pre)?.split_once('.')?;
            tail.starts_with("limbs[").then(|| f.to_string())
        })
        .collect();
    fs.sort_unstable();
    fs.dedup();
    fs
}

/// A byte-array leaf `name[i]` → its index `i` (only a flat 1-D index; nested /
/// multi-dim names like `x.bits[0][1]` return `None`).
fn array_index(leaf: &str, name: &str) -> Option<usize> {
    let inner = leaf
        .strip_prefix(name)?
        .strip_prefix('[')?
        .strip_suffix(']')?;
    if inner.contains('[') {
        return None;
    }
    inner.parse().ok()
}

/// A SHA-256 digest leaf `name.bits[w][j]` → `(word, bit)`.
fn digest_index(leaf: &str, name: &str) -> Option<(usize, usize)> {
    let rest = leaf.strip_prefix(name)?.strip_prefix(".bits[")?;
    let (w, rest) = rest.split_once("][")?;
    let j = rest.strip_suffix(']')?;
    Some((w.parse().ok()?, j.parse().ok()?))
}

/// The logical input a leaf belongs to (`input[3]` → `input`, `d.bits[0][1]` → `d`).
fn logical_root(leaf: &str) -> &str {
    let cut = leaf.find(['[', '.']).unwrap_or(leaf.len());
    &leaf[..cut]
}

/// Resolve `name → value` inputs to `VarId → decimal` for the solver.
///
/// Shared by `xark prove` and `xark check --inputs`. A name may be a single leaf
/// or a **logical input** that fans out to its leaves:
///   * scalar `Field` → decimal, or `0x`-hex (reduced mod p);
///   * byte array `[u8; N]` (leaves `name[i]`) → a `0x`-hex string of exactly `N`
///     bytes, one byte per leaf;
///   * hash (leaves `name.hi` / `name.lo`) → a `0x`-hex string of 32 bytes packed
///     into two 128-bit field halves (top 16 bytes → `hi`, low 16 → `lo`);
///   * SHA-256 digest (leaves `name.bits[w][j]`) → a `0x`-hex string of 32 bytes,
///     decomposed into the 256 bit leaves in the gadget's word/byte/bit layout.
///
/// A wrong value can only yield an unsatisfiable witness (a clear failure), never
/// a false proof, so this stays a convenience over the always-safe flat form.
pub fn resolve_input_ids(
    vars: &[xark_ir::primitive::Var],
    inputs: &BTreeMap<String, String>,
) -> Result<BTreeMap<VarId, String>, String> {
    // Only inputs can be supplied: a derived (solver-computed) var is never settable.
    let input_vars: Vec<xark_ir::primitive::Var> = vars
        .iter()
        .filter(|v| !matches!(v.role, VarRole::Derived))
        .cloned()
        .collect();
    let vars = &input_vars[..];
    let by_name: BTreeMap<&str, VarId> = vars.iter().map(|v| (v.name.as_str(), v.id)).collect();
    let is_hex = |s: &str| s.starts_with("0x") || s.starts_with("0X");
    let mut id_inputs: BTreeMap<VarId, String> = BTreeMap::new();

    for (k, v) in inputs {
        // 1. Exact leaf — a scalar value (decimal, or `0x`-hex reduced mod p).
        if let Some(&id) = by_name.get(k.as_str()) {
            let dec = if is_hex(v) {
                crate::hex_to_field_decimal(v).map_err(|e| format!("input `{k}`: {e}"))?
            } else {
                crate::try_fr_from_decimal(v)
                    .map_err(|e| format!("invalid value for input `{k}`: {e}"))?;
                v.clone()
            };
            id_inputs.insert(id, dec);
            continue;
        }

        // 2. Byte array `name[i]` — a `0x`-hex string, one byte per leaf.
        let mut arr: Vec<(usize, VarId)> = vars
            .iter()
            .filter_map(|var| array_index(&var.name, k).map(|i| (i, var.id)))
            .collect();
        if !arr.is_empty() {
            arr.sort_unstable_by_key(|(i, _)| *i);
            let bytes = parse_hex_bytes(v).map_err(|e| format!("input `{k}`: {e}"))?;
            if bytes.len() != arr.len() {
                return Err(format!(
                    "input `{k}` is a {}-byte array, but the hex value has {} bytes",
                    arr.len(),
                    bytes.len()
                ));
            }
            for ((_, id), byte) in arr.iter().zip(bytes) {
                id_inputs.insert(*id, byte.to_string());
            }
            continue;
        }

        // 3. Packed hash `name.hi` / `name.lo` — a 32-byte `0x`-hex value split into
        //    two 128-bit field halves (top 16 bytes → hi, low 16 → lo, big-endian).
        if let (Some(&hi_id), Some(&lo_id)) = (
            by_name.get(format!("{k}.hi").as_str()),
            by_name.get(format!("{k}.lo").as_str()),
        ) {
            let bytes = parse_hex_bytes(v).map_err(|e| format!("input `{k}`: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "hash input `{k}` needs a 32-byte hex value, but got {} bytes",
                    bytes.len()
                ));
            }
            let pack = |chunk: &[u8]| chunk.iter().fold(0u128, |acc, &b| (acc << 8) | b as u128);
            id_inputs.insert(hi_id, pack(&bytes[..16]).to_string());
            id_inputs.insert(lo_id, pack(&bytes[16..]).to_string());
            continue;
        }

        // 4. SHA-256 digest `name.bits[w][j]` — a 32-byte `0x`-hex hash. Byte `idx`
        //    occupies word `idx/4`, big-endian slot within the word; leaf bit `j`
        //    of word `w` is bit `j%8` of hash byte `4w + (3 - j/8)`.
        let dig: Vec<((usize, usize), VarId)> = vars
            .iter()
            .filter_map(|var| digest_index(&var.name, k).map(|wj| (wj, var.id)))
            .collect();
        if !dig.is_empty() {
            let bytes = parse_hex_bytes(v).map_err(|e| format!("input `{k}`: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "digest input `{k}` needs a 32-byte hex value, but got {} bytes",
                    bytes.len()
                ));
            }
            for ((w, j), id) in dig {
                let byte = bytes[4 * w + (3 - j / 8)];
                id_inputs.insert(id, ((byte >> (j % 8)) & 1).to_string());
            }
            continue;
        }

        // 5. Non-native scalar `name.limbs[i]` — a 256-bit value (a `0x`-hex crypto
        //    scalar or a decimal) fanned out to its `N` little-endian limbs via the
        //    same `limb_leaves` the gadget's host `NativeInput` uses. `N` picks the
        //    layout: 2 → 128-bit halves (packed secp), 3 → 86-bit limbs.
        let n_scalar = count_limbs(vars, k);
        if n_scalar > 0 {
            let be = value_to_be_bytes(v).map_err(|e| format!("input `{k}`: {e}"))?;
            let bits = limb_bits(n_scalar)?;
            for (name, dec) in crate::limb_leaves(&be, k, n_scalar, bits) {
                if let Some(&id) = by_name.get(name.as_str()) {
                    id_inputs.insert(id, dec);
                }
            }
            continue;
        }

        // 6. Non-native compound `name.<field>.limbs[i]` (an affine point `x ‖ y`,
        //    an ECDSA signature `r ‖ s`, …) — a big-endian concatenation of its
        //    32-byte fields (with an optional SEC1 `0x04` tag), each field fanned
        //    out like case 5. Fields are taken in name order (`r`<`s`, `x`<`y`),
        //    matching the wire concatenation.
        let fields = sub_fields(vars, k);
        if !fields.is_empty() {
            let mut bytes = parse_hex_bytes(v).map_err(|e| format!("input `{k}`: {e}"))?;
            let want = fields.len() * 32;
            if bytes.len() == want + 1 && bytes[0] == 0x04 {
                bytes.remove(0); // strip the SEC1 uncompressed-point tag
            }
            if bytes.len() != want {
                return Err(format!(
                    "compound input `{k}` ({} fields: {fields:?}) needs a {want}-byte \
                     big-endian value{}, but got {} bytes",
                    fields.len(),
                    if fields.len() == 2 {
                        " (or 65 with the 0x04 SEC1 tag)"
                    } else {
                        ""
                    },
                    bytes.len()
                ));
            }
            for (i, f) in fields.iter().enumerate() {
                let chunk = &bytes[i * 32..(i + 1) * 32];
                let n = count_limbs(vars, &format!("{k}.{f}"));
                for (name, dec) in crate::limb_leaves(chunk, &format!("{k}.{f}"), n, limb_bits(n)?)
                {
                    if let Some(&id) = by_name.get(name.as_str()) {
                        id_inputs.insert(id, dec);
                    }
                }
            }
            continue;
        }

        // Unknown — list the circuit's logical inputs (deduped roots, not leaves).
        let mut roots: Vec<&str> = vars.iter().map(|v| logical_root(&v.name)).collect();
        roots.sort_unstable();
        roots.dedup();
        return Err(format!("unknown input `{k}` (circuit inputs: {roots:?})"));
    }
    // Every input must be given — named here, rather than as the solver's
    // "missing input for variable <id>".
    let mut missing: Vec<&str> = Vec::new();
    for v in vars.iter().filter(|v| !id_inputs.contains_key(&v.id)) {
        let root = logical_root(&v.name);
        if !missing.contains(&root) {
            missing.push(root);
        }
    }
    if !missing.is_empty() {
        let list = missing
            .iter()
            .map(|m| format!("`{m}`"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("missing input {list}"));
    }
    Ok(id_inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xark_ir::primitive::Var;

    fn var(id: u32, name: &str, role: VarRole) -> Var {
        Var {
            id: id as VarId,
            name: name.to_string(),
            role,
        }
    }

    fn vars() -> Vec<Var> {
        vec![
            var(0, "id.dob", VarRole::PrivateInput),
            var(1, "id.salt", VarRole::PrivateInput),
            var(2, "msg[0]", VarRole::PrivateInput),
            var(3, "msg[1]", VarRole::PrivateInput),
            var(4, "out", VarRole::PublicInput),
            var(5, "tmp", VarRole::Derived),
        ]
    }

    fn resolve(entries: Vec<(&str, InputValue)>) -> Result<BTreeMap<VarId, String>, String> {
        let flat = flatten_inputs(entries.into_iter().map(|(k, v)| (k.to_string(), v)));
        resolve_input_ids(&vars(), &flat)
    }

    use InputValue::{List, Map, Scalar};

    #[test]
    fn nested_values_resolve_like_flat_leaves() {
        let got = resolve(vec![
            (
                "id",
                Map(vec![
                    ("dob".into(), Scalar("19940312".into())),
                    ("salt".into(), Scalar("0x10".into())),
                ]),
            ),
            ("msg", List(vec![Scalar("1".into()), Scalar("2".into())])),
            ("out", Scalar("9".into())),
        ])
        .unwrap();
        let want: BTreeMap<VarId, String> =
            [(0, "19940312"), (1, "16"), (2, "1"), (3, "2"), (4, "9")]
                .into_iter()
                .map(|(i, v)| (i as VarId, v.to_string()))
                .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn logical_byte_array_still_resolves() {
        let got = resolve(vec![
            ("id.dob", Scalar("1".into())),
            ("id.salt", Scalar("2".into())),
            ("msg", Scalar("0x0102".into())),
            ("out", Scalar("3".into())),
        ])
        .unwrap();
        assert_eq!(got.get(&2).map(String::as_str), Some("1"));
        assert_eq!(got.get(&3).map(String::as_str), Some("2"));
    }

    #[test]
    fn derived_vars_are_not_settable() {
        let err = resolve(vec![("tmp", Scalar("1".into()))]).unwrap_err();
        assert!(err.contains("unknown input `tmp`"), "{err}");
        assert!(
            !err.contains("\"tmp\""),
            "derived vars aren't listed as inputs: {err}"
        );
    }

    #[test]
    fn missing_inputs_are_named() {
        let err = resolve(vec![("out", InputValue::Scalar("1".into()))]).unwrap_err();
        assert_eq!(err, "missing input `id`, `msg`");
    }

    #[test]
    fn bad_values_name_the_input() {
        let err = resolve(vec![("out", Scalar("nine".into()))]).unwrap_err();
        assert!(err.contains("`out`"), "{err}");
    }
}
