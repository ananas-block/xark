//! Input values in a type's **natural encoding**, as `schema.json` declares it
//! (`types.<T>.encoding`): an Ed25519 key's 32 bytes for a `PointL`, a scalar's
//! number for a limbed `Fq`, a hash's 32 bytes for a `Hash`. [`expand`] rewrites
//! such a value into the type's leaves before input resolution, so
//! `xark prove --inputs '{"pubkey": "0x…"}'` works for any gadget type. The
//! generated TypeScript client implements the same encodings.
//!
//! Encodings (on a struct type):
//! * `{"bytes": K, "limbs": B}`: the value is a number (decimal / `0x`-hex, at most
//!   `K` bytes); the struct's leaves, in flatten order, are its little-endian
//!   `B`-bit limbs.
//! * `{"concat": [k₁, …] | "fields", "sec1"?: true}`: `0x`-hex bytes, the fields'
//!   encodings back to back (`k_i` bytes each, or each field type's own length); a
//!   `field` slice is its big-endian number. `sec1`: a leading `0x04` is accepted.
//! * `{"bytes": 32, "ed25519": true}`: a compressed Ed25519 point, decompressed to
//!   `x`, `y` (32 big-endian bytes each), then the two fields' encodings.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use num_bigint::BigUint;
use serde_json::Value;

/// Rewrite every input given in its type's natural encoding into its leaves
/// (decimal values), leaving everything else as it is. Without a `schema.json`
/// (or with no encoded types) the inputs come back unchanged.
pub fn expand(
    xark_dir: &std::path::Path,
    inputs: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let Ok(text) = std::fs::read_to_string(xark_dir.join("schema.json")) else {
        return Ok(inputs);
    };
    let schema: Value = serde_json::from_str(&text)?;
    let mut out = BTreeMap::new();
    for (key, value) in inputs {
        match encoded_type(&schema, &key) {
            Some(ty) => {
                let leaves = encode(&schema, &ty, &value, &key)
                    .map_err(|e| anyhow!("input `{key}`: {e}"))?;
                for (leaf, v) in leaves {
                    out.insert(leaf, v.to_string());
                }
            }
            None => {
                out.insert(key, value);
            }
        }
    }
    Ok(out)
}

/// The struct type at input path `key` (`sig`, `rounds[0].l`), if it has an
/// encoding.
fn encoded_type(schema: &Value, key: &str) -> Option<String> {
    // Walk `name`, then `.field` / `[i]` steps.
    let root = key.split(['.', '[']).next()?;
    let mut ty = schema["inputs"]
        .as_array()?
        .iter()
        .find(|i| i["name"] == root)?["type"]
        .clone();
    let rest = &key[root.len()..];
    let mut i = 0;
    let b = rest.as_bytes();
    while i < b.len() {
        if b[i] == b'.' {
            let end = rest[i + 1..]
                .find(['.', '['])
                .map_or(rest.len(), |e| i + 1 + e);
            let f = &rest[i + 1..end];
            let def = &schema["types"][ty["ref"].as_str()?];
            ty = def["struct"].as_array()?.iter().find(|x| x["name"] == f)?["type"].clone();
            i = end;
        } else if b[i] == b'[' {
            let end = rest[i..].find(']')? + i;
            ty = ty["array"]["of"].clone();
            i = end + 1;
        } else {
            return None;
        }
    }
    let name = ty["ref"].as_str()?;
    schema["types"][name].get("encoding")?;
    Some(name.to_string())
}

/// The leaf names of a value of `ty` at `prefix`, in flatten order.
fn leaf_names(schema: &Value, ty: &Value, prefix: &str, out: &mut Vec<String>) {
    if ty == "field" || ty.get("uint").is_some() {
        out.push(prefix.to_string());
    } else if let Some(a) = ty.get("array") {
        for i in 0..a["len"].as_u64().unwrap_or(0) {
            leaf_names(schema, &a["of"], &format!("{prefix}[{i}]"), out);
        }
    } else if let Some(t) = ty["tuple"].as_array() {
        for (i, e) in t.iter().enumerate() {
            leaf_names(schema, e, &format!("{prefix}.{i}"), out);
        }
    } else if let Some(r) = ty["ref"].as_str() {
        for f in schema["types"][r]["struct"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let n = f["name"].as_str().unwrap_or_default();
            leaf_names(schema, &f["type"], &format!("{prefix}.{n}"), out);
        }
    }
}

/// The encoded length of struct type `name`, in bytes.
fn encoded_len(schema: &Value, name: &str) -> Option<usize> {
    let enc = &schema["types"][name]["encoding"];
    if let Some(b) = enc["bytes"].as_u64() {
        return Some(b as usize);
    }
    concat_sizes(schema, name).map(|s| s.iter().sum())
}

/// Each field's byte length in a `concat` encoding.
fn concat_sizes(schema: &Value, name: &str) -> Option<Vec<usize>> {
    let def = &schema["types"][name];
    match &def["encoding"]["concat"] {
        Value::Array(xs) => xs.iter().map(|x| x.as_u64().map(|v| v as usize)).collect(),
        _ => def["struct"]
            .as_array()?
            .iter()
            .map(|f| encoded_len(schema, f["type"]["ref"].as_str()?))
            .collect(),
    }
}

fn hex_bytes(v: &str) -> Result<Vec<u8>> {
    let h = v
        .strip_prefix("0x")
        .or_else(|| v.strip_prefix("0X"))
        .ok_or_else(|| anyhow!("expected `0x`-hex bytes, got `{v}`"))?;
    if !h.len().is_multiple_of(2) {
        bail!("`{v}` has an odd number of hex digits");
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|_| anyhow!("invalid hex `{v}`")))
        .collect()
}

/// `value` (natural encoding of struct type `name`) as `(leaf, value)` pairs under
/// `prefix`.
fn encode(schema: &Value, name: &str, value: &str, prefix: &str) -> Result<Vec<(String, BigUint)>> {
    let enc = &schema["types"][name]["encoding"];
    let v = value.trim();
    if enc.get("limbs").is_some() {
        // A number: decimal or `0x`-hex.
        let n = match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
            Some(h) => BigUint::parse_bytes(h.as_bytes(), 16),
            None => BigUint::parse_bytes(v.as_bytes(), 10),
        }
        .ok_or_else(|| anyhow!("expected a decimal or `0x`-hex number, got `{v}`"))?;
        return encode_number(schema, name, &n, prefix);
    }
    encode_bytes(schema, name, &hex_bytes(v)?, prefix)
}

fn encode_number(
    schema: &Value,
    name: &str,
    n: &BigUint,
    prefix: &str,
) -> Result<Vec<(String, BigUint)>> {
    let enc = &schema["types"][name]["encoding"];
    let bits = enc["limbs"].as_u64().unwrap_or(0) as usize;
    let mut leaves = Vec::new();
    leaf_names(
        schema,
        &serde_json::json!({ "ref": name }),
        prefix,
        &mut leaves,
    );
    if n.bits() as usize > bits * leaves.len() {
        bail!(
            "{n} doesn't fit a {name} ({} limbs of {bits} bits)",
            leaves.len()
        );
    }
    let mask = (BigUint::from(1u8) << bits) - 1u8;
    Ok(leaves
        .into_iter()
        .enumerate()
        .map(|(i, l)| (l, (n >> (i * bits)) & &mask))
        .collect())
}

fn encode_bytes(
    schema: &Value,
    name: &str,
    bytes: &[u8],
    prefix: &str,
) -> Result<Vec<(String, BigUint)>> {
    let def = &schema["types"][name];
    let enc = &def["encoding"];
    let len = encoded_len(schema, name).ok_or_else(|| anyhow!("`{name}` has no byte length"))?;
    let mut bytes = bytes.to_vec();
    if enc["sec1"] == true && bytes.len() == len + 1 && bytes[0] == 0x04 {
        bytes.remove(0);
    }
    if bytes.len() != len {
        bail!("a {name} is {len} bytes, got {}", bytes.len());
    }
    if enc.get("limbs").is_some() {
        return encode_number(schema, name, &BigUint::from_bytes_be(&bytes), prefix);
    }
    let fields = def["struct"].as_array().cloned().unwrap_or_default();
    let (sizes, bytes) = if enc["ed25519"] == true {
        let (x, y) = decompress(&bytes)?;
        (vec![32, 32], [be32(&x), be32(&y)].concat())
    } else {
        (
            concat_sizes(schema, name).ok_or_else(|| anyhow!("`{name}` has no field lengths"))?,
            bytes,
        )
    };
    let mut out = Vec::new();
    let mut at = 0;
    for (f, size) in fields.iter().zip(sizes) {
        let chunk = &bytes[at..at + size];
        at += size;
        let leaf = format!("{prefix}.{}", f["name"].as_str().unwrap_or_default());
        match f["type"]["ref"].as_str() {
            Some(r) => out.extend(encode_bytes(schema, r, chunk, &leaf)?),
            None => out.push((leaf, BigUint::from_bytes_be(chunk))),
        }
    }
    Ok(out)
}

fn be32(v: &BigUint) -> Vec<u8> {
    let b = v.to_bytes_be();
    let mut out = vec![0u8; 32 - b.len()];
    out.extend(b);
    out
}

/// Decompress an Ed25519 point (32 bytes: `y` little-endian, `x`'s sign in the top
/// bit) to affine `(x, y)`.
fn decompress(comp: &[u8]) -> Result<(BigUint, BigUint)> {
    let dec = |s: &str| BigUint::parse_bytes(s.as_bytes(), 10).expect("constant");
    let p = dec("57896044618658097711785492504343953926634992332820282019728792003956564819949");
    let d = dec("37095705934669439343138083508754565189542113879843219016388785533085940283555");
    let sqrt_m1 =
        dec("19681161376707505956807079304988542015446066515923890162744021073123829784752");
    let mut yb = comp.to_vec();
    let sign = (yb[31] >> 7) & 1;
    yb[31] &= 0x7f;
    let y = BigUint::from_bytes_le(&yb);
    if y >= p {
        bail!("not an Ed25519 point (y >= p)");
    }
    let y2 = (&y * &y) % &p;
    let u = (&y2 + &p - 1u32) % &p;
    let v = (&d * &y2 + 1u32) % &p;
    let v3 = v.modpow(&BigUint::from(3u32), &p);
    let v7 = v.modpow(&BigUint::from(7u32), &p);
    let pw = ((&u * &v7) % &p).modpow(&((&p - 5u32) / 8u32), &p);
    let mut x = (((&u * &v3) % &p) * pw) % &p;
    if (&v * (&x * &x % &p)) % &p != u {
        x = (x * sqrt_m1) % &p;
    }
    if (&v * (&x * &x % &p)) % &p != u {
        bail!("not an Ed25519 point (no square root)");
    }
    if (x.bit(0) as u8) != sign {
        x = (&p - &x) % &p;
    }
    Ok((x, y))
}

/// One declared input, for summaries and `--inputs` templates.
pub struct InputSummary {
    pub name: String,
    pub public: bool,
    /// Its type, as written in Rust (`[u8; 13]`, `PointL`).
    pub ty: String,
    /// A placeholder value in its natural form (`"0x<32 bytes>"`), as JSON text
    /// (struct fields in declaration order).
    pub template: String,
}

/// The circuit's declared inputs, from `schema.json` (`None` without one).
pub fn summary(xark_dir: &std::path::Path) -> Option<Vec<InputSummary>> {
    let schema: Value =
        serde_json::from_str(&std::fs::read_to_string(xark_dir.join("schema.json")).ok()?).ok()?;
    Some(
        schema["inputs"]
            .as_array()?
            .iter()
            .map(|i| InputSummary {
                name: i["name"].as_str().unwrap_or_default().to_string(),
                public: i["visibility"] == "public",
                ty: describe(&i["type"]),
                template: template(&schema, &i["type"]),
            })
            .collect(),
    )
}

/// A schema type as Rust spells it.
fn describe(ty: &Value) -> String {
    if ty == "field" {
        return "Field".into();
    }
    if let Some(w) = ty["uint"].as_u64() {
        return format!("u{w}");
    }
    if let Some(a) = ty.get("array") {
        return format!("[{}; {}]", describe(&a["of"]), a["len"]);
    }
    if let Some(t) = ty["tuple"].as_array() {
        let parts: Vec<String> = t.iter().map(describe).collect();
        return format!("({})", parts.join(", "));
    }
    ty["ref"].as_str().unwrap_or("?").to_string()
}

/// A placeholder for a value of `ty`, in its natural form, as JSON text.
fn template(schema: &Value, ty: &Value) -> String {
    let q = |s: String| format!("{s:?}");
    if ty == "field" {
        return q("<field>".into());
    }
    if let Some(w) = ty["uint"].as_u64() {
        return q(format!("<u{w}>"));
    }
    let list = |xs: Vec<String>| format!("[{}]", xs.join(", "));
    if let Some(a) = ty.get("array") {
        let n = a["len"].as_u64().unwrap_or(0);
        if a["of"]["uint"] == 8 {
            return q(format!("0x<{n} bytes>"));
        }
        return list((0..n).map(|_| template(schema, &a["of"])).collect());
    }
    if let Some(t) = ty["tuple"].as_array() {
        return list(t.iter().map(|e| template(schema, e)).collect());
    }
    let name = ty["ref"].as_str().unwrap_or_default();
    let def = &schema["types"][name];
    if def.get("encoding").is_some() {
        let bytes = encoded_len(schema, name).map_or("bytes".into(), |b| format!("{b} bytes"));
        return q(if def["encoding"].get("limbs").is_some() {
            format!("<number, or 0x {bytes}>")
        } else {
            format!("0x<{bytes}>")
        });
    }
    let fields: Vec<String> = def["struct"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| {
            format!(
                "{:?}: {}",
                f["name"].as_str().unwrap_or_default(),
                template(schema, &f["type"])
            )
        })
        .collect();
    format!("{{{}}}", fields.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> Value {
        serde_json::json!({
            "inputs": [
                {"name": "k", "type": {"ref": "Fq"}},
                {"name": "h", "type": {"ref": "Hash"}},
                {"name": "sig", "type": {"ref": "Sig"}},
                {"name": "n", "type": "field"},
            ],
            "types": {
                "Fq": {"struct": [{"name": "limbs", "type": {"array": {"of": "field", "len": 3}}}],
                       "encoding": {"bytes": 32, "limbs": 86}},
                "Hash": {"struct": [{"name": "hi", "type": "field"}, {"name": "lo", "type": "field"}],
                         "encoding": {"bytes": 32, "concat": [16, 16]}},
                "Sig": {"struct": [{"name": "r", "type": {"ref": "Fq"}}, {"name": "s", "type": {"ref": "Fq"}}],
                        "encoding": {"concat": "fields"}},
            }
        })
    }

    fn run(key: &str, value: &str) -> Vec<(String, String)> {
        let s = schema();
        let ty = encoded_type(&s, key).expect("encoded");
        encode(&s, &ty, value, key)
            .unwrap()
            .into_iter()
            .map(|(l, v)| (l, v.to_string()))
            .collect()
    }

    #[test]
    fn limbs_hash_and_concat() {
        // 2^86 + 5 → [5, 1, 0].
        let two86p5 = (BigUint::from(1u8) << 86u32) + 5u32;
        assert_eq!(
            run("k", &two86p5.to_string()),
            [
                ("k.limbs[0]", "5"),
                ("k.limbs[1]", "1"),
                ("k.limbs[2]", "0")
            ]
            .map(|(a, b)| (a.to_string(), b.to_string()))
        );
        let h = format!("0x{}{}", "00".repeat(15) + "02", "00".repeat(15) + "03");
        assert_eq!(
            run("h", &h),
            [("h.hi", "2"), ("h.lo", "3")].map(|(a, b)| (a.to_string(), b.to_string()))
        );
        let sig = format!("0x{}{}", "00".repeat(31) + "04", "00".repeat(31) + "06");
        let got = run("sig", &sig);
        assert_eq!(got[0], ("sig.r.limbs[0]".into(), "4".into()));
        assert_eq!(got[3], ("sig.s.limbs[0]".into(), "6".into()));
        assert!(encoded_type(&schema(), "n").is_none());
    }

    #[test]
    fn ed25519_base_point_decompresses() {
        // The base point's compressed form: y = 4/5, x positive.
        let mut comp = [0x66u8; 32];
        comp[0] = 0x58;
        let (x, y) = decompress(&comp).unwrap();
        assert_eq!(
            x.to_string(),
            "15112221349535400772501151409588531511454012693041857206046113283949847762202"
        );
        assert_eq!(
            y.to_string(),
            "46316835694926478169428394003475163141307993866256225615783033603165251855960"
        );
    }
}
