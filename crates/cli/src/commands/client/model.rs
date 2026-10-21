//! A circuit's inputs as the standard types every client language maps from.
//!
//! [`Model::new`] resolves `schema.json` once: each input's type becomes a [`Ty`]
//! (newtypes unwrapped, encodings turned into the standard type they stand for), and
//! the structs and enums the inputs reach are collected in order. A language target
//! (`ts.rs`) then only says how each [`Ty`] looks in that language: its own types,
//! and the JSON form xark-wasm takes and gives back. Encoding values into field
//! elements stays in the one Rust codec (`xark_prover::schema`), which every target
//! calls into, so no target reimplements it.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// A standard type, as a client sees it.
#[derive(Clone, Debug, PartialEq)]
pub enum Ty {
    /// A field element.
    Field,
    /// An unsigned integer of this many bits.
    Uint(u64),
    /// `true` or `false`.
    Bool,
    /// A byte string: `[u8; N]` (`of: None`), or a byte-encoded type such as a hash or
    /// a curve point (`of: Some(name)`), of `len` bytes when that is fixed.
    Bytes {
        of: Option<String>,
        len: Option<u64>,
    },
    /// A whole number split into limbs (a non-native field element).
    Number { of: String },
    /// A calendar day.
    Date,
    /// A string of at most `max` UTF-8 bytes.
    Text { max: u64 },
    /// One variant of an enum.
    Choice(String),
    /// A set of an enum's variants.
    Set(String),
    /// `len` values of one type.
    Array(Box<Ty>, u64),
    /// Values of different types.
    Tuple(Vec<Ty>),
    /// A struct, by name (see [`Model::structs`]).
    Struct(String),
}

/// One input (or struct field).
#[derive(Clone, Debug)]
pub struct Field {
    /// As declared (`born_before`); targets apply their own case.
    pub name: String,
    pub ty: Ty,
    /// The Rust type as written (`Bitfield<Country>`), for docs.
    pub rust: String,
}

/// A circuit's inputs, resolved.
#[derive(Debug)]
pub struct Model {
    pub circuit: String,
    /// The inputs, in declaration order, and whether each is public.
    pub inputs: Vec<(Field, bool)>,
    /// Every struct an input reaches, its fields in order.
    pub structs: BTreeMap<String, Vec<Field>>,
    /// Every enum a `Choice` or `Set` names, its variants in order.
    pub enums: BTreeMap<String, Vec<String>>,
    /// The `schema.json` text, for xark-wasm.
    pub schema: String,
}

impl Model {
    pub fn new(schema: &Value) -> Result<Model> {
        if schema["version"].as_u64() != Some(2) {
            bail!(
                "unsupported schema version {} (expected 2: rebuild the circuit with this xark)",
                schema["version"]
            );
        }
        let mut m = Model {
            circuit: schema["circuit"]
                .as_str()
                .context("schema without `circuit`")?
                .to_string(),
            inputs: Vec::new(),
            structs: BTreeMap::new(),
            enums: BTreeMap::new(),
            schema: serde_json::to_string(schema)?,
        };
        for i in schema["inputs"].as_array().into_iter().flatten() {
            let f = m.field(schema, i)?;
            m.inputs.push((f, i["visibility"] == "public"));
        }
        Ok(m)
    }

    fn field(&mut self, schema: &Value, f: &Value) -> Result<Field> {
        Ok(Field {
            name: f["name"].as_str().unwrap_or_default().to_string(),
            ty: self.ty(schema, &f["type"])?,
            rust: rust_type(&f["type"]),
        })
    }

    fn ty(&mut self, schema: &Value, ty: &Value) -> Result<Ty> {
        if ty == "field" {
            return Ok(Ty::Field);
        }
        if ty == "bool" {
            return Ok(Ty::Bool);
        }
        if let Some(w) = ty["uint"].as_u64() {
            return Ok(Ty::Uint(w));
        }
        if let Some(a) = ty.get("array") {
            let len = a["len"].as_u64().unwrap_or(0);
            if a["of"]["uint"] == 8 {
                return Ok(Ty::Bytes {
                    of: None,
                    len: Some(len),
                });
            }
            return Ok(Ty::Array(Box::new(self.ty(schema, &a["of"])?), len));
        }
        if let Some(t) = ty["tuple"].as_array() {
            return Ok(Ty::Tuple(
                t.iter()
                    .map(|e| self.ty(schema, e))
                    .collect::<Result<_>>()?,
            ));
        }
        let r = ty["ref"]
            .as_str()
            .with_context(|| format!("unknown schema type {ty}"))?;
        let def = &schema["types"][r];
        let enc = &def["encoding"];
        let mut variants = |e: &str| -> String {
            let names = schema["types"][e]["enum"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|n| n.as_str().map(str::to_string))
                .collect();
            self.enums.insert(e.to_string(), names);
            e.to_string()
        };
        Ok(if enc.get("date").is_some() {
            Ty::Date
        } else if let Some(max) = enc["text"].as_u64() {
            Ty::Text { max }
        } else if let Some(e) = enc["choice"].as_str() {
            Ty::Choice(variants(e))
        } else if let Some(e) = enc["set"].as_str() {
            Ty::Set(variants(e))
        } else if enc.get("limbs").is_some() {
            Ty::Number { of: r.to_string() }
        } else if enc.is_object() {
            Ty::Bytes {
                of: Some(r.to_string()),
                len: byte_len(schema, r),
            }
        } else if let Some(n) = def.get("newtype") {
            self.ty(schema, n)?
        } else {
            if !self.structs.contains_key(r) {
                // Reserve the name first, so a struct reached twice is resolved once.
                self.structs.insert(r.to_string(), Vec::new());
                let fields = def["struct"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|f| self.field(schema, f))
                    .collect::<Result<_>>()?;
                self.structs.insert(r.to_string(), fields);
            }
            Ty::Struct(r.to_string())
        })
    }

    /// The public inputs, in declaration order.
    pub fn public(&self) -> impl Iterator<Item = &Field> {
        self.inputs.iter().filter(|(_, p)| *p).map(|(f, _)| f)
    }
}

/// A byte-encoded named type's length, when fixed.
fn byte_len(schema: &Value, r: &str) -> Option<u64> {
    let def = &schema["types"][r];
    let enc = &def["encoding"];
    if let Some(b) = enc["bytes"].as_u64() {
        return Some(b);
    }
    def["struct"]
        .as_array()?
        .iter()
        .map(|f| byte_len(schema, f["type"]["ref"].as_str()?))
        .sum()
}

/// A Rust type as written, from a schema type.
fn rust_type(ty: &Value) -> String {
    if ty == "field" {
        return "Field".into();
    }
    if ty == "bool" {
        return "bool".into();
    }
    if let Some(w) = ty["uint"].as_u64() {
        return format!("u{w}");
    }
    if let Some(a) = ty.get("array") {
        return format!("[{}; {}]", rust_type(&a["of"]), a["len"]);
    }
    if let Some(t) = ty["tuple"].as_array() {
        let p: Vec<String> = t.iter().map(rust_type).collect();
        return format!("({})", p.join(", "));
    }
    ty["ref"].as_str().unwrap_or("?").into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_standard_types() {
        let schema: Value = serde_json::from_str(
            r#"{"version": 2, "circuit": "c",
              "inputs": [
                {"name": "id", "visibility": "private", "type": {"ref": "Id"}},
                {"name": "k", "visibility": "public", "type": {"ref": "Point"}}],
              "types": {
                "Id": {"struct": [
                  {"name": "home", "type": {"ref": "Choice<Country>"}},
                  {"name": "born", "type": {"ref": "Date"}},
                  {"name": "w", "type": {"ref": "W"}}]},
                "W": {"newtype": {"uint": 32}},
                "Choice<Country>": {"newtype": "field", "encoding": {"choice": "Country"}},
                "Country": {"enum": ["AD", "US"]},
                "Date": {"newtype": "field", "encoding": {"date": "yyyymmdd"}},
                "Fp": {"struct": [{"name": "limbs", "type": {"array": {"of": "field", "len": 3}}}],
                       "encoding": {"bytes": 32, "limbs": 86}},
                "Point": {"struct": [{"name": "x", "type": {"ref": "Fp"}}, {"name": "y", "type": {"ref": "Fp"}}],
                          "encoding": {"concat": "fields"}}},
              "public_inputs": []}"#,
        )
        .unwrap();
        let m = Model::new(&schema).unwrap();
        let id = &m.structs["Id"];
        assert_eq!(id[0].ty, Ty::Choice("Country".into()));
        assert_eq!((&id[1].ty, &id[2].ty), (&Ty::Date, &Ty::Uint(32)));
        assert_eq!(m.enums["Country"], ["AD", "US"]);
        assert_eq!(
            m.inputs[1].0.ty,
            Ty::Bytes {
                of: Some("Point".into()),
                len: Some(64)
            }
        );
        assert!(!m.structs.contains_key("Fp"));
    }
}
