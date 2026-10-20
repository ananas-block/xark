//! `schema.json` from the input binding events: every leaf's full name
//! (`policy.tags[1]`), visibility and `uN` width, plus the struct type bound at each
//! path. The leaf names spell the structure (`.field`, `[i]`, `.0`); the markers
//! name the structs.

use std::collections::BTreeMap;

use serde_json::{Value, json};

#[derive(Default)]
struct Node {
    /// Children in first-bound order: `(segment, node)`; a segment is a field name
    /// or an `[i]` index.
    kids: Vec<(Seg, Node)>,
    width: Option<Option<u32>>,
}

#[derive(Clone, PartialEq)]
enum Seg {
    Field(String),
    Index(usize),
}

fn segments(path: &str) -> Vec<Seg> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '.' => {
                if !cur.is_empty() {
                    out.push(Seg::Field(std::mem::take(&mut cur)));
                }
            }
            '[' => {
                if !cur.is_empty() {
                    out.push(Seg::Field(std::mem::take(&mut cur)));
                }
                let mut n = String::new();
                for d in chars.by_ref() {
                    if d == ']' {
                        break;
                    }
                    n.push(d);
                }
                out.push(Seg::Index(n.parse().unwrap_or(0)));
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(Seg::Field(cur));
    }
    out
}

fn insert(node: &mut Node, segs: &[Seg], width: Option<u32>) {
    match segs.split_first() {
        None => node.width = Some(width),
        Some((s, rest)) => {
            let i = match node.kids.iter().position(|(k, _)| k == s) {
                Some(i) => i,
                None => {
                    node.kids.push((s.clone(), Node::default()));
                    node.kids.len() - 1
                }
            };
            insert(&mut node.kids[i].1, rest, width);
        }
    }
}

fn path_of(segs: &[Seg]) -> String {
    let mut p = String::new();
    for s in segs {
        match s {
            Seg::Field(f) if p.is_empty() => p.push_str(f),
            Seg::Field(f) => {
                p.push('.');
                p.push_str(f);
            }
            Seg::Index(i) => p.push_str(&format!("[{i}]")),
        }
    }
    p
}

fn type_of(
    node: &Node,
    at: &mut Vec<Seg>,
    structs: &BTreeMap<String, String>,
    encodings: &BTreeMap<String, Value>,
    types: &mut serde_json::Map<String, Value>,
) -> Value {
    if let Some(w) = node.width {
        return match w {
            None => json!("field"),
            Some(w) => json!({ "uint": w }),
        };
    }
    if let Some(name) = structs.get(&path_of(at)) {
        if !types.contains_key(name) {
            types.insert(name.clone(), Value::Null);
            let fields: Vec<Value> = node
                .kids
                .iter()
                .map(|(s, k)| {
                    at.push(s.clone());
                    let t = type_of(k, at, structs, encodings, types);
                    at.pop();
                    let n = match s {
                        Seg::Field(f) => f.clone(),
                        Seg::Index(i) => i.to_string(),
                    };
                    json!({ "name": n, "type": t })
                })
                .collect();
            let mut def = json!({ "struct": fields });
            if let Some(e) = encodings.get(name) {
                def["encoding"] = e.clone();
            }
            types.insert(name.clone(), def);
        }
        return json!({ "ref": name });
    }
    if node.kids.iter().all(|(s, _)| matches!(s, Seg::Index(_))) && !node.kids.is_empty() {
        let (s, first) = &node.kids[0];
        at.push(s.clone());
        let of = type_of(first, at, structs, encodings, types);
        at.pop();
        return json!({ "array": { "of": of, "len": node.kids.len() } });
    }
    // Positional fields `.0`, `.1`, …: a tuple.
    let elems: Vec<Value> = node
        .kids
        .iter()
        .map(|(s, k)| {
            at.push(s.clone());
            let t = type_of(k, at, structs, encodings, types);
            at.pop();
            t
        })
        .collect();
    json!({ "tuple": elems })
}

pub(crate) fn build(
    circuit: &str,
    leaves: &[(String, bool, Option<u32>)],
    structs: &[(String, String)],
    encodings: &[(String, String)],
) -> Value {
    let structs: BTreeMap<String, String> = structs.iter().cloned().collect();
    // A struct's natural encoding, as its type declared it (malformed JSON: none).
    let encodings: BTreeMap<String, Value> = encodings
        .iter()
        .filter_map(|(t, j)| Some((t.clone(), serde_json::from_str(j).ok()?)))
        .collect();
    // Parameters in first-bound order, each with its leaves' trie.
    let mut params: Vec<(String, bool, Node)> = Vec::new();
    let mut public_inputs = Vec::new();
    for (name, public, width) in leaves {
        let segs = segments(name);
        let Some(Seg::Field(root)) = segs.first() else {
            continue;
        };
        let i = match params.iter().position(|(r, _, _)| r == root) {
            Some(i) => i,
            None => {
                params.push((root.clone(), *public, Node::default()));
                params.len() - 1
            }
        };
        insert(&mut params[i].2, &segs[1..], *width);
        if *public {
            public_inputs.push(name.clone());
        }
    }
    let mut types = serde_json::Map::new();
    let inputs: Vec<Value> = params
        .iter()
        .map(|(root, public, node)| {
            let mut at = vec![Seg::Field(root.clone())];
            json!({
                "name": root,
                "visibility": if *public { "public" } else { "private" },
                "type": type_of(node, &mut at, &structs, &encodings, &mut types),
            })
        })
        .collect();
    json!({
        "version": 1,
        "circuit": circuit,
        "inputs": inputs,
        "types": types,
        "public_inputs": public_inputs,
    })
}
