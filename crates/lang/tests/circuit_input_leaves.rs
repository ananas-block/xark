//! `#[derive(CircuitInput)]` generates the host-side `NativeInput` fan-out directly:
//! `Native = Self` (the `Field`-composed struct, built host-side with `Field` values),
//! and `leaves` renders each field to a decimal under the compiler's structural-flatten
//! names — no parallel `String` mirror. These tests pin the generated leaf names, order,
//! and decimal values, which must match the compiler's input-var order exactly.

use xark::{CircuitInput, Field};
use xark_prover::NativeInput;

/// Scalars + a fixed array — `Field`s (host-built) rendered to decimals, `<prefix>.f[i]`
/// for array elements.
#[derive(CircuitInput)]
struct Account {
    id: Field,
    tags: [Field; 3],
    balance: Field,
}

#[test]
fn circuit_input_leaves_are_decimals_in_flatten_order() {
    let acct = Account {
        id: Field::from(7u64),
        tags: [Field::from(10u64), Field::from(11u64), Field::from(12u64)],
        balance: Field::from(999u64),
    };
    let leaves = <Account as NativeInput>::leaves(&acct, "user");
    assert_eq!(
        leaves,
        vec![
            ("user.id".to_string(), "7".to_string()),
            ("user.tags[0]".to_string(), "10".to_string()),
            ("user.tags[1]".to_string(), "11".to_string()),
            ("user.tags[2]".to_string(), "12".to_string()),
            ("user.balance".to_string(), "999".to_string()),
        ]
    );
}

#[test]
fn circuit_input_leaf_count_matches_flatten_arity() {
    // `From<Account> for [Field; 5]` (id + 3 tags + balance) — the leaf fan-out and the
    // flatten agree on the count leaf-for-leaf.
    let flat: [Field; 5] = Account {
        id: Field::from(0u8),
        tags: [Field::from(0u8); 3],
        balance: Field::from(0u8),
    }
    .into();
    let acct = Account {
        id: Field::from(1u64),
        tags: [Field::from(2u64); 3],
        balance: Field::from(3u64),
    };
    assert_eq!(
        <Account as NativeInput>::leaves(&acct, "x").len(),
        flat.len()
    );
}

/// Native integers, byte arrays, and a nested `CircuitInput` struct: host values stay
/// native (`u64`, `[u8; 2]`), leaves follow the compiler's structural flatten, and the
/// nested struct's leaves appear inline under its field name.
#[derive(Clone, Copy, Debug, CircuitInput)]
struct Inner {
    a: u64,
    b: Field,
}

#[derive(Clone, Copy, Debug, CircuitInput)]
struct Outer {
    inner: Inner,
    tag: [u8; 2],
    c: u32,
}

#[test]
fn circuit_input_uints_and_nesting_leaves() {
    let o = Outer {
        inner: Inner { a: u64::MAX, b: Field::from(20u8) },
        tag: [1, 2],
        c: 3,
    };
    let leaves = <Outer as NativeInput>::leaves(&o, "o");
    let got: Vec<(&str, &str)> = leaves.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    assert_eq!(
        got,
        vec![
            ("o.inner.a", "18446744073709551615"),
            ("o.inner.b", "20"),
            ("o.tag[0]", "1"),
            ("o.tag[1]", "2"),
            ("o.c", "3"),
        ]
    );
    assert_eq!(Inner::FIELD_LEN, 2);
    assert_eq!(Outer::FIELD_LEN, 5);
    // Constant flatten works on the host too: integers convert with `Field::from`.
    let flat: [Field; 5] = o.into();
    assert_eq!(flat[0].to_decimal(), "18446744073709551615");
    assert_eq!(flat[4].to_decimal(), "3");
}

use xark::{Private, Public};

#[xark::circuit]
fn schema_demo(
    o: Private<Outer>,
    n: Public<u64>,
    b: Private<[u8; 4]>,
    w: Public<[u32; 2]>,
    f: Public<Field>,
) {
    let _ = (o, n, b, w, f);
}

#[test]
fn circuit_schema_describes_nested_types() {
    assert_eq!(
        SchemaDemoInputs::schema(),
        concat!(
            r#"{"circuit":"schema_demo","inputs":["#,
            r#"{"name":"o","visibility":"private","type":{"ref":"Outer"}},"#,
            r#"{"name":"n","visibility":"public","type":{"uint":64}},"#,
            r#"{"name":"b","visibility":"private","type":{"array":{"of":{"uint":8},"len":4}}},"#,
            r#"{"name":"w","visibility":"public","type":{"array":{"of":{"uint":32},"len":2}}},"#,
            r#"{"name":"f","visibility":"public","type":"field"}],"#,
            r#""types":{"#,
            r#""Inner":{"struct":[{"name":"a","type":{"uint":64}},{"name":"b","type":"field"}]},"#,
            r#""Outer":{"struct":[{"name":"inner","type":{"ref":"Inner"}},"#,
            r#"{"name":"tag","type":{"array":{"of":{"uint":8},"len":2}}},"#,
            r#"{"name":"c","type":{"uint":32}}]}}}"#,
        )
    );
}

/// Off-circuit, `Field` operations don't compute: they panic with an explanation
/// instead of hanging in an infinite loop.
#[test]
fn field_arithmetic_on_host_panics_with_explanation() {
    let r = std::panic::catch_unwind(|| Field::from(1u8) + Field::from(2u8));
    let msg = r.expect_err("host Field arithmetic must not return");
    let msg = msg
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| msg.downcast_ref::<&str>().copied())
        .unwrap_or_default();
    assert!(msg.contains("outside a circuit"), "{msg}");
}
