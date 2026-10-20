//! `#[derive(CircuitInput)]` generates the host-side `NativeInput` fan-out directly:
//! the value is the struct itself (built host-side with `Field` values), and `leaves`
//! gives each field's value under the compiler's structural-flatten names. These
//! tests pin the generated leaf names, order, and values, which must match the
//! compiler's input-var order exactly.

use xark::{CircuitInput, Field};

/// The leaves with decimal values, for comparison.
fn leaves<T: xark_prover::NativeInput>(v: &T, prefix: &str) -> Vec<(String, String)> {
    T::leaves(v, prefix)
        .into_iter()
        .map(|(n, f)| (n, f.to_string()))
        .collect()
}

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
    let leaves = leaves(&acct, "user");
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
    assert_eq!(leaves(&acct, "x").len(), flat.len());
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
        inner: Inner {
            a: u64::MAX,
            b: Field::from(20u8),
        },
        tag: [1, 2],
        c: 3,
    };
    let leaves = leaves(&o, "o");
    let got: Vec<(&str, &str)> = leaves
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
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

/// Off-circuit, circuit code runs natively: `Field` arithmetic, comparisons and
/// hints compute what the solver would, and a failed `require` panics at its line.
#[test]
fn circuit_code_runs_natively_on_the_host() {
    use xark::{require, require_eq};
    let (a, b) = (Field::from(6u8), Field::from(7u8));
    assert_eq!((a * b + a - b).to_decimal(), "41");
    assert_eq!((-a + a).to_decimal(), "0");
    assert_eq!((a.inv() * a).to_decimal(), "1");
    assert_eq!(a.pow(3).to_decimal(), "216");
    assert!(a == Field::from(6u8) && a != b);
    assert!(a.lt::<8>(b) && !b.lt::<8>(a) && a < 7u8);
    assert_eq!(
        Field::from(5u8).to_bits::<3>().map(|b| b.to_decimal()),
        ["1", "0", "1"]
    );
    let qr = Field::hint_div_rem(Field::from(17u8), Field::from(5u8));
    assert_eq!([qr[0].to_decimal(), qr[1].to_decimal()], ["3", "2"]);
    // p − 1 is −1.
    assert_eq!(
        (Field::from(0u8) - Field::from(1u8) + Field::from(1u8)).to_decimal(),
        "0"
    );

    require(a < 7u8);
    require_eq(a * b, 42u64);
    let fails = |f: fn()| {
        let msg = std::panic::catch_unwind(f).expect_err("must fail");
        let msg = msg
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| msg.downcast_ref::<&str>().copied())
            .unwrap_or_default()
            .to_string();
        assert!(msg.contains("requirement failed"), "{msg}");
    };
    fails(|| require(Field::from(9u8) < 7u8));
    fails(|| require_eq(Field::from(1u8), 2u64));
    fails(|| {
        let _ = Field::from(8u8).to_bits::<3>(); // 8 doesn't fit 3 bits
    });
    // Inside a witness-only region requirements aren't constraints, so aren't checked.
    xark::witness_begin();
    require_eq(Field::from(1u8), 2u64);
    xark::witness_end();
}
