//! The template-reduced R1CS (what `xark setup` keys) must stay as sound as the full
//! circuit. Regression: the per-scope minimizer used to treat a template call's
//! output as a free internal variable in the *caller*, eliminate it there and drop
//! the row tying it to a public output — leaving the output unconstrained, so a proof
//! could claim any value.
//!
//! Fixture: `examples/mimc_loop` built by the MIR frontend (templated `circuit.xbc`).

use std::collections::BTreeMap;

use xark_ir::function_decode::{expand_function_blob, expand_function_blob_reduced};
use xark_ir::solver::{check_cp, solve_cp};

const XBC: &[u8] = include_bytes!("fixtures/mimc_loop_templated.xbc");

fn witness(h: &str) -> BTreeMap<u32, xark_ir::solver::Fp> {
    let full = expand_function_blob(XBC).unwrap();
    let id = |n: &str| full.vars.iter().find(|v| v.name == n).unwrap().id;
    let inputs: BTreeMap<u32, String> = [("x", "3"), ("k", "5"), ("h", h)]
        .into_iter()
        .map(|(n, v)| (id(n), v.to_string()))
        .collect();
    solve_cp(&full, &inputs).unwrap()
}

#[test]
fn reduced_circuit_rejects_a_wrong_public_output() {
    let full = expand_function_blob(XBC).unwrap();
    let reduced = expand_function_blob_reduced(XBC).unwrap();
    let forged = witness("12345");
    assert!(
        check_cp(&full, &forged).is_err(),
        "the full circuit rejects h = 12345"
    );
    assert!(
        check_cp(&reduced, &forged).is_err(),
        "the keyed (reduced) circuit must reject it too"
    );
}

#[test]
fn reduced_circuit_references_every_public_input() {
    let reduced = expand_function_blob_reduced(XBC).unwrap();
    for v in reduced
        .vars
        .iter()
        .filter(|v| v.role == xark_ir::primitive::VarRole::PublicInput)
    {
        assert!(
            reduced
                .constraints
                .iter()
                .flat_map(|r| [&r.a, &r.b, &r.c])
                .any(|lc| lc.terms.iter().any(|t| t.var == v.id)),
            "public input `{}` is unconstrained in the keyed circuit",
            v.name
        );
    }
}
