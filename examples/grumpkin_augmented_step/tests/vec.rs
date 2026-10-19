//! Verify the augmented step circuit `F'` against the host reference
//! (`ark-grumpkin` + host `poseidon2`). The circuit re-derives the fold + both
//! IO hashes in-circuit and checks `io_in`/`io_out`. Accept / analyzer-clean /
//! tamper-reject (wrong output state) / constraint count / Groth16.

use std::path::Path;

use grumpkin_augmented_step::GrumpkinAugmentedStepInputs;

fn src() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")
}

// host reference (scratchpad/reference `augmented`), step 0, F(z)=z²+5, z:3->14.
const IO_IN: &str = "19907833986718335647518476905173400024903380676282260977664490893668197328880";
const IO_OUT: &str = "18455067260797647450241762189385044412093293481241569654248316453283960629055";
const Z0: &str = "3";
const ZI: &str = "3";
const UI_CWX: &str = "5541057644303065254198978319021299963813613025890967735191946958170803635963";
const UI_CWY: &str = "1090039197710617384995251408449123883585777313183467283953051925104608545894";
const UI_CEX: &str = "4850035816089662575584531767234751057843073514516729038085564438359968988824";
const UI_CEY: &str = "14505663385114841392403642611656212825504921992342703259189393607313084956304";
const UI_U: &str = "7";
const UI_X: &str = "13";
const S_CWX: &str = "2689464466883345466870406516192131206798867494563174663401373503616308486522";
const S_CWY: &str = "14284470724459285329583671672346501634471412747554954445898157584469342023256";
const S_CEX: &str = "17139003749319088366501156891546301999505258967247129491939947605044679468675";
const S_CEY: &str = "16801526290712393585817395843048980845538227969954237825544784234576984878296";
const S_U: &str = "1";
const S_X: &str = "5";
const TX: &str = "17379784669106027629420386012926013711889290282791045264368570596918799018333";
const TY: &str = "5261888182127316643551963109191000327408457967043340449287656632743840125850";

fn pt(x: &str, y: &str) -> [String; 2] {
    [x.into(), y.into()]
}

fn honest() -> GrumpkinAugmentedStepInputs {
    GrumpkinAugmentedStepInputs {
        io_in: IO_IN.into(),
        io_out: IO_OUT.into(),
        i: "0".into(),
        z0: Z0.into(),
        zi: ZI.into(),
        ui_cw: pt(UI_CWX, UI_CWY),
        ui_ce: pt(UI_CEX, UI_CEY),
        ui_u: UI_U.into(),
        ui_x: UI_X.into(),
        s_cw: pt(S_CWX, S_CWY),
        s_ce: pt(S_CEX, S_CEY),
        s_u: S_U.into(),
        s_x: S_X.into(),
        t: pt(TX, TY),
    }
}

#[test]
fn augmented_step_verifies() {
    let circuit = xark_prover::circuit("grumpkin_augmented_step");
    // satisfiable on the honest vector, with no under-constrained (forgeable)
    // witness variable.
    circuit.check_constrained(honest()).expect("augmented step must verify the honest reference");

    let mut bad = honest();
    bad.io_out = "123".into();
    assert!(circuit.check(bad).is_err(), "wrong io_out must reject");
}

#[test]
fn report_constraint_count() {
    let c = xark_test_harness::compile_file(&src(), "grumpkin_augmented_step", "bn254");
    assert!(c.status_success, "{}", c.stderr);
    let n = c.minimized_r1cs_len();
    println!("grumpkin_augmented_step (Nova F' + Poseidon2 IO compression): {n} minimized R1CS constraints");
    assert!(n < 60_000, "unexpectedly large: {n}");
}

#[test]
fn groth16_setup_prove_verify() {
    // solve → dev-mode Groth16 setup → prove → verify, on the built circuit.
    xark_prover::circuit("grumpkin_augmented_step")
        .prove_dev(honest())
        .expect("the Groth16 proof must verify");
}
