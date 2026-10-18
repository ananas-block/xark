//! Verify the `grumpkin_ipa` deferred-MSM accumulator circuit against an
//! independent `ark-grumpkin` reference vector (`Q = Σⱼ sⱼ·Gⱼ`, full-width
//! ~253-bit scalars split into 127-bit limbs). Confirms: (1) the emitted R1CS is
//! satisfiable on the honest vector, (2) it is analyzer-clean (no forgeable
//! derived vars), (3) a wrong claimed `Q` is rejected, and (4) reports the
//! minimized constraint count — the efficiency evidence.

use std::path::Path;

use grumpkin_ipa::GrumpkinIpaInputs;

fn src() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")
}

// --- ark-grumpkin reference vector (validated: same routine reproduces the
//     gadget's corr₁₂₈ exactly). Q = Σⱼ sⱼ·Gⱼ, sⱼ = loⱼ + hiⱼ·2^127. ---
const G0X: &str = "3078034153852398078128400807926804309327113743808504829582559963737223069694";
const G0Y: &str = "12696890884641142049456609402511852099066095483298083855939691685001536962732";
const S0LO: &str = "60084397167073555162083361513403522487";
const S0HI: &str = "36088648481254637903101376313178913327";
const G1X: &str = "18660890509582237958343981571981920822503400000196279471655180441138020044621";
const G1Y: &str = "8902249110305491597038405103722863701255802573786510474664632793109847672620";
const S1LO: &str = "97605276812866110489057805785336271852";
const S1HI: &str = "69103295295569534943010654047256774201";
const G2X: &str = "763947558912359675602353050994051190166418588022888764656343140671310115434";
const G2Y: &str = "1244893704640049169462398469384866579396698880516857177429128873187668729859";
const S2LO: &str = "44598705996698807541652267929952945441";
const S2HI: &str = "4463001242034982868263207590522768002";
const G3X: &str = "12229279139087521908560794489267966517139449915173592433539394009359081620359";
const G3Y: &str = "12096995292699515952722386974733884667125946823386040531322131902193094989869";
const S3LO: &str = "167338704812101959590156073396584628054";
const S3HI: &str = "35439497807825386909150426018507431884";
const QX: &str = "20903080311600324333489123549926276227734645934862144969632742816704833802883";
const QY: &str = "21415318633544108147494823273278274647092448118324172091757610792088028377648";

fn pt(x: &str, y: &str) -> [String; 2] {
    [x.into(), y.into()]
}

fn honest() -> GrumpkinIpaInputs {
    GrumpkinIpaInputs {
        g0: pt(G0X, G0Y),
        g1: pt(G1X, G1Y),
        g2: pt(G2X, G2Y),
        g3: pt(G3X, G3Y),
        s0_lo: S0LO.into(),
        s0_hi: S0HI.into(),
        s1_lo: S1LO.into(),
        s1_hi: S1HI.into(),
        s2_lo: S2LO.into(),
        s2_hi: S2HI.into(),
        s3_lo: S3LO.into(),
        s3_hi: S3HI.into(),
        q: pt(QX, QY),
    }
}

#[test]
fn deferred_msm_accumulator_verifies() {
    let circuit = xark_prover::circuit("grumpkin_ipa");
    // satisfiable on the honest vector, with no under-constrained (forgeable)
    // witness variable.
    circuit.check_constrained(honest()).expect("grumpkin_ipa must verify on the reference accumulator vector");

    let mut bad = honest();
    bad.q[0] = "123".into();
    assert!(circuit.check(bad).is_err(), "a wrong claimed Q must be rejected");
}

#[test]
fn report_constraint_count() {
    let c = xark_test_harness::compile_file(&src(), "grumpkin_ipa", "bn254");
    assert!(c.status_success, "{}", c.stderr);
    let n = c.minimized_r1cs_len();
    println!("grumpkin_ipa (n=4 deferred MSM, 254-bit scalars): {n} minimized R1CS constraints");
    // sanity envelope: native Grumpkin keeps this in the low tens of thousands.
    assert!(n < 60_000, "unexpectedly large: {n}");
}

#[test]
fn groth16_setup_prove_verify() {
    // solve → dev-mode Groth16 setup → prove → verify, on the built circuit.
    xark_prover::circuit("grumpkin_ipa")
        .prove(honest())
        .expect("the Groth16 proof must verify");
}
