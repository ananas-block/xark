//! Verify the `grumpkin_ipa_fold` circuit against a real, self-validated
//! `ark-grumpkin` Halo IPA transcript (n=4, k=2) whose Poseidon2 Fiat–Shamir
//! challenges were produced by the host `poseidon2` crate — KAT-identical to the
//! in-circuit `xark-poseidon2` gadget. Confirms: the circuit derives the same
//! challenges in-circuit, the fold + final IPA relation hold (accept), it's
//! analyzer-clean, a tampered transcript is rejected, and Groth16 verifies.

use std::path::Path;

use grumpkin_ipa_fold::GrumpkinIpaFoldInputs;

fn src() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")
}

// --- validated ark-grumpkin IPA transcript (see scratchpad `ipa.rs`) ---
const G0X: &str = "3078034153852398078128400807926804309327113743808504829582559963737223069694";
const G0Y: &str = "12696890884641142049456609402511852099066095483298083855939691685001536962732";
const G1X: &str = "18660890509582237958343981571981920822503400000196279471655180441138020044621";
const G1Y: &str = "8902249110305491597038405103722863701255802573786510474664632793109847672620";
const G2X: &str = "763947558912359675602353050994051190166418588022888764656343140671310115434";
const G2Y: &str = "1244893704640049169462398469384866579396698880516857177429128873187668729859";
const G3X: &str = "12229279139087521908560794489267966517139449915173592433539394009359081620359";
const G3Y: &str = "12096995292699515952722386974733884667125946823386040531322131902193094989869";
const UX: &str = "19868620912412181345668466222923426387494605076920370335460774735343299789752";
const UY: &str = "6059460531771770795655190242937417624731692114481337797941757599076835632520";
const PX: &str = "7262120032663357783654906393919160913111124567168699421301630859444327709541";
const PY: &str = "11155030046688321624273106377749056935412504513751886880294439874968220140598";
const L0X: &str = "5375487694808310702659162973823695341196693601475937153072891344179794880600";
const L0Y: &str = "7944815556999890941264774559535943707519717265897709639308240942984276847325";
const R0X: &str = "17034097151798272950285519022103253440012683113956019853678963310363407959531";
const R0Y: &str = "18529034907721181274925498681152838112266648732084001694074521268678278737501";
const X0INV_LO: &str = "22680322995267882538288038281662432166";
const X0INV_HI: &str = "113283149988673162651007931328977853114";
const L1X: &str = "1872918305289159651257036358108855396449892509458318319071404177563869713952";
const L1Y: &str = "2271021141447234717017625313274307644996847071030702732038489305273600737863";
const R1X: &str = "7835704774720879293142241306850648079782227543413187604842960141293422373118";
const R1Y: &str = "16930240884099899267128604087196418167932878781814926712675664728081976528106";
const X1INV_LO: &str = "114112989897027601752745677149678585070";
const X1INV_HI: &str = "120143048278880904150553374539496715209";
const S0LO: &str = "101347123743563917546956268938516812231";
const S0HI: &str = "116059811866484552728776788088143116719";
const S1LO: &str = "3737174836610366512887417732964775452";
const S1HI: &str = "62405511235622711844824004721254249746";
const S2LO: &str = "132824948574992135427287791523091904248";
const S2HI: &str = "23069863320759349988016793932704121578";
const S3LO: &str = "63674618799522023557137309721945942722";
const S3HI: &str = "112778294607876493459452263846670719498";
const ASTAR_LO: &str = "60432969165013805297498137096559625484";
const ASTAR_HI: &str = "41346699135982308264555816248439742743";
const C_LO: &str = "18374556530022161497450493908745285757";
const C_HI: &str = "69110116733184639059592971484944498067";

fn pt(x: &str, y: &str) -> [String; 2] {
    [x.into(), y.into()]
}

fn honest() -> GrumpkinIpaFoldInputs {
    GrumpkinIpaFoldInputs {
        g0: pt(G0X, G0Y),
        g1: pt(G1X, G1Y),
        g2: pt(G2X, G2Y),
        g3: pt(G3X, G3Y),
        u: pt(UX, UY),
        p: pt(PX, PY),
        l0: pt(L0X, L0Y),
        r0: pt(R0X, R0Y),
        l1: pt(L1X, L1Y),
        r1: pt(R1X, R1Y),
        x0inv_lo: X0INV_LO.into(),
        x0inv_hi: X0INV_HI.into(),
        x1inv_lo: X1INV_LO.into(),
        x1inv_hi: X1INV_HI.into(),
        s0_lo: S0LO.into(),
        s0_hi: S0HI.into(),
        s1_lo: S1LO.into(),
        s1_hi: S1HI.into(),
        s2_lo: S2LO.into(),
        s2_hi: S2HI.into(),
        s3_lo: S3LO.into(),
        s3_hi: S3HI.into(),
        astar_lo: ASTAR_LO.into(),
        astar_hi: ASTAR_HI.into(),
        c_lo: C_LO.into(),
        c_hi: C_HI.into(),
    }
}

#[test]
fn ipa_fold_verifies() {
    let circuit = xark_prover::circuit("grumpkin_ipa_fold");
    // satisfiable on the honest vector, with no under-constrained (forgeable)
    // witness variable.
    circuit.check_constrained(honest()).expect("grumpkin_ipa_fold must verify the honest IPA transcript");

    let mut bad = honest();
    bad.r0[0] = "123".into();
    assert!(circuit.check(bad).is_err(), "a tampered transcript must be rejected");
}

#[test]
fn report_constraint_count() {
    let c = xark_test_harness::compile_file(&src(), "grumpkin_ipa_fold", "bn254");
    assert!(c.status_success, "{}", c.stderr);
    let n = c.minimized_r1cs_len();
    println!("grumpkin_ipa_fold (n=4 IPA, in-circuit Poseidon2 FS): {n} minimized R1CS constraints");
    assert!(n < 120_000, "unexpectedly large: {n}");
}

#[test]
fn groth16_setup_prove_verify() {
    // solve → dev-mode Groth16 setup → prove → verify, on the built circuit.
    xark_prover::circuit("grumpkin_ipa_fold")
        .prove(honest())
        .expect("the Groth16 proof must verify");
}
