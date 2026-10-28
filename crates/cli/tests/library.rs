use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use xark_cli::{QapDomain, SetupOptions};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "xark-library-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn failures_return_to_host_with_unrelated_process_arguments() -> Result<()> {
    const CHILD: &str = "XARK_LIBRARY_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let temp = TempDir::new()?;
        let missing = temp.0.join("missing");
        let output = temp.0.join("out");
        assert!(xark_cli::build(&missing, &output).is_err());
        assert!(xark_cli::setup(&missing, SetupOptions::default()).is_err());
        assert!(xark_cli::client(&missing, &output, true).is_err());
        println!("returned to host after all failures");
        return Ok(());
    }

    // These are test-harness arguments, deliberately unrelated to xark's CLI.
    let child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "failures_return_to_host_with_unrelated_process_arguments",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()?;
    assert!(child.status.success(), "{child:?}");
    assert!(String::from_utf8_lossy(&child.stdout).contains("returned to host after all failures"));
    Ok(())
}

#[test]
fn build_setup_and_client_use_the_same_artifacts() -> Result<()> {
    let temp = TempDir::new()?;
    let circuit = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/cube");
    let artifacts = temp.0.join("artifacts");
    xark_cli::build(&circuit, &artifacts)?;
    let schema: serde_json::Value =
        serde_json::from_slice(&std::fs::read(artifacts.join("schema.json"))?)?;
    assert_eq!(schema["circuit"], "cube");

    let options = SetupOptions {
        insecure_dev_mode: true,
        deterministic_rng: Some(0),
        domain: QapDomain::Radix2,
        ..Default::default()
    };
    xark_cli::setup(&artifacts, options)?;
    let (proving_key, verifying_key) = (
        std::fs::read(artifacts.join("pk.bin"))?,
        std::fs::read(artifacts.join("vk.bin"))?,
    );
    assert!(!proving_key.is_empty() && !verifying_key.is_empty());

    let pk = artifacts.join("pk.bin");
    let vk = artifacts.join("vk.bin");
    assert!(xark_cli::keys_match(&pk, &vk)?);

    let invalid_pk = temp.0.join("invalid-pk.bin");
    std::fs::write(&invalid_pk, &proving_key[..proving_key.len() - 1])?;
    assert!(!xark_cli::keys_match(&invalid_pk, &vk)?);
    let mut trailing_pk = proving_key;
    trailing_pk.push(0);
    std::fs::write(&invalid_pk, trailing_pk)?;
    assert!(!xark_cli::keys_match(&invalid_pk, &vk)?);

    let invalid_vk = temp.0.join("invalid-vk.bin");
    std::fs::write(&invalid_vk, &verifying_key[..verifying_key.len() - 1])?;
    assert!(xark_cli::keys_match(&pk, &invalid_vk).is_err());
    let mut trailing_vk = verifying_key;
    trailing_vk.push(0);
    std::fs::write(&invalid_vk, trailing_vk)?;
    assert!(!xark_cli::keys_match(&pk, &invalid_vk)?);

    let other_keys = temp.0.join("other-keys");
    xark_cli::setup(
        &artifacts,
        SetupOptions {
            out: Some(other_keys.clone()),
            insecure_dev_mode: true,
            deterministic_rng: Some(1),
            domain: QapDomain::Radix2,
            ..Default::default()
        },
    )?;
    assert!(!xark_cli::keys_match(&pk, &other_keys.join("vk.bin"))?);

    let client = temp.0.join("cube.ts");
    xark_cli::client(&artifacts, &client, true)?;
    let generated = std::fs::read_to_string(client)?;
    assert!(
        generated.contains("Cube"),
        "missing generated circuit client"
    );
    assert!(temp.0.join("cube.schema.ts").is_file());
    Ok(())
}
