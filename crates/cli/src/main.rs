//! `xark`: the standalone toolchain CLI.

// Circuit loading makes millions of small allocations across rayon threads.
// Keep this allocator choice in the binary, so embedders choose their own.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let code = match xark_cli::run_cli() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            1
        }
    };
    std::process::exit(code);
}
