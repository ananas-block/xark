# Limitations

## Recoverable assertion errors

`require` and `require_eq` return `()`. When application Rust code runs
directly, a failed requirement panics. A surrounding
`Result<_, CircuitError>` does not convert that panic into an error. The
requirements also lack an argument for an application-specific error message.

This affects applications that execute their circuit logic to construct
transaction data before proving. In Zolana, that execution produces the checked
transaction used to construct shielded-pool program (SPP) proof inputs. Valid
inputs work, but a failed requirement interrupts construction instead of
returning a validation error.

### Application execution and witness generation

Executing the application's original Rust methods calls the native assertion
implementations in [intrinsics.rs](crates/lang/src/intrinsics.rs). Here, “native”
means ordinary Rust execution outside Xark's circuit compilation mode; the same
implementations can be compiled into an application's WASM module.

Xark's proving path evaluates the compiled witness program from `circuit.xbc`.
It does not call the application's original Rust methods. The solver and prover
have error-returning paths for witness failures and unsatisfied constraints.
Those paths do not make direct application execution recoverable.

### Catching panics on native hosts

On Rust hosts built with unwinding enabled, an application can use
`std::panic::catch_unwind` around the operation that constructs its proof inputs
and convert a caught panic into an application error. The operation must return
its completed output through that boundary; partially mutated transaction state
must be discarded on failure. Captured values must satisfy Rust's unwind-safety
requirements.

This is a possible application-level adapter, not a recovery mechanism currently
provided by Xark. It does not work with `panic = "abort"`. The panic hook runs
before a panic is caught, and the current equality failure message includes the
compared field values. Exposing that message can reveal private inputs.

Panic payloads are not structured validation errors. A broad catch also catches
unrelated application bugs, and parsing panic strings cannot reliably identify
which rule failed or restore the application's original assertion labels.

### Browser WASM

In the current browser WASM build, Rust panics abort execution and surface as a
WASM trap. Rust's `catch_unwind` cannot recover from these aborts. JavaScript can
catch the trap, but it cannot resume the Rust operation or obtain its unfinished
proof inputs. Reusing the instance after a panic is not a supported recovery
strategy: stack cleanup and Rust destructors may not have run.

Consequently, wrapping application execution in `catch_unwind` would address
native host failures but leave browser transaction construction without a
recoverable validation error.

### Direction for a complete solution

Add checked assertions that return structured errors during ordinary Rust
execution and lower to the corresponding enforced constraints during circuit
compilation. Preserve an application label and source location as diagnostic
metadata through witness generation and proving. Xark already records source
locations and exposes `CheckFailed` errors in some WASM paths, which provides a
starting point for consistent diagnostics.

Tests should cover recoverable native and browser failures, rejection of invalid
witnesses, and conditional checks. Changes intended to affect diagnostics alone
should preserve the mathematical constraints and proof encoding. Artifact bytes
may change when diagnostic metadata changes; circuit digests and proving-key
compatibility need explicit verification.

Witness-only regions are unsuitable for this recovery: their requirements are
not enforced as constraints. Application validation must retain its checks.
