//! `xark`: the standard prelude (`use xark::prelude::*`) for writing zero-knowledge
//! programs in the `xark` Rust subset. A circuit is an ordinary `#![no_std]` Rust
//! function over [`Field`] values; the toolchain compiles it end to end (rustc →
//! wasm32 → xark-IR → R1CS → Groth16) with no per-gadget backend support — gadgets are
//! ordinary frontend library code lowering to the same primitive constraint set.
//!
//! ```rust,ignore
//! #![no_std]
//! use xark::prelude::*;
//!
//! /// Prove knowledge of a cube root: `secret^3 == result`.
//! pub fn circuit(secret: Private<Field>, result: Public<Field>) {
//!     require_eq(secret ^ 3, result);
//! }
//! ```
//!
//! [`Private<T>`]/[`Public<T>`] are transparent aliases the compiler recovers from
//! the signature; [`require_eq`] emits an equality constraint (circuit `==`, not
//! native `bool`); `Field` supports `+ - * ^` (`^ n` = exponentiation). Lower-level
//! bit/word helpers (`xark-bits`) and gadgets (`xark-bignum`, `xark-poseidon`, …)
//! are separate crates.

#![no_std]

// `Field::to_decimal` (host-side input tooling) allocates a `String`. `alloc` links
// in both builds; the allocation only ever runs host-side, never in a circuit.
extern crate alloc;

// Self-alias so the `#[derive(CircuitInput)]` macro's generated `::xark::Field`
// paths resolve *inside* this crate (where the derive is used on `Digest`), the
// same way they resolve in downstream circuit crates. Standard proc-macro pattern.
extern crate self as xark;

/// The `xark` language markers: `Field`, `Private`, `Public`, `require_eq`, the
/// `Field` methods and operator impls, and the recognized intrinsics.
pub mod lang;

/// Everyday input types: [`Date`], [`Text`], [`Bitfield`] (of [`flags!`] flags).
pub mod types;
pub use types::{Bitfield, Date, Flags, Text};

/// The compiler intrinsics — `#[inline(never)]` functions that, in the circuit
/// build, call the frontend's `xark.*` wasm imports (the `Field` operator/hint ABI). See the module doc
/// for the constraint-vs-hint distinction. `lang.rs` calls these to back its
/// `Field` impls; circuit authors use the `Field` methods, not these directly.
pub mod intrinsics;

/// The stable-frontend circuit build (`--cfg xark` on `wasm32`): the `xark.*` imports
/// the intrinsics call, input binding for the `#[circuit]` entry, and the runtime.
#[cfg(all(xark, target_arch = "wasm32"))]
#[doc(hidden)]
pub mod wasm;

/// The everyday circuit-author surface. `use xark::prelude::*;`.
pub mod prelude {
    pub use crate::lang::{
        Field, Private, Public, require, require_eq, require_ge, require_gt, require_le,
        require_lt, require_ne, witness_begin, witness_end,
    };
    // `CircuitInput` makes a `Field`-composed struct a circuit input (the everyday way to
    // group inputs); `circuit` is the entry attribute.
    pub use crate::types::{Bitfield, Date, Flags, Text};
    pub use xark_macros::{CircuitInput, circuit};
}

// Same surface as `prelude`, re-exported at the crate root so both
// `use xark::prelude::*;` and `use xark::{require, Field, ...};` work.
pub use crate::lang::{
    Field, Private, Public, require, require_eq, require_ge, require_gt, require_le, require_lt,
    require_ne, witness_begin, witness_end,
};
// `require_eq` dispatches through `RequireEqCircuit`, comparing scalars, fixed
// arrays, and composite types; downstream crates impl it for their own shapes.
pub use crate::lang::RequireEqCircuit;
// A circuit input type's `Field` leaves: derived structs and gadget input types.
pub use crate::lang::ToFields;

/// The natural encoding length of a value held in `limbs` × `bits`-bit limbs: 32
/// bytes for a field-sized value (up to 264 bits of limbs, e.g. 3 × 86: the value
/// itself is below 2²⁵⁶), else the limbs' bits rounded up to bytes.
#[doc(hidden)]
pub const fn natural_bytes(limbs: usize, bits: usize) -> usize {
    if limbs * bits <= 264 {
        32
    } else {
        (limbs * bits).div_ceil(8)
    }
}
/// The host-side prover: load a built circuit and `check` / `prove` inputs
/// against it (`xark::prover::circuit("name").prove(inputs)`). Host builds only.
#[cfg(not(xark))]
pub use xark_prover as prover;
// Host-side helpers for building input values (gadgets' `From` impls, derives).
#[cfg(not(xark))]
#[doc(hidden)]
pub mod host;
#[doc(hidden)]
pub use crate::lang::bytes_to_fields;
// The recognized scalar-equality intrinsic every `RequireEqCircuit` impl bottoms
// out at — re-exported (doc-hidden) so the compiler's intrinsic scan finds it by
// name. Authors never touch it; they write `require_eq`.
#[doc(hidden)]
pub use crate::lang::__xark_require_eq_scalar;
// `#[derive(CircuitInput)]` makes a `Field`-composed struct a circuit input: it
// generates the `Into<[Field; N]>` flatten AND the host-side `NativeInput` fan-out
// (`Native = Self`, each field rendered via `Field::to_decimal`) — so the host builds
// the same struct with `Field` values, no `String` mirror. `#[derive(Transparent)]`
// does the same for a byte-backed gadget type (`limbs`/native-bytes form).
pub use xark_macros::{CircuitInput, Transparent, circuit};
