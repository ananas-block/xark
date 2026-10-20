//! Everyday input types with a natural form on both sides: a [`Date`], a short
//! [`Text`], and a [`Bitfield`] of named [`Flags`]. Each is one `Field` in the circuit
//! and its plain value off it (`Date::new(1990, 1, 1)` in Rust, a JS `Date` in a
//! generated client), with the encoding recorded in `schema.json`.

use core::cmp::Ordering;
use core::marker::PhantomData;

use crate::lang::{Field, require, require_eq};

// ---- Date ---------------------------------------------------------------------

/// `YYYYMMDD ≤ 99_991_231 < 2²⁷`: the comparison width for any date.
const DATE_BITS: usize = 27;

/// A calendar date, packed as the integer `YYYYMMDD` in one `Field`, compared as
/// such: `require(id.born < cutoff)`. Each comparison range-checks both sides to 27
/// bits (a few dozen constraints).
///
/// Built off-circuit from calendar parts, checked ([`Date::new`] refuses 30 February),
/// or from `"YYYY-MM-DD"`. Validity isn't re-checked in the circuit: a date input is
/// one a trusted party fixed (an issuer's commitment, a verifier's public input). The
/// unchecked [`Date::from_raw`] is for sentinels such as "any date of birth".
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Date(Field);

/// Days in `month` of `year` (proleptic Gregorian).
const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        2 if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl Date {
    /// A real calendar day, checked: a bad literal in a `const` is a compile error,
    /// at run time a panic.
    pub const fn new(year: u16, month: u8, day: u8) -> Date {
        assert!(year <= 9999, "year must be 0..=9999");
        assert!(month >= 1 && month <= 12, "month must be 1..=12");
        assert!(
            day >= 1 && day <= days_in_month(year, month),
            "no such day in that month"
        );
        Date(Field::from_u64(
            year as u64 * 10_000 + month as u64 * 100 + day as u64,
        ))
    }

    /// The raw integer `YYYYMMDD`, unchecked: for sentinels that aren't calendar days
    /// (`Date::from_raw(99_999_999)`: after every date).
    pub const fn from_raw(yyyymmdd: u32) -> Date {
        Date(Field::from_u64(yyyymmdd as u64))
    }

    /// The date's `Field` (`YYYYMMDD`).
    pub const fn field(self) -> Field {
        self.0
    }
}

/// `<`, `<=`, `>`, `>=` between dates: a `{0, 1}` circuit wire, both sides range-checked
/// to 27 bits. (`==` is [`require_eq`] on [`Date::field`].)
impl PartialOrd for Date {
    // Never reached: the comparison operators below are overridden.
    fn partial_cmp(&self, _: &Date) -> Option<Ordering> {
        crate::intrinsics::__xark_marker()
    }
    fn lt(&self, other: &Date) -> bool {
        self.0.lt::<DATE_BITS>(other.0)
    }
    fn le(&self, other: &Date) -> bool {
        self.0.le::<DATE_BITS>(other.0)
    }
    fn gt(&self, other: &Date) -> bool {
        self.0.gt::<DATE_BITS>(other.0)
    }
    fn ge(&self, other: &Date) -> bool {
        self.0.ge::<DATE_BITS>(other.0)
    }
}

/// Circuit equality (see `Field`'s `PartialEq`); with `PartialOrd`, dates compare with
/// every operator.
impl PartialEq for Date {
    fn eq(&self, other: &Date) -> bool {
        self.0 == other.0
    }
}

// ---- Text ---------------------------------------------------------------------

/// Up to 31 bytes of UTF-8 (a document number, a ticker), packed little-endian into
/// one `Field`: `Text::new("A1938274")`. Compared and hashed as that field.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Text(Field);

impl Text {
    /// The string's bytes, little-endian. Panics past 31 bytes.
    pub const fn new(s: &str) -> Text {
        assert!(
            s.len() <= 31,
            "text longer than 31 bytes doesn't fit a field"
        );
        Text(Field::from_le_bytes(s.as_bytes()))
    }

    /// The text's `Field`.
    pub const fn field(self) -> Field {
        self.0
    }
}

// ---- Bitfield -------------------------------------------------------------------

/// A fixed set of named flags, each a bit of a [`Bitfield`]: declare one with
/// [`flags!`](crate::flags). Append only: a flag's position is its bit.
pub trait Flags: Copy {
    /// Every flag's name, in bit order.
    const NAMES: &'static [&'static str];
    /// The bitfield's `schema.json` type name (`Bitfield<Country>`).
    const SET: &'static str;
    /// The bitfield's `schema.json` encoding (the flag names).
    const ENCODING: &'static str;
    /// This flag's bit.
    fn bit(self) -> usize;
}

/// Declare a set of named flags for a [`Bitfield`]: an enum whose variants are bits
/// `0, 1, …` in order (at most 253: one `Field`). Append only, never reorder: a
/// variant's position is its bit in every stored value.
///
/// ```ignore
/// xark::flags! {
///     /// ISO 3166-1 alpha-2 countries.
///     pub enum Country { AD, AE, AF, /* … */ }
/// }
/// ```
#[macro_export]
macro_rules! flags {
    ($(#[$m:meta])* $vis:vis enum $name:ident { $($(#[$vm:meta])* $v:ident),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[repr(u8)]
        $vis enum $name {
            $($(#[$vm])* $v),+
        }
        impl $crate::Flags for $name {
            const NAMES: &'static [&'static str] = &[$(stringify!($v)),+];
            const SET: &'static str = concat!("Bitfield<", stringify!($name), ">");
            const ENCODING: &'static str = concat!(
                "{\"flags\":\"", stringify!($name), "\",\"names\":\"", $(stringify!($v), ",",)+ "\"}"
            );
            fn bit(self) -> usize {
                const { assert!(<$name as $crate::Flags>::NAMES.len() <= 253, "at most 253 flags") };
                self as usize
            }
        }
    };
}

/// A set of [`Flags`] in one `Field` (bit `i` = flag `i`): a holder's nationality, a
/// verifier's allow-list. Off-circuit it's built from flags (`Bitfield::of([US, GB])`,
/// `Country::US.into()`); a generated client takes `"US"` or `["US", "GB"]`.
///
/// In the circuit, each check decomposes the value into its bits (253 constraints) and
/// proves no bit outside the flags is set, so a value can't name a flag that isn't
/// declared.
pub struct Bitfield<F: Flags>(Field, PhantomData<F>);

impl<F: Flags> Clone for Bitfield<F> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<F: Flags> Copy for Bitfield<F> {}

impl<F: Flags> Bitfield<F> {
    /// The value's bits, with every bit past the declared flags constrained to zero.
    fn bits(self) -> [Field; 253] {
        let bits = self.0.to_bits::<253>();
        let mut i = F::NAMES.len();
        while i < 253 {
            require_eq(bits[i], Field::from_u8(0));
            i += 1;
        }
        bits
    }

    /// Constrain exactly one flag to be set (a one-hot value: one nationality).
    pub fn require_single(self) {
        let bits = self.bits();
        let mut n = Field::from_u8(0);
        let mut i = 0;
        while i < F::NAMES.len() {
            n += bits[i];
            i += 1;
        }
        require_eq(n, Field::from_u8(1));
    }

    /// Constrain exactly one flag to be set, and that one to be in `allowed` (a holder's
    /// one nationality against an allow-list: 2 × 253 constraints, plus one per flag).
    pub fn require_one_of(self, allowed: Bitfield<F>) {
        let (c, a) = (self.bits(), allowed.bits());
        let (mut hot, mut hit) = (Field::from_u8(0), Field::from_u8(0));
        let mut i = 0;
        while i < F::NAMES.len() {
            hot += c[i];
            hit += c[i] * a[i];
            i += 1;
        }
        require_eq(hot, Field::from_u8(1)); // exactly one flag
        require_eq(hit, Field::from_u8(1)); // and it is allowed
    }

    /// Constrain every flag set in `self` to be set in `other` too.
    pub fn require_subset_of(self, other: Bitfield<F>) {
        let (a, b) = (self.bits(), other.bits());
        let mut i = 0;
        while i < F::NAMES.len() {
            require_eq(a[i] * b[i], a[i]); // a ⇒ b
            i += 1;
        }
    }

    /// Whether `flag` is set: a `{0, 1}` circuit wire.
    pub fn contains(self, flag: F) -> bool {
        !self.bits()[flag.bit()].is_zero()
    }

    /// Constrain `flag` to be set.
    pub fn require_contains(self, flag: F) {
        require(self.contains(flag));
    }

    /// The set's `Field`.
    pub const fn field(self) -> Field {
        self.0
    }
}

// ---- shared: flattening, circuit input binding, host side -------------------------

macro_rules! newtype_common {
    ($t:ident $(<$g:ident: $b:ident>)?, $name:expr, $enc:expr) => {
        impl$(<$g: $b>)? crate::ToFields for $t$(<$g>)? {
            const FIELD_LEN: usize = 1;
            fn write_fields(&self, out: &mut [Field]) {
                out[0] = self.0;
            }
        }

        /// A circuit input: one leaf at the parameter's own path, its type and natural
        /// encoding recorded for `schema.json`.
        #[cfg(all(xark, target_arch = "wasm32"))]
        impl$(<$g: $b>)? crate::wasm::Input for $t$(<$g>)? {
            fn input(n: &mut crate::wasm::NameBuf, vis: u32) -> Self {
                crate::wasm::input_struct(n, $name);
                crate::wasm::input_encoding($name, $enc);
                Self::wrap(<Field as crate::wasm::Input>::input(n, vis))
            }
        }

        #[cfg(not(xark))]
        impl$(<$g: $b>)? xark_prover::NativeInput for $t$(<$g>)? {
            fn leaves(value: &Self, prefix: &str) -> alloc::vec::Vec<(alloc::string::String, xark_prover::Fr)> {
                alloc::vec![(alloc::string::String::from(prefix), value.0.into())]
            }
        }
    };
}

impl Date {
    #[cfg_attr(not(all(xark, target_arch = "wasm32")), allow(dead_code))]
    fn wrap(f: Field) -> Self {
        Date(f)
    }
}
impl Text {
    #[cfg_attr(not(all(xark, target_arch = "wasm32")), allow(dead_code))]
    fn wrap(f: Field) -> Self {
        Text(f)
    }
}
impl<F: Flags> Bitfield<F> {
    #[cfg_attr(not(all(xark, target_arch = "wasm32")), allow(dead_code))]
    fn wrap(f: Field) -> Self {
        Bitfield(f, PhantomData)
    }
}

newtype_common!(Date, "Date", "{\"date\":\"yyyymmdd\"}");
newtype_common!(Text, "Text", "{\"text\":31}");
newtype_common!(Bitfield<F: Flags>, F::SET, F::ENCODING);

// In the circuit build `Debug` only has to exist (a derived `Debug` on a struct of
// these compiles there too); the host's renders the value.
#[cfg(xark)]
mod circuit_debug {
    use core::fmt;

    use super::*;

    impl fmt::Debug for Date {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Date({:?})", self.0)
        }
    }
    impl fmt::Debug for Text {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Text({:?})", self.0)
        }
    }
    impl<F: Flags> fmt::Debug for Bitfield<F> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Bitfield({:?})", self.0)
        }
    }
}

#[cfg(not(xark))]
mod host {
    use alloc::string::String;
    use core::fmt;

    use super::*;

    impl Date {
        /// The calendar parts `(year, month, day)`.
        pub fn parts(self) -> (u16, u8, u8) {
            let v: u64 = self.0.to_decimal().parse().unwrap_or(0);
            ((v / 10_000) as u16, (v / 100 % 100) as u8, (v % 100) as u8)
        }
    }

    /// `"YYYY-MM-DD"` (or `"YYYYMMDD"`), checked like [`Date::new`]. Panics otherwise.
    impl From<&str> for Date {
        fn from(s: &str) -> Date {
            let d: String = s.chars().filter(|c| *c != '-').collect();
            let n = |r: core::ops::Range<usize>| -> u32 {
                d.get(r)
                    .and_then(|x| x.parse().ok())
                    .unwrap_or_else(|| panic!("`{s}` is not a YYYY-MM-DD date"))
            };
            assert!(d.len() == 8, "`{s}` is not a YYYY-MM-DD date");
            Date::new(n(0..4) as u16, n(4..6) as u8, n(6..8) as u8)
        }
    }

    impl From<(u16, u8, u8)> for Date {
        fn from((y, m, d): (u16, u8, u8)) -> Date {
            Date::new(y, m, d)
        }
    }

    impl fmt::Debug for Date {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let (y, m, d) = self.parts();
            write!(f, "Date({y:04}-{m:02}-{d:02})")
        }
    }

    impl From<&str> for Text {
        fn from(s: &str) -> Text {
            Text::new(s)
        }
    }

    impl From<String> for Text {
        fn from(s: String) -> Text {
            Text::new(&s)
        }
    }

    impl fmt::Debug for Text {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let b = le_bytes(self.0);
            let n = b.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
            write!(f, "Text({:?})", String::from_utf8_lossy(&b[..n]))
        }
    }

    /// A constant `Field`'s 32 little-endian bytes.
    fn le_bytes(f: Field) -> [u8; 32] {
        use ark_ff::{BigInteger, PrimeField};
        let fr: ark_bn254::Fr = f.into();
        let mut b = [0u8; 32];
        b.copy_from_slice(&fr.into_bigint().to_bytes_le());
        b
    }

    impl<F: Flags> Bitfield<F> {
        /// No flags set.
        pub fn empty() -> Self {
            Bitfield(Field::from_u8(0), PhantomData)
        }
        /// Every flag set (an allow-list that allows everything).
        pub fn all() -> Self {
            Self::from_bits((0..F::NAMES.len()).map(Some))
        }
        /// These flags set.
        pub fn of(flags: impl IntoIterator<Item = F>) -> Self {
            Self::from_bits(flags.into_iter().map(|f| Some(f.bit())))
        }
        /// The flags set, in bit order.
        pub fn names(self) -> alloc::vec::Vec<&'static str> {
            let b = le_bytes(self.0);
            (0..F::NAMES.len())
                .filter(|&i| b[i / 8] >> (i % 8) & 1 == 1)
                .map(|i| F::NAMES[i])
                .collect()
        }
        fn from_bits(bits: impl Iterator<Item = Option<usize>>) -> Self {
            let mut b = [0u8; 32];
            for i in bits.flatten() {
                b[i / 8] |= 1 << (i % 8);
            }
            Bitfield(Field::from_le_bytes(&b), PhantomData)
        }
    }

    impl<F: Flags> From<F> for Bitfield<F> {
        fn from(flag: F) -> Self {
            Self::of([flag])
        }
    }

    impl<F: Flags, const N: usize> From<[F; N]> for Bitfield<F> {
        fn from(flags: [F; N]) -> Self {
            Self::of(flags)
        }
    }

    impl<F: Flags> fmt::Debug for Bitfield<F> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Bitfield{:?}", self.names())
        }
    }
}

#[cfg(all(test, not(xark)))]
mod tests {
    use super::*;

    crate::flags! {
        enum Color { Red, Green, Blue }
    }

    #[test]
    fn dates() {
        assert_eq!(Date::new(1990, 1, 1).field().to_decimal(), "19900101");
        assert_eq!(Date::from("2024-02-29").parts(), (2024, 2, 29));
        assert_eq!(
            alloc::format!("{:?}", Date::from("20261005")),
            "Date(2026-10-05)"
        );
    }

    #[test]
    #[should_panic(expected = "no such day")]
    fn february_30_is_refused() {
        let _ = Date::new(2023, 2, 29);
    }

    #[test]
    fn text_and_flags() {
        assert_eq!(
            alloc::format!("{:?}", Text::from("A1938274")),
            "Text(\"A1938274\")"
        );
        let s = Bitfield::of([Color::Red, Color::Blue]);
        assert_eq!(s.field().to_decimal(), "5");
        assert_eq!(s.names(), ["Red", "Blue"]);
        assert_eq!(Bitfield::from(Color::Green).field().to_decimal(), "2");
        assert_eq!(Bitfield::<Color>::all().names().len(), 3);
        assert_eq!(
            <Color as Flags>::ENCODING,
            r#"{"flags":"Color","names":"Red,Green,Blue,"}"#
        );
        assert_eq!(<Color as Flags>::SET, "Bitfield<Color>");
    }
}
