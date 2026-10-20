//! Zero-knowledge KYC: prove an identity an issuer committed to meets a verifier's
//! policy (old enough, wealthy enough, document still valid, nationality allowed)
//! without revealing it. The identity stays private; the commitment and the policy
//! are public, so a verifier picks the rules at proof time with no new circuit.
#![cfg_attr(xark, no_std)]

use xark::prelude::*;

/// What an issuer attests about a holder, committed to as a whole with Poseidon2.
#[derive(Clone, Copy, Debug, Input)]
pub struct Identity {
    /// The ID document's number.
    pub document: Text,
    pub born: Date,
    /// Exactly one country (an ISO 3166 code, `xark::Country`).
    pub nationality: Bitfield<Country>,
    /// Attested net worth, in whole USD.
    pub net_worth: u64,
    /// The ID document's expiry.
    pub expires: Date,
    /// The issuer's random blinding secret: it hides the commitment.
    pub salt: Field,
}

impl Identity {
    /// The issuer's commitment: Poseidon2 over every field, so adding one extends it.
    pub fn commitment(&self) -> Field {
        xark_poseidon2::hash(self.to_fields())
    }
}

/// `id` is the identity the issuer committed to as `commitment`, born before
/// `born_before`, worth at least `min_net_worth`, with a document valid on `today`
/// and a nationality in `allowed`. To switch a check off, pass a value every identity
/// meets (`Date::from_raw(99_999_999)`, `0`, `Date::from_raw(0)`, `Bitfield::all()`).
#[circuit]
pub fn zk_kyc(
    id: Private<Identity>,
    commitment: Public<Field>,
    born_before: Public<Date>,
    min_net_worth: Public<u64>,
    today: Public<Date>,
    allowed: Public<Bitfield<Country>>,
) {
    require_eq(id.commitment(), commitment);
    require(id.born < born_before);
    require(id.net_worth >= min_net_worth);
    require(id.expires >= today);
    id.nationality.require_one_of(allowed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use Country::*;

    fn holder(nationality: Country, born: &str, net_worth: u64, expires: &str) -> Identity {
        Identity {
            document: "A1938274".into(),
            born: born.into(),
            nationality: nationality.into(),
            net_worth,
            expires: expires.into(),
            salt: Field::from_le_bytes(&[0x13; 31]),
        }
    }

    /// Born before 2008-10-20, worth ≥ 500k, valid on 2026-10-20, from US/GB/FR/DE.
    fn check(id: Identity) -> Result<(), xark::prover::ProveError> {
        zk_kyc(
            id,
            id.commitment(),
            "2008-10-20",
            500_000,
            "2026-10-20",
            [US, GB, FR, DE],
        )
    }

    #[test]
    fn accepts_a_compliant_holder() {
        check(holder(US, "1990-01-01", 1_000_000, "2030-01-01")).unwrap();
        check(holder(GB, "1990-01-01", 500_000, "2026-10-20")).unwrap(); // both limits inclusive
    }

    #[test]
    fn rejects_each_failed_check() {
        assert!(check(holder(KP, "1990-01-01", 1_000_000, "2030-01-01")).is_err());
        assert!(check(holder(US, "2010-01-01", 1_000_000, "2030-01-01")).is_err());
        assert!(check(holder(US, "1990-01-01", 100, "2030-01-01")).is_err());
        assert!(check(holder(US, "1990-01-01", 1_000_000, "2026-10-19")).is_err());
    }

    #[test]
    fn rejects_two_nationalities_and_a_wrong_commitment() {
        let mut two = holder(US, "1990-01-01", 1_000_000, "2030-01-01");
        two.nationality = [US, GB].into();
        assert!(check(two).is_err());
        let id = holder(US, "1990-01-01", 1_000_000, "2030-01-01");
        assert!(zk_kyc(id, 1, "2008-10-20", 500_000, "2026-10-20", [US]).is_err());
    }

    #[test]
    fn checks_switch_off_without_a_new_circuit() {
        let id = holder(JP, "2025-01-01", 0, "2026-10-21");
        let any = Date::from_raw(99_999_999);
        zk_kyc(
            id,
            id.commitment(),
            any,
            0,
            Date::from_raw(0),
            Bitfield::all(),
        )
        .unwrap();
    }
}
