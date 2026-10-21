//! Zero-knowledge KYC: prove an identity an issuer committed to meets a verifier's
//! policy (old enough, wealthy enough, document still valid, nationality allowed)
//! without revealing it. The identity stays private; the commitment and the policy
//! are public, so a verifier picks the rules at proof time with no new circuit.
use xark::prelude::*;

/// What an issuer attests about a holder, committed to as a whole with Poseidon2.
#[input]
pub struct Identity {
    /// The ID document's number.
    pub document: Text,
    pub born: Date,
    /// An ISO 3166 code.
    pub nationality: Choice<Country>,
    /// Attested net worth, in the attestor's unit (its currency and scale).
    pub net_worth: u64,
    /// The ID document's expiry.
    pub expires: Date,
    /// The issuer's random blinding secret: it hides the commitment.
    pub salt: Field,
}

#[xark::input]
impl Identity {
    /// The issuer's commitment: Poseidon2 over every field, so adding one extends it.
    pub fn commitment(&self) -> Field {
        xark_poseidon2::hash(self.to_fields())
    }
}

/// What a verifier requires, checked on `today`: a public input, so each verifier
/// picks its own rules with no new circuit.
///
/// ```ignore
/// Policy::on("2026-10-20").min_age(18).worth_at_least(500_000).nationalities([US, GB, FR, DE])
/// ```
#[input]
pub struct Policy {
    /// The day of the check: the document mustn't have expired by then.
    pub today: Date,
    /// The latest birth date allowed (a minimum age on `today`).
    pub born_by: Date,
    /// The least attested net worth allowed, in the attestor's unit.
    pub min_net_worth: u64,
    /// The nationalities allowed.
    pub allowed: Bitfield<Country>,
}

#[xark::input]
impl Policy {
    /// A check on `today` that any holder with a valid document passes: tighten it
    /// with the other constructors.
    pub fn on(today: impl Into<Date>) -> Policy {
        Policy {
            today: today.into(),
            born_by: Date::MAX,
            min_net_worth: 0,
            allowed: Bitfield::all(),
        }
    }

    /// At least `years` old on `today`.
    #[cfg(not(xark))]
    pub fn min_age(self, years: u16) -> Policy {
        Policy {
            born_by: self.today.years_before(years),
            ..self
        }
    }

    /// Worth at least `amount`, in the attestor's unit.
    pub fn worth_at_least(self, amount: u64) -> Policy {
        Policy {
            min_net_worth: amount,
            ..self
        }
    }

    /// A national of one of `allowed` (a country, or a list of them).
    pub fn nationalities(self, allowed: impl Into<Bitfield<Country>>) -> Policy {
        Policy {
            allowed: allowed.into(),
            ..self
        }
    }
}

/// `id` is the identity the issuer committed to as `commitment`, and it meets
/// `policy`.
#[circuit]
pub fn zk_kyc(id: Private<Identity>, commitment: Public<Field>, policy: Public<Policy>) {
    require_eq(id.commitment(), commitment);
    require(id.born <= policy.born_by);
    require(id.net_worth >= policy.min_net_worth);
    require(id.expires >= policy.today);
    id.nationality.require_in(policy.allowed);
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

    /// 18 or older, worth ≥ 500k, valid on 2026-10-20, from US/GB/FR/DE.
    fn policy() -> Policy {
        Policy::on("2026-10-20")
            .min_age(18)
            .worth_at_least(500_000)
            .nationalities([US, GB, FR, DE])
    }

    fn check(id: Identity) -> Result<(), xark::prover::ProveError> {
        zk_kyc(id, id.commitment(), policy())
    }

    #[test]
    fn accepts_a_compliant_holder() {
        check(holder(US, "1990-01-01", 1_000_000, "2030-01-01")).unwrap();
        // Every limit inclusive: 18 today, exactly 500k, the document's last day.
        check(holder(GB, "2008-10-20", 500_000, "2026-10-20")).unwrap();
    }

    #[test]
    fn rejects_each_failed_check() {
        assert!(check(holder(KP, "1990-01-01", 1_000_000, "2030-01-01")).is_err());
        assert!(check(holder(US, "2008-10-21", 1_000_000, "2030-01-01")).is_err()); // 18 tomorrow
        assert!(check(holder(US, "1990-01-01", 100, "2030-01-01")).is_err());
        assert!(check(holder(US, "1990-01-01", 1_000_000, "2026-10-19")).is_err());
    }

    #[test]
    fn rejects_a_wrong_commitment() {
        let id = holder(US, "1990-01-01", 1_000_000, "2030-01-01");
        assert!(zk_kyc(id, 1, policy()).is_err());
    }

    #[test]
    fn checks_switch_off_without_a_new_circuit() {
        let id = holder(JP, "2025-01-01", 0, "2026-10-21");
        zk_kyc(id, id.commitment(), Policy::on("2026-10-20")).unwrap();
    }
}
