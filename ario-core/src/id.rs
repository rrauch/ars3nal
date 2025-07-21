use crate::BigUint;
use crate::base64::{Base64Stringify, UrlSafeNoPadding};
use crate::serde::StringifySerdeStrategy;
use crate::stringify::DefaultStringify;
use crate::typed::{FromInner, StringifyDebugStrategy, Typed};
use std::fmt::Debug;
use std::hash::Hash;
use uuid::Uuid;

#[allow(private_bounds)]
pub type TypedId<
    T,
    ID,
    SER = StringifySerdeStrategy,
    STR = DefaultStringify<ID>,
    DBG = StringifyDebugStrategy,
> = Typed<T, ID, SER, STR, DBG>;

impl<T, Id> From<Id> for TypedId<T, Id>
where
    Id: Clone + Debug + PartialEq + PartialOrd + Hash + Send + Sync,
{
    fn from(value: Id) -> Self {
        Self::from_inner(value)
    }
}

pub type TypedUuid<T> = TypedId<T, Uuid, StringifySerdeStrategy>;

pub type Typed256B64Id<T> =
    TypedId<T, [u8; 32], StringifySerdeStrategy, Base64Stringify<UrlSafeNoPadding, 64>>;

pub type TypedBigUintB64Id<T> =
    TypedId<T, BigUint, StringifySerdeStrategy, Base64Stringify<UrlSafeNoPadding, { 1024 * 10 }>>;

#[cfg(test)]
mod tests {
    use crate::id::{Typed256B64Id, TypedBigUintB64Id, TypedUuid};
    use std::str::FromStr;

    #[test]
    fn test_id_256_b64_ok() {
        let b64_enc = "Kx7IKKdBzaYiZpYLgtL5tWoOseFt0vjXQMyirrTPc-E";
        let id = Typed256B64Id::<()>::from_str(b64_enc).unwrap();
        let str = id.to_string();
        assert_eq!(&str, b64_enc);
    }

    #[test]
    fn test_id_biguint_b64_ok() {
        let b64_enc = "l8lxft8zbGA39CDjvsCLFnxC97AnAAxmN0X3-pFPoUiqZ_8ipkygrGm16Y0HT9uILuPPxwbes8mGK5xcteUpaxYY58scXcPboyqryXjwUX-xPgMzUipOMleeVtrCnes_QxtVFCihYU2vaAqBYmzocF2xpwlzK7oeEv_CRVMjABtOfgwlVg8jfkfQvhRsOihUCVJiBDU49uuPe-V3KfB0-i3rlm44p5uQ-IxQMc1SyY_3HdvRelDZsKTxIzk3_nf7Tr0Q_4PX6608Ehm3hLmIz4G0tXzGV_pEVdbK5Bq_p7z5wEQUXV08Gv-WZwhtwxqpbbXIpJmTHQnz-Es6QzlEHYy7y2MPwhGQTw5P7s4DZ5r5jFjpLI0G46gifIEMuEpKFPmh1IimsluWEtvaLTj-FrPyFJvP6TDOzT-mRceUmqKFgTlTBuSeB_91JJ2MNpYgmh58JGKwPTVmsrZTIWr2HndJOZSxciZOSb9bNlw2mMUUMaFZNt4pH_vqB9dzV5kf0g-C80bRNd8gOIcEejnDA6SEcQV7a8v5eYPDshdkyMfxpYaAVwb1g-qQyC9n_nWZ8p85lPgW0cyxw-xFTdJItyv9n-2SMDshmtEtuYC2t3cBL0C9GcZTDuLHVXOG92kblSC3q5-lV3gjpZU6FidusfHihGAHs88hmpMHng78WSU";
        let id = TypedBigUintB64Id::<()>::from_str(b64_enc).unwrap();
        let str = id.to_string();
        assert_eq!(&str, b64_enc);
    }

    #[test]
    fn test_id_256_b64_inv() {
        assert!(Typed256B64Id::<()>::from_str("Kx7IKKdBzaYiZpYLgtL5tWoOseF").is_err());
    }

    #[test]
    fn test_uuid_ok() {
        let id_str = "72474585-0734-4b4e-ba20-093445359a10";
        let id = TypedUuid::<()>::from_str(id_str).unwrap();
        let str = id.to_string();
        assert_eq!(&str, id_str);
    }

    #[test]
    fn test_uuid_inv() {
        assert!(TypedUuid::<()>::from_str("12345674a-eb5e-4134-8ae2-a3946a428ec7").is_err());
    }
}
