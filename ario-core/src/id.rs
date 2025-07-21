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
    TypedId<T, [u8; 32], StringifySerdeStrategy, Base64Stringify<UrlSafeNoPadding, 43>>;

pub type Typed384B64Id<T> =
    TypedId<T, [u8; 48], StringifySerdeStrategy, Base64Stringify<UrlSafeNoPadding, 64>>;

#[cfg(test)]
mod tests {
    use crate::id::{Typed256B64Id, Typed384B64Id, TypedUuid};
    use std::str::FromStr;

    #[test]
    fn test_id_256_b64_ok() {
        let b64_enc = "Kx7IKKdBzaYiZpYLgtL5tWoOseFt0vjXQMyirrTPc-E";
        let id = Typed256B64Id::<()>::from_str(b64_enc).unwrap();
        let str = id.to_string();
        assert_eq!(&str, b64_enc);
    }

    #[test]
    fn test_id_384_b64_ok() {
        let b64_enc = "d5FBi46TVGVSSmjCmH1zGJ69I9XMEHL_VMEvQmYC7oBEQuVQ1mYNZvRN2gNknpQb";
        let id = Typed384B64Id::<()>::from_str(b64_enc).unwrap();
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
