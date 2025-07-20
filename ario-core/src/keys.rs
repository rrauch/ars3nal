use crate::base64::UrlSafeNoPadding;
use crate::serde::Base64SerdeStrategy;
use crate::typed::{FromInner, Typed};
use crate::{Address, BigUint, RsaError};
use derive_where::derive_where;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::marker::PhantomData;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type TypedSecretKey<T> = Typed<T, SecretKeyInner<T>, (), ()>;

#[derive_where(Debug, Clone)]
pub struct SecretKeyInner<T> {
    inner: RsaPrivateKey,
    pkey: TypedPublicKey<T>,
}

impl<T> TypedSecretKey<T> {
    pub(crate) fn try_from_components(
        components: RsaPrivateKeyComponents,
    ) -> Result<Self, RsaError> {
        let inner = RsaPrivateKey::from_components(
            components.n,
            components.e,
            components.d,
            components.primes,
        )?;

        // todo: RsaPrivateKey::from_components does NOT zeroize the provided key material on error
        // a PR might be warranted

        let pkey = inner.to_public_key();

        Ok(Self::from_inner(SecretKeyInner {
            inner,
            pkey: TypedPublicKey::new(pkey),
        }))
    }

    pub fn public_key(&self) -> &TypedPublicKey<T> {
        &self.pkey
    }
}

#[derive(Zeroize)]
pub struct RsaPrivateKeyComponents {
    n: BigUint,
    e: BigUint,
    d: BigUint,
    primes: Vec<BigUint>,
}

impl RsaPrivateKeyComponents {
    pub fn new(n: BigUint, e: BigUint, d: BigUint, p_q: Option<(BigUint, BigUint)>) -> Self {
        Self {
            n,
            e,
            d,
            primes: p_q.map(|(p, q)| vec![p, q]).unwrap_or_default(),
        }
    }

    pub(crate) fn try_from_jwk(jwk: &[u8]) -> Result<Self, JwkError> {
        let mut jwk: RsaJwk = serde_json::from_slice(jwk)?;
        if !jwk.kty.eq_ignore_ascii_case("RSA") {
            return Err(JwkError::NonRsaKeyType(jwk.kty.to_string()));
        }

        let p_q = if jwk.p.is_some() && jwk.q.is_some() {
            Some((
                jwk.p.take().unwrap().into_inner(),
                jwk.q.take().unwrap().into_inner(),
            ))
        } else {
            None
        };

        Ok(Self::new(
            jwk.n.clone().into_inner(),
            jwk.e.clone().into_inner(),
            jwk.d.clone().into_inner(),
            p_q,
        ))
    }
}

#[derive(Error, Debug)]
pub enum JwkError {
    #[error(transparent)]
    InvalidFieldValue(#[from] JwkFieldValueError),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error("expected kty 'RSA' but found '{0}'")]
    NonRsaKeyType(String),
}

#[derive(Error, Debug)]
pub enum JwkFieldValueError {
    #[error("field value length '{found}' exceeds allowed maximum of '{max}'")]
    MaxLengthExceeded { max: usize, found: usize },
    #[error("failed to decode Base64: {0}")]
    Base64DecodingError(String),
}

type RsaJwkValue = Typed<(), BigUint, Base64SerdeStrategy<UrlSafeNoPadding, { 1024 * 10 }>>;

#[derive(Zeroize, ZeroizeOnDrop, Deserialize)]
struct RsaJwk<'a> {
    #[zeroize(skip)]
    kty: &'a str,
    n: RsaJwkValue,
    e: RsaJwkValue,
    d: RsaJwkValue,
    #[serde(default)]
    p: Option<RsaJwkValue>,
    #[serde(default)]
    q: Option<RsaJwkValue>,
}

pub type TypedPublicKey<T> = Typed<T, PublicKeyInner<T>>;

#[derive_where(Debug, Clone)]
pub struct PublicKeyInner<T> {
    inner: RsaPublicKey,
    address: Address<T>,
    ph: PhantomData<T>,
}

impl<T> TypedPublicKey<T> {
    fn new(inner: RsaPublicKey) -> Self {
        let address = rsa_public_key_to_address(&inner);
        Self::from_inner(PublicKeyInner {
            inner,
            address,
            ph: PhantomData,
        })
    }

    pub fn address(&self) -> &Address<T> {
        &self.address
    }
}

fn rsa_public_key_to_address<T>(pk: &RsaPublicKey) -> Address<T> {
    // sha256 hash from bytes representing a big-endian encoded modulus
    let hash: [u8; 32] = Sha256::digest(pk.n_bytes()).into();
    Address::from_inner(hash)
}

mod tests {
    use crate::wallet::WalletKeyPair;

    #[test]
    pub fn rsa_jwk_ok() -> anyhow::Result<()> {
        let jwk_content = r#"{"kty":"RSA","n":"l8lxft8zbGA39CDjvsCLFnxC97AnAAxmN0X3-pFPoUiqZ_8ipkygrGm16Y0HT9uILuPPxwbes8mGK5xcteUpaxYY58scXcPboyqryXjwUX-xPgMzUipOMleeVtrCnes_QxtVFCihYU2vaAqBYmzocF2xpwlzK7oeEv_CRVMjABtOfgwlVg8jfkfQvhRsOihUCVJiBDU49uuPe-V3KfB0-i3rlm44p5uQ-IxQMc1SyY_3HdvRelDZsKTxIzk3_nf7Tr0Q_4PX6608Ehm3hLmIz4G0tXzGV_pEVdbK5Bq_p7z5wEQUXV08Gv-WZwhtwxqpbbXIpJmTHQnz-Es6QzlEHYy7y2MPwhGQTw5P7s4DZ5r5jFjpLI0G46gifIEMuEpKFPmh1IimsluWEtvaLTj-FrPyFJvP6TDOzT-mRceUmqKFgTlTBuSeB_91JJ2MNpYgmh58JGKwPTVmsrZTIWr2HndJOZSxciZOSb9bNlw2mMUUMaFZNt4pH_vqB9dzV5kf0g-C80bRNd8gOIcEejnDA6SEcQV7a8v5eYPDshdkyMfxpYaAVwb1g-qQyC9n_nWZ8p85lPgW0cyxw-xFTdJItyv9n-2SMDshmtEtuYC2t3cBL0C9GcZTDuLHVXOG92kblSC3q5-lV3gjpZU6FidusfHihGAHs88hmpMHng78WSU","e":"AQAB","d":"Vr_67dgDO92CHTTu9QZ2d9NtMsKqh4yOnuiOYdbK_BLb0bQvyXviGKgSH_lKRInju2jYR5fVkEuNMz-afRsMIPfwJAohnDVkQk0RAYTtVKb2VcreegdTydHp3RoKQNdCwMfOSEcwdLxBk-TtLaOw9QeXkTAFcuhcZ99k2No7FsSEh-XJMPZWAsZotzpU4KhL30gGXQFOHVFkIBt1j7KuKI42JzO3jZOLt4H6E3yV5D0zrw0DHDU5NYwPhWIeboGET-we2uovbbMEshOgn2qqlm47Kb62XXHbvHOWYegnwWZwF0LRoMq4n3WUMC7RDMEgNGPA2NItElut5CqakfEYzCKfHY0GI2l0lEc6086Z_NrXsLva6V00n72DXQxO4rSEuuTYf_OdjW46mcP_s0Dt5CL_3zf5av_aI5moSHsPYA1JZ2zx7odwoPQnWNfzknQ6dYR61V2q6xFeZ1pSeERo92WRAKd3GwNUSa0PRDbUAflUpYu4RumvHmD5WdNSUMeDZQ1Okf4OHziAu6NuRUPVVF6gudF7dFvC1W1bR8k3x59Hg8u8WRxxB7U4iLroGmsWRX7OvDNs9c3NlXsEHhfa5Yppu7sjMhigJesmXyRYpP127TpJmeaEBGeNj8rK72_2WpqClakZYbOH8_SGcQklma64HFR6F2bTntfUPQkOPAE","p":"-6bCYmYRp4-C9odNPeEhwrJA24LWCHjTGOrKb4ufmTebBUJPUzGW3aEGYn-ZFkKNuM5XJ03ssozhD9w-L_m5lCCaPd3iOQezbXco9kkmVv2zl4N-rnk8C0Os8vqzbEygjePhhWdNuD0qX_b4fr68CdF3pWTBJiN3fzzXAnuggk_5I_73Xfr63qbLrhqBFYbCmAMwsWUjawJENJimc5Nq6ROW3aPUmVSCxIDTl6_bTFw5JbxAxVQIzkUDqO4ueUtc9_PgRHa0wLgeAMvSyjr5eRDJUKTy4MIBfjl5h7x3o2uhpwLALM__d7diN54Sl7aUUYe5Knloha3MZp4nrDMQdQ","q":"mmjoxO4IcpZpC8LChhaaV91cMml5PLjz5NJAV2jvjQsnU30fbQbe1C7zxPZ4IvGFlb16XevuUrL42I1SsjviEDBFM-4e63TPc9zeddum4mymA9ot5vQhAyRGcQsZFpo191X95LKPMs0fzQN0LEHH3OWQUURFXttIXQUlz0671WOcASShmvmuG3w9d9kutgrhAhTSoV1u0olMYcDvnUJvGbTPNiWihL4shRcT2DunrXJR_XO9YgyJYpIgw8ROSdZUlwJhQQI9gKFEvz0ybC2ZUPem4uzRmVxEwbYNLtyVBZ7RycYWWGBCltRRYx2Pwd4m5Fx3y3AH6wDxoraGQscP8Q","dp":"AeSeP7k-1sDYnlwkM5v28gz_OeeBDq1CAUT64t3tBG0LqH14NUsBNIeakbEeCLHVeRdsRmpqpmky5Dim6xt4zulz35VEt2MccW1dDIU-WZcs-63MjSlyTy9iJK3IHb9x0b9uGd_OEN287N3hvqpWpchCmybn4Q6RPo7Jm0Ysze4mFKQ9XiKeMoCUtamTYQMTgas8eYkmPA7XToH7dpEcU8aG8wHhfonJNgs2DEURZECpWWRSJGneaxbP0TyBcv4jI-ZcwIcYEv8Pkrf1zPmmmMeMjCPBg_lRo45xIJlFWSBdJfF6Wpvx8weZIIv63dNMyFQ6C1zAcYj-KaN07vGvZQ","dq":"Ez1bM56NQunm8OY1osuSM7yLTmTCDITnLu3bwoh6wNJQ9iAzGDyw6zNmgHZNhd0eTggsBSPusDNIuoLxeO_pPScmmE_lXmVRrBgrR_g0lSYAkZ5P9eUZb_DHLjK5z40riEQYvLRbD3NrsPnrMdCIfMfF8bpWAnnETILlsS0YToB44dOUp2DRBu-2IQbYwSod20qI7D5eHrGo6M1HjgrHGSbkYtTRqUSg-3xipqDYRc5m1PPk9yCkxbl7h6kgMCcapy5Ou_DxhOOTU1jmvX_5CJOzIbdsbnWGw7RRdDNcBjVB4qhiBGUKJw0Rjw4R6ZAqvG2hJ6Iv-mJFuYaQuCVhoQ","qi":"VU4CqV_8FZNBwgTrfUY65-9rkWtMhSNNmSE-9OLYy6a--pGO_vNv0k3r1toqWX51WH5rUMSUTx_f8zuusWhrCwtrCv9HOCVegxPrUHZCCMPiIGq2Dnu9IGobG3t5mjKn6fRdXahEn1EF3rDE7TzUGhrCenMCRmssIgEMs5j7tkMElbPfKkKo2kP_1zk3c2J5kUyTqi_OuWMfZJcjLRGSEg90DeU_jY55MysKiKo3auhaDbw3HjB5bGZysA8SmbdqKwF-vP6cX4GcRhLSmvq_no6xqkZoHPPfWw8VMJpDJeFM-pZgzlzhEauvW3AJ8zQ0FwWjWFeWC25UuKT-l8O7vA"}"#;
        let keypair =
            WalletKeyPair::try_from_jwk(jwk_content.to_string().into_bytes().as_mut_slice())?;
        let pk = keypair.public_key();
        let addr = pk.address();
        assert_eq!(
            addr.to_string(),
            "yn4o-XYMgG_Tcz5dFn2WjBp4JIDwX-HaN0AxscBKwfc"
        );
        Ok(())
    }
}
