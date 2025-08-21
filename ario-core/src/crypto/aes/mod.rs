pub mod gcm;

use crate::confidential::{NewSecretExt, Protected};
use crate::crypto::keys::{SymmetricKey, SymmetricScheme};
use aes::cipher::consts::U16;
use aes::cipher::typenum::Unsigned;
use aes::cipher::{BlockCipherEncrypt, BlockSizeUser, KeyInit};
use hybrid_array::Array;

pub struct Aes<const BIT: usize>;

pub trait AesCipher {
    type Cipher: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + KeyInit;
}

impl AesCipher for Aes<256> {
    type Cipher = aes::Aes256;
}

impl<const BIT: usize> SymmetricScheme for Aes<BIT>
where
    Self: AesCipher,
{
    type SecretKey = AesKey<BIT>;
}

pub type KeySize<const BIT: usize> =
    <<Aes<BIT> as AesCipher>::Cipher as aes::cipher::KeySizeUser>::KeySize;

#[derive(Clone)]
#[repr(transparent)]
pub struct AesKey<const BIT: usize>(Protected<Array<u8, KeySize<BIT>>>)
where
    Aes<BIT>: AesCipher;

impl<const BIT: usize> AesKey<BIT>
where
    Aes<BIT>: AesCipher,
{
    pub(crate) fn try_from_bytes<T: AsRef<[u8]>>(input: T) -> Option<Self> {
        let key_size = KeySize::<BIT>::to_usize();
        let input = input.as_ref();
        if key_size != input.len() {
            //todo
            return None;
        }
        Some(Self(Array::try_from(input).unwrap().protected()))
    }
}

impl<const BIT: usize> SymmetricKey for AesKey<BIT>
where
    Aes<BIT>: AesCipher,
{
    type Scheme = Aes<BIT>;
}
