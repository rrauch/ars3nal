use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Display, Formatter};
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Confidential<T: Zeroize + ?Sized, const ALLOW_CLONING: bool = false>(Box<T>);

impl<T: Zeroize + ?Sized, const ALLOW_CLONING: bool> Confidential<T, ALLOW_CLONING> {
    pub fn new(data: impl Into<Box<T>>) -> Self {
        Self(data.into())
    }
}

impl<T: Zeroize + ?Sized> Confidential<T, true> {
    pub fn new_cloneable(data: impl Into<Box<T>>) -> Self {
        Self::new(data)
    }
}

impl<T: Debug + Zeroize + ?Sized, const ALLOW_CLONING: bool> Debug
    for Confidential<T, ALLOW_CLONING>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.serialize_str("[redacted]")
    }
}

impl<T: Display + Zeroize + ?Sized, const ALLOW_CLONING: bool> Display
    for Confidential<T, ALLOW_CLONING>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.serialize_str("[redacted]")
    }
}

impl<T: Serialize + Zeroize + ?Sized, const ALLOW_CLONING: bool> Serialize
    for Confidential<T, ALLOW_CLONING>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de> + Zeroize + ?Sized, const ALLOW_CLONING: bool> Deserialize<'de>
    for Confidential<T, ALLOW_CLONING>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(|d| Self::new(d))
    }
}

impl<T: Zeroize + ?Sized, const ALLOW_CLONING: bool> Zeroize for Confidential<T, ALLOW_CLONING> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl<T: Zeroize + ?Sized, const ALLOW_CLONING: bool> ZeroizeOnDrop
    for Confidential<T, ALLOW_CLONING>
{
}

impl<T: Zeroize + ?Sized, const ALLOW_CLONING: bool> Drop for Confidential<T, ALLOW_CLONING> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<'a, T: Zeroize + ?Sized + 'a, const ALLOW_CLONING: bool> SecretKeeper<'a, T>
    for Confidential<T, ALLOW_CLONING>
{
    type Secret = &'a T;
    type SecretMut = &'a mut T;

    #[inline]
    fn reveal(&'a self) -> Self::Secret {
        &self.0
    }

    #[inline]
    fn reveal_mut(&'a mut self) -> Self::SecretMut {
        &mut self.0
    }
}

impl<T: Zeroize + Sized + Clone> Clone for Confidential<T, true> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Sensitive<T>(T);

impl<T> Sensitive<T> {
    pub fn new(data: T) -> Self {
        Self(data)
    }

    pub fn extract_secret(self) -> T {
        self.0
    }
}

impl<T: Debug> Debug for Sensitive<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.serialize_str("[redacted]")
    }
}

impl<T: Display> Display for Sensitive<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.serialize_str("[redacted]")
    }
}

impl<T: Serialize> Serialize for Sensitive<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Sensitive<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(|d| Self::new(d))
    }
}

impl<T: Zeroize> Zeroize for Sensitive<T> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl<T: ZeroizeOnDrop> ZeroizeOnDrop for Sensitive<T> {}

impl<'a, T: 'a> SecretKeeper<'a, T> for Sensitive<T> {
    type Secret = &'a T;
    type SecretMut = &'a mut T;

    #[inline]
    fn reveal(&'a self) -> Self::Secret {
        &self.0
    }

    #[inline]
    fn reveal_mut(&'a mut self) -> Self::SecretMut {
        &mut self.0
    }
}

pub trait SecretKeeper<'a, T: ?Sized> {
    type Secret: Deref<Target = T>;
    type SecretMut: DerefMut<Target = T>;

    fn reveal(&'a self) -> Self::Secret;

    fn reveal_mut(&'a mut self) -> Self::SecretMut;
}

pub trait SecretExt {
    fn confidential(self) -> Confidential<Self>
    where
        Self: Zeroize;

    fn confidential_cloneable(self) -> Confidential<Self, true>
    where
        Self: Zeroize;

    fn sensitive(self) -> Sensitive<Self>
    where
        Self: Sized;
}

impl<T> SecretExt for T {
    fn confidential(self) -> Confidential<T>
    where
        Self: Zeroize,
    {
        Confidential::new(self)
    }

    fn confidential_cloneable(self) -> Confidential<Self, true>
    where
        Self: Zeroize,
    {
        Confidential::new(self)
    }

    fn sensitive(self) -> Sensitive<Self> {
        Sensitive::new(self)
    }
}

pub trait OptionSecretExt<'a, T, S: SecretKeeper<'a, T>> {
    fn reveal(self) -> Option<S::Secret>;
}

impl<'a, T, S: SecretKeeper<'a, T>> OptionSecretExt<'a, T, S> for Option<&'a S> {
    #[inline]
    fn reveal(self) -> Option<S::Secret> {
        self.map(|s| s.reveal())
    }
}

pub trait OptionSecretMutExt<'a, T, S: SecretKeeper<'a, T>> {
    fn reveal_mut(self) -> Option<S::SecretMut>;
}

impl<'a, T, S: SecretKeeper<'a, T>> OptionSecretMutExt<'a, T, S> for Option<&'a mut S> {
    #[inline]
    fn reveal_mut(self) -> Option<S::SecretMut> {
        self.map(|s| s.reveal_mut())
    }
}
