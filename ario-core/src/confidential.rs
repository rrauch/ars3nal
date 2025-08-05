use bytemuck::TransparentWrapper;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Display, Formatter};
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(PartialEq, Eq, PartialOrd, Ord, TransparentWrapper)]
#[repr(transparent)]
struct Secret<const ZEROIZE: bool, T>(T);

impl<T> Zeroize for Secret<false, T> {
    fn zeroize(&mut self) {
        // do nothing
    }
}

impl<T: Zeroize> Zeroize for Secret<true, T> {
    fn zeroize(&mut self) {
        T::zeroize(&mut self.0)
    }
}

impl<T: Clone, const ZEROIZE: bool> Clone for Secret<ZEROIZE, T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T, const ZEROIZE: bool> Deref for Secret<ZEROIZE, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, const ZEROIZE: bool> DerefMut for Secret<ZEROIZE, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

macro_rules! impl_secret {
    ($name:ident, $zeroize:literal) => {
        #[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
        #[repr(transparent)]
        pub(crate) struct $name<T>(Secret<$zeroize, T>)
        where
            Secret<$zeroize, T>: Zeroize;

        impl<T> $name<T>
        where
            Secret<$zeroize, T>: Zeroize,
        {
            pub fn new(value: T) -> Self {
                Self(Secret(value))
            }

            pub fn reveal(&self) -> &T {
                self.0.deref()
            }

            pub fn reveal_mut(&mut self) -> &mut T {
                self.0.deref_mut()
            }
        }

        impl<T> Zeroize for $name<T>
        where
            Secret<$zeroize, T>: Zeroize,
        {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl<T> ZeroizeOnDrop for $name<T> where Secret<$zeroize, T>: Zeroize {}

        impl<T> Drop for $name<T>
        where
            Secret<$zeroize, T>: Zeroize,
        {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        impl<T: Debug> Debug for $name<T>
        where
            Secret<$zeroize, T>: Zeroize,
        {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.write_str("[redacted]")
            }
        }

        impl<T: Display> Display for $name<T>
        where
            Secret<$zeroize, T>: Zeroize,
        {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.write_str("[redacted]")
            }
        }

        impl<T: Serialize> Serialize for $name<T>
        where
            Secret<$zeroize, T>: Zeroize,
        {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                T::serialize(self.0.deref(), serializer)
            }
        }

        impl<'de, T: Deserialize<'de>> Deserialize<'de> for $name<T>
        where
            Secret<$zeroize, T>: Zeroize,
        {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                T::deserialize(deserializer).map(Self::new)
            }
        }
    };
}

impl_secret!(Confidential, true);
impl_secret!(Sensitive, false);

pub(crate) trait SecretExt {
    fn confidential(self) -> Confidential<Self>
    where
        Self: Zeroize + Sized,
        Secret<true, Self>: Zeroize;

    fn sensitive(self) -> Sensitive<Self>
    where
        Self: Sized,
        Secret<false, Self>: Zeroize;
}

impl<T> SecretExt for T {
    fn confidential(self) -> Confidential<T>
    where
        Self: Zeroize + Sized,
        Secret<true, Self>: Zeroize,
    {
        Confidential::new(self)
    }

    fn sensitive(self) -> Sensitive<Self>
    where
        Self: Sized,
        Secret<false, Self>: Zeroize,
    {
        Sensitive::new(self)
    }
}

pub(crate) trait SecretOptExt<'a, T> {
    fn reveal(self) -> Option<&'a T>;
}

pub(crate) trait SecretOptMutExt<'a, T> {
    fn reveal_mut(self) -> Option<&'a mut T>;
}

impl<'a, T> SecretOptExt<'a, T> for Option<&'a Confidential<T>>
where
    Secret<true, T>: Zeroize,
{
    fn reveal(self) -> Option<&'a T> {
        self.map(|s| s.reveal())
    }
}

impl<'a, T> SecretOptMutExt<'a, T> for Option<&'a mut Confidential<T>>
where
    Secret<true, T>: Zeroize,
{
    fn reveal_mut(self) -> Option<&'a mut T> {
        self.map(|s| s.reveal_mut())
    }
}

impl<'a, T> SecretOptExt<'a, T> for Option<&'a Sensitive<T>>
where
    Secret<false, T>: Zeroize,
{
    fn reveal(self) -> Option<&'a T> {
        self.map(|s| s.reveal())
    }
}

impl<'a, T> SecretOptMutExt<'a, T> for Option<&'a mut Sensitive<T>>
where
    Secret<true, T>: Zeroize,
{
    fn reveal_mut(self) -> Option<&'a mut T> {
        self.map(|s| s.reveal_mut())
    }
}
