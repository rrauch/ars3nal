use std::fmt::Display;
use std::hash::{BuildHasher, Hash, RandomState};
use std::marker::PhantomData;

pub struct ValidityProof<T: SupportsValidation> {
    hash: u64,
    state: RandomState,
    _phantom: PhantomData<T>,
}

impl<T: SupportsValidation> ValidityProof<T> {
    #[inline]
    pub fn new(value: &T) -> Self {
        let state = RandomState::new();
        let hash = state.hash_one(value);
        Self {
            hash,
            state,
            _phantom: PhantomData,
        }
    }

    #[inline]
    pub fn is_valid_for(self, value: &T) -> bool {
        let hash = self.state.hash_one(value);
        hash == self.hash
    }
}

pub trait SupportsValidation: Sized + Hash {
    type Validated;
    type Validator: Validator<Self>;

    fn into_valid(
        self,
        token: <<Self as SupportsValidation>::Validator as Validator<Self>>::Token,
    ) -> Option<Self::Validated>;
}

pub trait ValidityToken<T: SupportsValidation>: Send {
    fn is_valid_for(self, value: &T) -> bool;
}

pub trait Validator<T: SupportsValidation> {
    type Error: Display;
    type Reference<'r>: Send;
    type Token: ValidityToken<T>;

    fn validate(data: &T, reference: &Self::Reference<'_>) -> Result<Self::Token, Self::Error>;
}

pub trait ValidateExt<T: SupportsValidation> {
    type Error: Display;
    type Validated;
    fn validate_with(
        self,
        data: &<T::Validator as Validator<T>>::Reference<'_>,
    ) -> Result<Self::Validated, (Self, Self::Error)>
    where
        Self: Sized;

    fn validate(self) -> Result<Self::Validated, (Self, Self::Error)>
    where
        for<'r> T: SupportsValidation<Validator: Validator<T, Reference<'r> = ()>>,
        Self: Sized;
}

impl<T> ValidateExt<T> for T
where
    T: SupportsValidation,
{
    type Error = <<T as SupportsValidation>::Validator as Validator<T>>::Error;
    type Validated = T::Validated;

    fn validate_with(
        self,
        reference: &<T::Validator as Validator<T>>::Reference<'_>,
    ) -> Result<T::Validated, (Self, Self::Error)>
    where
        Self: Sized,
    {
        let token = match T::Validator::validate(&self, reference) {
            Ok(token) => token,
            Err(err) => return Err((self, err)),
        };
        Ok(T::into_valid(self, token).expect("token to be valid"))
    }

    fn validate(self) -> Result<Self::Validated, (Self, Self::Error)>
    where
        for<'r> T: SupportsValidation<Validator: Validator<T, Reference<'r> = ()>>,
        Self: Sized,
    {
        self.validate_with(&())
    }
}
