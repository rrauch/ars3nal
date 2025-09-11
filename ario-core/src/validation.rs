use std::fmt::Display;
use std::marker::PhantomData;

pub struct Valid<T>(PhantomData<T>);

pub trait SupportsValidation: Sized {
    type Validated;
    type Validator: Validator<Self>;

    fn into_valid(self, token: Valid<Self>) -> Self::Validated;
}

pub trait Validator<T> {
    type Error: Display;
    fn validate(data: &T) -> Result<(), Self::Error>;
}

pub trait ValidateExt {
    type Error: Display;
    type Validated;
    fn validate(self) -> Result<Self::Validated, (Self, Self::Error)>
    where
        Self: Sized;
}

impl<T> ValidateExt for T
where
    T: SupportsValidation,
{
    type Error = <<T as SupportsValidation>::Validator as Validator<T>>::Error;
    type Validated = T::Validated;

    fn validate(self) -> Result<T::Validated, (Self, Self::Error)>
    where
        Self: Sized,
    {
        if let Err(err) = T::Validator::validate(&self) {
            return Err((self, err));
        }
        Ok(T::into_valid(self, Valid(PhantomData)))
    }
}
