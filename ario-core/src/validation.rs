use std::fmt::Display;

pub trait SupportsValidation: Sized {
    type Validated;
    type Validator: Validator<Self>;

    fn into_valid(
        self,
        token: <<Self as SupportsValidation>::Validator as Validator<Self>>::Token,
    ) -> Self::Validated;
}

pub trait Validator<T> {
    type Error: Display;
    type Token: Send;
    fn validate(data: &T) -> Result<Self::Token, Self::Error>;
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
        let token = match T::Validator::validate(&self) {
            Ok(token) => token,
            Err(err) => return Err((self, err)),
        };
        Ok(T::into_valid(self, token))
    }
}
