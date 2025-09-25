use std::fmt::Display;

pub trait SupportsValidation: Sized {
    type Validated;
    type Error: Display + Send;
    type Reference<'r>: Send;

    fn validate_with(
        self,
        reference: &Self::Reference<'_>,
    ) -> Result<Self::Validated, (Self, Self::Error)>;
}

pub trait ValidateExt<T: SupportsValidation> {
    fn validate(self) -> Result<T::Validated, (T, T::Error)>
    where
        for<'r> T: SupportsValidation<Reference<'r> = ()>,
        Self: Sized;
}

impl<T> ValidateExt<T> for T
where
    T: SupportsValidation,
{
    fn validate(self) -> Result<T::Validated, (T, T::Error)>
    where
        for<'r> T: SupportsValidation<Reference<'r> = ()>,
        Self: Sized,
    {
        self.validate_with(&())
    }
}
