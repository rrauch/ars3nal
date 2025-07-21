use std::fmt::Display;

pub trait Valid {
    type Error: Display;

    fn validate(&self) -> Result<(), Self::Error>;
}
