use crate::crypto::hash::deep_hash::DeepHashable;
use crate::crypto::hash::{Digest, Hashable, Hasher};
use crate::money::MoneyError::{ParseError, PrecisionError, RepresentationError};
use crate::typed::{FromInner, Typed};
use bigdecimal::{BigDecimal, One, ParseBigDecimalError, RoundingMode};
use derive_where::derive_where;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::convert::Infallible;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::ops::{Add, Deref, Div, Mul, Sub};
use std::str::FromStr;
use std::sync::LazyLock;
use thiserror::Error;

#[allow(type_alias_bounds)]
pub type TypedMoney<T, C: Currency> = Typed<T, Money<C>>;

impl<T, C: Currency> TypedMoney<T, C> {
    pub fn zero() -> Self {
        Self::from_inner(Money::zero())
    }
}

static BIG_ONE: LazyLock<BigDecimal> = LazyLock::new(|| BigDecimal::one());

pub trait Currency {
    const DECIMAL_POINTS: u16;
    const SYMBOL: &'static str;
}

pub struct Winston;

impl Currency for Winston {
    const DECIMAL_POINTS: u16 = 0;
    const SYMBOL: &'static str = "W";
}

pub struct AR;

impl Currency for AR {
    const DECIMAL_POINTS: u16 = 12;
    const SYMBOL: &'static str = "AR";
}

static AR_WINSTON_XE: LazyLock<BigDecimal> = LazyLock::new(|| BigDecimal::from(1000000000000u64));
impl ConversionRate<'static, AR, Winston> for () {
    fn get<'a>(&self) -> &'static BigDecimal {
        &AR_WINSTON_XE
    }
}

static WINSTON_AR_XE: LazyLock<BigDecimal> =
    LazyLock::new(|| BigDecimal::from(1000000000000u64).inverse());
impl ConversionRate<'static, Winston, AR> for () {
    fn get(&self) -> &'static BigDecimal {
        &WINSTON_AR_XE
    }
}

impl DeepHashable for Money<Winston> {
    fn deep_hash<H: Hasher>(&self) -> Digest<H> {
        self.0.to_plain_string().deep_hash()
    }
}

impl Hashable for Money<Winston> {
    fn feed<H: Hasher>(&self, hasher: &mut H) {
        self.0.to_plain_string().feed(hasher)
    }
}

impl From<Money<Winston>> for Money<AR> {
    fn from(value: Money<Winston>) -> Self {
        value
            .try_convert_impl(&WINSTON_AR_XE, true)
            .expect("conversion from Winston to AR should never fail")
    }
}

impl From<Money<AR>> for Money<Winston> {
    fn from(value: Money<AR>) -> Self {
        value
            .try_convert_impl(&AR_WINSTON_XE, true)
            .expect("conversion from AR to Winston should never fail")
    }
}

#[derive(Error, Debug)]
pub enum MoneyError {
    #[error("Value has more decimal places ('{found}') than currency supports ('{supported}')")]
    PrecisionError { supported: u16, found: i64 },
    #[error("Unable to use value as a valid BigDecimal")]
    RepresentationError,
    #[error(transparent)]
    ParseError(ParseBigDecimalError),
}

impl From<Infallible> for MoneyError {
    fn from(_: Infallible) -> Self {
        unreachable!("infallible can never be an error")
    }
}

#[derive_where(Clone)]
#[repr(transparent)]
pub struct Money<C: Currency>(BigDecimal, PhantomData<C>);

impl<C: Currency> Money<C> {
    pub fn try_from(value: impl TryInto<BigDecimal>) -> Result<Self, MoneyError> {
        let value = value
            .try_into()
            .map_err(|_| RepresentationError)?
            .normalized();
        let fractional_digits = value.fractional_digit_count();
        if fractional_digits > 0 && fractional_digits > C::DECIMAL_POINTS as i64 {
            return Err(PrecisionError {
                supported: C::DECIMAL_POINTS,
                found: fractional_digits,
            });
        }

        Ok(Self::new_unchecked(value))
    }

    fn new_unchecked(value: BigDecimal) -> Self {
        Self(
            value.normalized().with_scale(C::DECIMAL_POINTS as i64),
            PhantomData,
        )
    }

    pub fn zero() -> Self {
        Self::try_from(BigDecimal::from(0)).expect("should never fail for '0'")
    }

    pub fn to_plain_string(&self) -> String {
        self.0.to_plain_string()
    }

    fn try_convert_impl<T: Currency>(
        self,
        rate: &BigDecimal,
        precise: bool,
    ) -> Result<Money<T>, MoneyError> {
        if rate == BIG_ONE.deref() {
            return Ok(Money(self.0, PhantomData));
        }
        if precise {
            // only succeeds if there is no loss of precision
            Money::<T>::try_from(self.0 * rate)
        } else {
            // imprecise mode allows rounding and never fails
            Ok(Money::<T>::new_unchecked((self.0 * rate).with_scale_round(
                T::DECIMAL_POINTS as i64,
                RoundingMode::HalfEven,
            )))
        }
    }

    pub fn convert_with<'a, To: Currency, XE>(self, xe: &'a XE) -> Money<To>
    where
        XE: ConversionRate<'a, C, To>,
    {
        self.try_convert_impl(xe.get(), false)
            .expect("imprecise conversion should never fail")
    }

    pub fn convert<To: Currency>(self) -> Money<To>
    where
        (): Convertible<C, To>,
    {
        <() as Convertible<C, To>>::convert(self)
    }
}

impl<C: Currency> From<Money<C>> for BigDecimal {
    fn from(value: Money<C>) -> Self {
        value.0
    }
}

impl<C: Currency> Debug for Money<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl<C: Currency> Display for Money<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{} {}", C::SYMBOL, self.to_plain_string()))
    }
}

impl<C: Currency> FromStr for Money<C> {
    type Err = MoneyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(BigDecimal::from_str(s).map_err(ParseError)?)
    }
}

macro_rules! impl_try_from_int {
    ($($int_type:ty),*) => {
        $(
            impl<C: Currency> TryFrom<$int_type> for Money<C> {
                type Error = MoneyError;

                fn try_from(value: $int_type) -> Result<Self, Self::Error> {
                    Self::try_from(BigDecimal::from(value))
                }
            }
        )*
    };
}

impl_try_from_int!(i8, i16, i32, i64, i128, u8, u16, u32, u64, u128);

impl<C: Currency> TryFrom<isize> for Money<C> {
    type Error = MoneyError;

    fn try_from(value: isize) -> Result<Self, Self::Error> {
        Self::try_from(BigDecimal::from(value as i64))
    }
}

impl<C: Currency> TryFrom<usize> for Money<C> {
    type Error = MoneyError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::try_from(BigDecimal::from(value as u64))
    }
}

impl<C: Currency> TryFrom<BigDecimal> for Money<C> {
    type Error = MoneyError;

    fn try_from(value: BigDecimal) -> Result<Self, Self::Error> {
        Self::try_from(value)
    }
}

impl<'a, C: Currency> TryFrom<&'a str> for Money<C> {
    type Error = MoneyError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Money::<C>::from_str(value)
    }
}

pub trait ConversionRate<'a, From: Currency, To: Currency> {
    fn get(&self) -> &'a BigDecimal;
}

impl<C: Currency> ConversionRate<'static, C, C> for () {
    fn get(&self) -> &'static BigDecimal {
        &BIG_ONE
    }
}

pub trait Convertible<From: Currency, To: Currency> {
    // Converts a monetary amound from currency `From` into currency `To`.
    // This conversion never fails but may lead to a loss of precision.
    fn convert(from: Money<From>) -> Money<To>;
}

impl<'a, From: Currency, To: Currency> Convertible<From, To> for ()
where
    (): ConversionRate<'a, From, To>,
{
    fn convert(from: Money<From>) -> Money<To> {
        from.convert_with(&())
    }
}

impl<C: Currency, RHS> Add<RHS> for Money<C>
where
    RHS: Into<Money<C>>,
{
    type Output = Self;

    fn add(self, rhs: RHS) -> Self::Output {
        Self::new_unchecked(self.0 + rhs.into().0)
    }
}

impl<C: Currency, RHS> Sub<RHS> for Money<C>
where
    RHS: Into<Money<C>>,
{
    type Output = Self;

    fn sub(self, rhs: RHS) -> Self::Output {
        Self::new_unchecked(self.0 - rhs.into().0)
    }
}

impl<C: Currency, M: Into<BigDecimal>> Mul<M> for Money<C> {
    type Output = Self;

    fn mul(self, rhs: M) -> Self::Output {
        let result = (self.0 * rhs.into())
            .with_scale_round(C::DECIMAL_POINTS as i64, RoundingMode::HalfEven);
        Self::new_unchecked(result)
    }
}

impl<C: Currency, D: Into<BigDecimal>> Div<D> for Money<C> {
    type Output = Self;

    fn div(self, rhs: D) -> Self::Output {
        // Perform division, then set the scale to the currency's precision, rounding as needed.
        let result = (self.0 / rhs.into())
            .with_scale_round(C::DECIMAL_POINTS as i64, RoundingMode::HalfEven);
        Self::new_unchecked(result)
    }
}

impl<C: Currency> PartialEq for Money<C> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<C: Currency> Eq for Money<C> {}

impl<C: Currency> PartialOrd for Money<C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<C: Currency> Ord for Money<C> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl<C: Currency> Serialize for Money<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_plain_string().as_str())
    }
}

impl<'de, C: Currency> Deserialize<'de> for Money<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MoneyVisitor<C>(PhantomData<C>);
        impl<'de, C: Currency> Visitor<'de> for MoneyVisitor<C> {
            type Value = Money<C>;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Money::from_str(value)
                    .map(Into::into)
                    .map_err(serde::de::Error::custom)
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Money::try_from(value)
                    .map(Into::into)
                    .map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Money::try_from(value)
                    .map(Into::into)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(MoneyVisitor(PhantomData))
    }
}

pub trait CurrencyExt<C: Currency> {
    fn try_new(value: impl TryInto<BigDecimal>) -> Result<Money<C>, MoneyError>;
    fn from_str(value: impl AsRef<str>) -> Result<Money<C>, MoneyError>;
    fn zero() -> Money<C>;
}

impl<C: Currency> CurrencyExt<C> for C {
    fn try_new(value: impl TryInto<BigDecimal>) -> Result<Money<C>, MoneyError> {
        Money::try_from(value)
    }

    fn from_str(value: impl AsRef<str>) -> Result<Money<C>, MoneyError> {
        Money::from_str(value.as_ref())
    }

    fn zero() -> Money<C> {
        Money::zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bigdecimal::BigDecimal;
    use std::str::FromStr;

    #[test]
    fn test_winston_precision_enforcement() {
        // Winston has 0 decimal places
        assert!(Winston::try_new(100).is_ok());
        assert!(Winston::try_new(0).is_ok());
        assert!(Winston::try_new(-50).is_ok());

        // Should reject any decimal values
        assert!(matches!(
            Winston::try_new(BigDecimal::from_str("1.1").unwrap()),
            Err(PrecisionError {
                supported: 0,
                found: 1
            })
        ));
        assert!(matches!(
            Winston::try_new(BigDecimal::from_str("0.000001").unwrap()),
            Err(PrecisionError {
                supported: 0,
                found: 6
            })
        ));
    }

    #[test]
    fn test_ar_precision_enforcement() {
        // AR has 12 decimal places
        assert!(AR::try_new(100).is_ok());
        assert!(AR::try_new(BigDecimal::from_str("1.123456789012").unwrap()).is_ok());
        assert!(AR::try_new(BigDecimal::from_str("0.000000000001").unwrap()).is_ok());

        // Should reject 13+ decimal places
        assert!(matches!(
            AR::try_new(BigDecimal::from_str("1.1234567890123").unwrap()),
            Err(PrecisionError {
                supported: 12,
                found: 13
            })
        ));
        assert!(matches!(
            AR::try_new(BigDecimal::from_str("0.0000000000001").unwrap()),
            Err(PrecisionError {
                supported: 12,
                found: 13
            })
        ));
    }

    #[test]
    fn test_construction_methods() {
        // try_from with various types
        let winston = Money::<Winston>::try_from(100).unwrap();
        assert_eq!(winston.to_plain_string(), "100");

        let ar = Money::<AR>::try_from(BigDecimal::from_str("1.5").unwrap()).unwrap();
        assert_eq!(ar.to_plain_string(), "1.500000000000");

        // from_str
        let winston_str = Money::<Winston>::from_str("42").unwrap();
        assert_eq!(winston_str.to_plain_string(), "42");

        let ar_str = Money::<AR>::from_str("3.14159").unwrap();
        assert_eq!(ar_str.to_plain_string(), "3.141590000000");

        // zero constructor
        let winston_zero = Money::<Winston>::zero();
        assert_eq!(winston_zero.to_plain_string(), "0");

        let ar_zero = Money::<AR>::zero();
        assert_eq!(ar_zero.to_plain_string(), "0.000000000000");
    }

    #[test]
    fn test_currency_ext_trait() {
        let winston = Winston::try_new(100).unwrap();
        assert_eq!(winston.to_plain_string(), "100");

        let ar = AR::from_str("2.5").unwrap();
        assert_eq!(ar.to_plain_string(), "2.500000000000");
    }

    #[test]
    fn test_scale_normalization() {
        // Values should be normalized to currency precision
        let winston = Money::<Winston>::try_from(BigDecimal::from_str("100.0").unwrap()).unwrap();
        assert_eq!(winston.to_plain_string(), "100");

        let ar1 = Money::<AR>::try_from(BigDecimal::from_str("1").unwrap()).unwrap();
        assert_eq!(ar1.to_plain_string(), "1.000000000000");

        let ar2 = Money::<AR>::try_from(BigDecimal::from_str("1.5").unwrap()).unwrap();
        assert_eq!(ar2.to_plain_string(), "1.500000000000");
    }

    #[test]
    fn test_addition() {
        let w1 = Money::<Winston>::try_from(100).unwrap();
        let w2 = Money::<Winston>::try_from(50).unwrap();
        let result = w1 + w2;
        assert_eq!(result.to_plain_string(), "150");

        let ar1 = Money::<AR>::try_from(BigDecimal::from_str("1.5").unwrap()).unwrap();
        let ar2 = Money::<AR>::try_from(BigDecimal::from_str("2.3").unwrap()).unwrap();

        let result = ar1 + ar2;
        assert_eq!(result.to_plain_string(), "3.800000000000");
    }

    #[test]
    fn test_subtraction() {
        let w1 = Money::<Winston>::try_from(100).unwrap();
        let w2 = Money::<Winston>::try_from(30).unwrap();
        let result = w1 - w2;
        assert_eq!(result.to_plain_string(), "70");

        let ar1 = Money::<AR>::try_from(BigDecimal::from_str("5.5").unwrap()).unwrap();
        let ar2 = Money::<AR>::try_from(BigDecimal::from_str("2.3").unwrap()).unwrap();
        let result = ar1 - ar2;
        assert_eq!(result.to_plain_string(), "3.200000000000");
    }

    #[test]
    fn test_multiplication() {
        let winston = Money::<Winston>::try_from(100).unwrap();
        let result = winston * BigDecimal::from_str("2.5").unwrap();
        assert_eq!(result.to_plain_string(), "250");

        let ar = Money::<AR>::try_from(BigDecimal::from_str("1.5").unwrap()).unwrap();
        let result = ar * 3;
        assert_eq!(result.to_plain_string(), "4.500000000000");
    }

    #[test]
    fn test_division_with_rounding() {
        let winston = Money::<Winston>::try_from(100).unwrap();
        let result = winston / 3;
        assert_eq!(result.to_plain_string(), "33"); // Rounded down

        let winston2 = Money::<Winston>::try_from(101).unwrap();
        let result2 = winston2 / 3;
        assert_eq!(result2.to_plain_string(), "34"); // Rounded up (HalfEven)

        let ar = Money::<AR>::try_from(1).unwrap();
        let result = ar / 3;
        assert_eq!(result.to_plain_string(), "0.333333333333");
    }

    #[test]
    fn test_equality() {
        let w1 = Money::<Winston>::try_from(100).unwrap();
        let w2 = Money::<Winston>::try_from(100).unwrap();
        let w3 = Money::<Winston>::try_from(101).unwrap();

        assert_eq!(w1, w2);
        assert_ne!(w1, w3);

        let ar1 = Money::<AR>::try_from(BigDecimal::from_str("1.5").unwrap()).unwrap();
        let ar2 = Money::<AR>::try_from(BigDecimal::from_str("1.500000000000").unwrap()).unwrap();
        assert_eq!(ar1, ar2);
    }

    #[test]
    fn test_ordering() {
        let w1 = Money::<Winston>::try_from(100).unwrap();
        let w2 = Money::<Winston>::try_from(200).unwrap();
        let w3 = Money::<Winston>::try_from(50).unwrap();

        assert!(w1 < w2);
        assert!(w2 > w1);
        assert!(w1 > w3);

        let ar1 = Money::<AR>::try_from(BigDecimal::from_str("1.5").unwrap()).unwrap();
        let ar2 = Money::<AR>::try_from(BigDecimal::from_str("2.0").unwrap()).unwrap();
        assert!(ar1 < ar2);
    }

    #[test]
    fn test_display_formatting() {
        let winston = Money::<Winston>::try_from(100).unwrap();
        assert_eq!(format!("{}", winston), "W 100");
        assert_eq!(format!("{:?}", winston), "W 100");

        let ar = Money::<AR>::try_from(BigDecimal::from_str("1.5").unwrap()).unwrap();
        assert_eq!(format!("{}", ar), "AR 1.500000000000");
        assert_eq!(format!("{:?}", ar), "AR 1.500000000000");
    }

    #[test]
    fn test_stringify_trait() {
        let winston = Money::<Winston>::try_from(100).unwrap();
        let winston_str: std::borrow::Cow<str> = Money::<Winston>::to_plain_string(&winston).into();
        assert_eq!(winston_str, "100");

        let parsed = Money::<Winston>::from_str("200.0").unwrap();
        assert_eq!(parsed.to_plain_string(), "200");

        let ar = Money::<AR>::try_from(BigDecimal::from_str("3.14").unwrap()).unwrap();
        let ar_str: std::borrow::Cow<str> = Money::<AR>::to_plain_string(&ar).into();
        assert_eq!(ar_str, "3.140000000000");
    }

    #[test]
    fn test_parse_errors() {
        assert!(matches!(
            Money::<Winston>::from_str("invalid"),
            Err(ParseError(_))
        ));

        assert!(matches!(
            Money::<Winston>::from_str("1.5"),
            Err(PrecisionError {
                supported: 0,
                found: 1
            })
        ));

        assert!(matches!(
            Money::<AR>::from_str("1.1234567890123"),
            Err(PrecisionError {
                supported: 12,
                found: 13
            })
        ));
    }

    #[test]
    fn test_negative_values() {
        let winston = Money::<Winston>::try_from(-100).unwrap();
        assert_eq!(winston.to_plain_string(), "-100");

        let ar = Money::<AR>::try_from(BigDecimal::from_str("-1.5").unwrap()).unwrap();
        assert_eq!(ar.to_plain_string(), "-1.500000000000");

        // Arithmetic with negatives
        let w1 = Money::<Winston>::try_from(100).unwrap();
        let w2 = Money::<Winston>::try_from(-50).unwrap();
        assert_eq!((w1 + w2).to_plain_string(), "50");
    }

    #[test]
    fn test_zero_values() {
        let winston_zero = Money::<Winston>::zero();
        let ar_zero = Money::<AR>::zero();

        assert_eq!(winston_zero.to_plain_string(), "0");
        assert_eq!(ar_zero.to_plain_string(), "0.000000000000");

        // Operations with zero
        let winston = Money::<Winston>::try_from(100).unwrap();
        assert_eq!(
            (winston.clone() + winston_zero.clone()).to_plain_string(),
            "100"
        );
        assert_eq!((winston - winston_zero).to_plain_string(), "100");
    }

    #[test]
    fn test_edge_case_precision_limits() {
        // Test exactly at precision limit for AR
        let ar_max_precision =
            Money::<AR>::try_from(BigDecimal::from_str("1.123456789012").unwrap()).unwrap();
        assert_eq!(ar_max_precision.to_plain_string(), "1.123456789012");

        // Test one decimal place over limit
        assert!(matches!(
            Money::<AR>::try_from(BigDecimal::from_str("1.1234567890123").unwrap()),
            Err(PrecisionError {
                supported: 12,
                found: 13
            })
        ));
    }

    #[test]
    fn test_large_numbers() {
        let large_winston =
            Money::<Winston>::try_from(BigDecimal::from_str("999999999999999999").unwrap())
                .unwrap();
        assert_eq!(large_winston.to_plain_string(), "999999999999999999");

        let large_ar =
            Money::<AR>::try_from(BigDecimal::from_str("999999999999.123456789012").unwrap())
                .unwrap();
        assert_eq!(large_ar.to_plain_string(), "999999999999.123456789012");
    }

    #[test]
    fn test_ar_to_winston_conversion_implicit() {
        let ar = Money::<AR>::try_from(1).unwrap(); // 1 AR
        let winston: Money<Winston> = ar.convert();
        assert_eq!(winston.to_plain_string(), "1000000000000"); // 1 trillion winston
    }

    #[test]
    fn test_winston_to_ar_conversion_implicit() {
        let winston = Money::<Winston>::try_from(1000000000000u64).unwrap(); // 1 trillion winston
        let ar: Money<AR> = winston.convert();
        assert_eq!(ar.to_plain_string(), "1.000000000000"); // 1 AR
    }

    #[test]
    fn test_same_currency_conversion() {
        let winston = Money::<Winston>::try_from(100).unwrap();
        let winston_converted: Money<Winston> = winston.convert();
        assert_eq!(winston_converted.to_plain_string(), "100");

        let ar = Money::<AR>::try_from(BigDecimal::from_str("2.5").unwrap()).unwrap();
        let ar_converted: Money<AR> = ar.convert();
        assert_eq!(ar_converted.to_plain_string(), "2.500000000000");
    }

    #[test]
    fn test_fractional_ar_to_winston_conversion() {
        let ar = Money::<AR>::try_from(BigDecimal::from_str("0.5").unwrap()).unwrap(); // 0.5 AR
        let winston: Money<Winston> = ar.convert();
        assert_eq!(winston.to_plain_string(), "500000000000"); // 0.5 trillion winston
    }

    #[test]
    fn test_fractional_winston_to_ar_conversion() {
        let winston = Money::<Winston>::try_from(500000000000u64).unwrap(); // 0.5 trillion winston
        let ar: Money<AR> = winston.convert();
        assert_eq!(ar.to_plain_string(), "0.500000000000"); // 0.5 AR
    }

    #[test]
    fn test_conversion_with_rounding() {
        // Test conversion that requires rounding
        let winston = Money::<Winston>::try_from(1).unwrap(); // 1 winston
        let ar: Money<AR> = winston.convert();
        // 1 winston = 0.000000000001 AR
        assert_eq!(ar.to_plain_string(), "0.000000000001");
    }

    #[test]
    fn test_cross_currency_arithmetic() {
        let ar = Money::<AR>::try_from(1).unwrap(); // 1 AR
        let winston = Money::<Winston>::try_from(1000000000000u64).unwrap(); // 1 trillion winston (= 1 AR)

        // Addition with conversion
        let result = ar + winston; // winston should be converted to AR
        assert_eq!(result.to_plain_string(), "2.000000000000"); // 2 AR

        // Subtraction with conversion
        let ar2 = Money::<AR>::try_from(BigDecimal::from_str("0.5").unwrap()).unwrap();
        let winston2 = Money::<Winston>::try_from(250000000000u64).unwrap(); // 0.25 trillion winston (= 0.25 AR)
        let result = ar2 - winston2; // winston2 should be converted to AR
        assert_eq!(result.to_plain_string(), "0.250000000000"); // 0.25 AR
    }

    #[test]
    fn test_zero_conversion() {
        let winston_zero = Money::<Winston>::zero();
        let ar_zero: Money<AR> = winston_zero.convert();
        assert_eq!(ar_zero.to_plain_string(), "0.000000000000");

        let ar_zero = Money::<AR>::zero();
        let winston_zero: Money<Winston> = ar_zero.convert();
        assert_eq!(winston_zero.to_plain_string(), "0");
    }

    #[test]
    fn test_negative_conversion() {
        let ar = Money::<AR>::try_from(BigDecimal::from_str("-1.5").unwrap()).unwrap();
        let winston: Money<Winston> = ar.convert();
        assert_eq!(winston.to_plain_string(), "-1500000000000");

        let winston = Money::<Winston>::try_from(-2000000000000i64).unwrap();
        let ar: Money<AR> = winston.convert();
        assert_eq!(ar.to_plain_string(), "-2.000000000000");
    }

    #[test]
    fn test_large_number_conversion() {
        let large_ar =
            Money::<AR>::try_from(BigDecimal::from_str("999999.123456789012").unwrap()).unwrap();
        let winston: Money<Winston> = large_ar.convert();
        assert_eq!(winston.to_plain_string(), "999999123456789012");

        let large_winston =
            Money::<Winston>::try_from(BigDecimal::from_str("123456789012345").unwrap()).unwrap();
        let ar: Money<AR> = large_winston.convert();
        assert_eq!(ar.to_plain_string(), "123.456789012345");
    }

    #[test]
    fn test_conversion_precision_handling() {
        // Test that conversions maintain proper precision for target currency
        let ar = Money::<AR>::try_from(BigDecimal::from_str("1.123456789012").unwrap()).unwrap();
        let winston: Money<Winston> = ar.convert();
        // Converting back should preserve the original value
        let ar_back: Money<AR> = winston.convert();
        assert_eq!(ar_back.to_plain_string(), "1.123456789012");
    }
}
