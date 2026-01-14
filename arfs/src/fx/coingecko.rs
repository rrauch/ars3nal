use crate::fx::fiat::{CNY, EUR, GBP, JPY, USD};
use crate::fx::{Rates, XeSource};
use ario_core::money::{ConversionRate, Currency, Money};
use ario_core::{BigDecimal, money};
use reqwest::StatusCode;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

pub struct CoinGecko {
    client: reqwest::Client,
}

impl Default for CoinGecko {
    fn default() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("ArFS/0.1") // CoinGecko API requires a user agent
                .build()
                .expect("reqwest client builder to succeed"),
        }
    }
}

#[derive(Error, Debug)]
pub enum CoinGeckoError {
    #[error(transparent)]
    HttpError(#[from] reqwest::Error),
    #[error("rate limit reached, try again later")]
    RateLimitReached,
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    MoneyError(#[from] money::MoneyError),
    #[error("exchange rate missing for currency '{0}'")]
    ExchangeRateMissing(&'static str),
}

impl XeSource for CoinGecko {
    type Error = CoinGeckoError;

    async fn retrieve(&self) -> Result<Rates, Self::Error> {
        let resp = self
            .client
            .get("https://api.coingecko.com/api/v3/simple/price?ids=arweave&vs_currencies=usd,eur,cny,jpy,gbp")
            .timeout(Duration::from_secs(15))
            .send()
            .await?;

        let resp = match resp.status() {
            StatusCode::TOO_MANY_REQUESTS => Err(CoinGeckoError::RateLimitReached),
            _ => resp.error_for_status().map_err(|e| e.into()),
        }?;

        let body = resp.bytes().await?;

        Ok(deserialize_response(body.as_ref())?)
    }
}

fn deserialize_response(bytes: &[u8]) -> Result<Rates, CoinGeckoError> {
    let mut usd = None;
    let mut eur = None;
    let mut cny = None;
    let mut jpy = None;
    let mut gbp = None;

    for (symbol, value) in
        serde_json::from_slice::<HashMap<String, HashMap<String, BigDecimal>>>(bytes)?.into_iter()
    {
        if symbol.eq_ignore_ascii_case("arweave") {
            for (symbol, value) in value.into_iter() {
                if symbol.eq_ignore_ascii_case(USD::SYMBOL) {
                    usd = Some(Money::try_from(value)?);
                } else if symbol.eq_ignore_ascii_case(EUR::SYMBOL) {
                    eur = Some(Money::try_from(value)?);
                } else if symbol.eq_ignore_ascii_case(CNY::SYMBOL) {
                    cny = Some(Money::try_from(value)?);
                } else if symbol.eq_ignore_ascii_case(JPY::SYMBOL) {
                    jpy = Some(Money::try_from(value)?);
                } else if symbol.eq_ignore_ascii_case(GBP::SYMBOL) {
                    gbp = Some(Money::try_from(value)?);
                }
            }
        }
    }
    Ok(Rates::new(
        usd.ok_or_else(|| CoinGeckoError::ExchangeRateMissing(USD::SYMBOL))?,
        eur.ok_or_else(|| CoinGeckoError::ExchangeRateMissing(EUR::SYMBOL))?,
        cny.ok_or_else(|| CoinGeckoError::ExchangeRateMissing(CNY::SYMBOL))?,
        jpy.ok_or_else(|| CoinGeckoError::ExchangeRateMissing(JPY::SYMBOL))?,
        gbp.ok_or_else(|| CoinGeckoError::ExchangeRateMissing(GBP::SYMBOL))?,
    ))
}

#[cfg(test)]
mod tests {
    use crate::fx::XeSource;
    use crate::fx::coingecko::{CoinGecko, deserialize_response};
    use ario_core::BigDecimal;
    use ario_core::money::ConversionRate;
    use ario_core::money::Money;
    use std::str::FromStr;

    #[test]
    fn test_deserialize() -> anyhow::Result<()> {
        let json_ok = r#"
        {"arweave":{"usd":4.13,"eur":3.55,"cny":28.83,"jpy":653.83,"gbp":3.07}}
        "#;

        let json_no_arweave = r#"
        {"foo":{"usd":4.13}}
        "#;

        let xe = deserialize_response(json_ok.as_bytes())?;
        assert_eq!(xe.usd.0, Money::from_str("4.13")?);
        assert_eq!(xe.eur.0, Money::from_str("3.55")?);
        assert_eq!(xe.cny.0, Money::from_str("28.83")?);
        assert_eq!(xe.jpy.0, Money::from_str("653.83")?);
        assert_eq!(xe.gbp.0, Money::from_str("3.07")?);

        let xe = deserialize_response(json_no_arweave.as_bytes());
        assert!(xe.is_err());

        Ok(())
    }

    #[ignore]
    #[tokio::test]
    async fn test_live() -> anyhow::Result<()> {
        let ck = CoinGecko::default();
        let xe = ck.retrieve().await?;

        let multiplier = xe.usd.multiplier();
        assert!(multiplier > &BigDecimal::from_str("0")?);
        assert!(multiplier < &BigDecimal::from_str("1000")?);
        Ok(())
    }
}
