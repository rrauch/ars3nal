pub(crate) mod coingecko;

use crate::fx::fiat::{CNY, EUR, GBP, JPY, USD};
use ario_core::BigDecimal;
use ario_core::money::{AR, ConversionRate, Currency, Money};
use bon::bon;
use std::fmt::Display;
use std::marker::PhantomData;
use std::ops::Deref;
use std::time::{Duration, SystemTime};
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub struct FxService {
    current: watch::Receiver<Rates>,
    jh: JoinHandle<()>,
}

#[bon]
impl FxService {
    #[tracing::instrument(fields(backend = XE::NAME), skip(xe_source))]
    #[builder]
    pub async fn new<XE: XeSource + Send + 'static>(
        xe_source: XE,
        #[builder(default = Duration::from_secs(300))] refresh_interval: Duration,
        #[builder(default = Duration::from_secs(900))] retry_interval: Duration,
    ) -> Result<Self, XE::Error> {
        let (tx, rx) = watch::channel(xe_source.retrieve().await?);
        let jh = tokio::spawn(async move {
            refresh_task(xe_source, tx, refresh_interval, retry_interval).await;
        });
        tracing::info!("FxService started");
        Ok(Self { current: rx, jh })
    }
}

#[tracing::instrument(skip(xe_source, sender))]
async fn refresh_task<XE: XeSource>(
    xe_source: XE,
    sender: watch::Sender<Rates>,
    refresh_interval: Duration,
    retry_interval: Duration,
) {
    let mut next_attempt = SystemTime::now() + refresh_interval;
    loop {
        let sleep_duration = next_attempt
            .duration_since(SystemTime::now())
            .ok()
            .unwrap_or_else(|| Duration::from_millis(0));

        tracing::debug!(
            next_refresh_in_secs = sleep_duration.as_secs(),
            "fx rate refresh attempt"
        );
        tokio::time::sleep(sleep_duration).await;
        tracing::debug!("fx rate refresh start");
        let start = SystemTime::now();
        let res = xe_source.retrieve().await;
        let duration = SystemTime::now().duration_since(start).unwrap_or_default();
        tracing::debug!(
            duration_millis = duration.as_millis(),
            success = res.is_ok(),
            "fx rate refresh complete"
        );
        match res {
            Ok(rates) => {
                if sender.send(rates).is_err() {
                    // no more listeners, shut down now
                    break;
                }
                next_attempt = SystemTime::now() + refresh_interval;
            }
            Err(err) => {
                tracing::error!(error = %err, "fx rate refresh failed");
                next_attempt = SystemTime::now() + retry_interval;
            }
        }
    }

    // shutting down fx rate refresher
    tracing::info!("FxService shutting down");
}

impl Drop for FxService {
    fn drop(&mut self) {
        self.jh.abort();
    }
}

trait SupportedCurrency: Currency {
    fn get_xe(rates: &Rates) -> &Rate<Self>
    where
        Self: Sized;
}

impl FxService {
    pub fn convert<C: SupportedCurrency>(&self, amount: Money<C>) -> Money<AR> {
        let current_rates = self.current.borrow();
        let rate = C::get_xe(current_rates.deref());
        amount.convert_with(rate)
    }
}

pub trait XeSource {
    const NAME: &'static str;
    type Error: Send + Display;

    fn retrieve(&self) -> impl Future<Output = Result<Rates, Self::Error>> + Send;
}

#[derive(Clone, PartialEq)]
#[repr(transparent)]
pub struct Rate<C: Currency>(BigDecimal, PhantomData<C>);

impl<C: Currency> Rate<C> {
    pub fn new(multiplier: BigDecimal) -> Rate<C> {
        Self(multiplier, PhantomData::default())
    }
}

impl<C: Currency> ConversionRate<C, AR> for Rate<C> {
    fn multiplier(&self) -> &BigDecimal {
        &self.0
    }
}

#[derive(Clone)]
pub struct Rates {
    usd: Rate<USD>,
    eur: Rate<EUR>,
    cny: Rate<CNY>,
    jpy: Rate<JPY>,
    gbp: Rate<GBP>,
}

impl Rates {
    pub fn new(
        usd: Rate<USD>,
        eur: Rate<EUR>,
        cny: Rate<CNY>,
        jpy: Rate<JPY>,
        gbp: Rate<GBP>,
    ) -> Self {
        Self {
            usd,
            eur,
            cny,
            jpy,
            gbp,
        }
    }
}

pub mod fiat {
    use crate::fx::{Rate, Rates, SupportedCurrency};
    use ario_core::money::Currency;

    #[derive(PartialEq, Clone, Debug, Hash)]
    pub struct USD;

    impl Currency for USD {
        const DECIMAL_POINTS: u16 = 2;
        const SYMBOL: &'static str = "USD";
    }

    impl SupportedCurrency for USD {
        fn get_xe(rates: &Rates) -> &Rate<Self> {
            &rates.usd
        }
    }

    #[derive(PartialEq, Clone, Debug, Hash)]
    pub struct EUR;

    impl Currency for EUR {
        const DECIMAL_POINTS: u16 = 2;
        const SYMBOL: &'static str = "EUR";
    }

    impl SupportedCurrency for EUR {
        fn get_xe(rates: &Rates) -> &Rate<Self> {
            &rates.eur
        }
    }

    #[derive(PartialEq, Clone, Debug, Hash)]
    pub struct CNY;

    impl Currency for CNY {
        const DECIMAL_POINTS: u16 = 2;
        const SYMBOL: &'static str = "CNY";
    }

    impl SupportedCurrency for CNY {
        fn get_xe(rates: &Rates) -> &Rate<Self> {
            &rates.cny
        }
    }

    #[derive(PartialEq, Clone, Debug, Hash)]
    pub struct JPY;

    impl Currency for JPY {
        const DECIMAL_POINTS: u16 = 2;
        const SYMBOL: &'static str = "JPY";
    }

    impl SupportedCurrency for JPY {
        fn get_xe(rates: &Rates) -> &Rate<Self> {
            &rates.jpy
        }
    }

    #[derive(PartialEq, Clone, Debug, Hash)]
    pub struct GBP;

    impl Currency for GBP {
        const DECIMAL_POINTS: u16 = 2;
        const SYMBOL: &'static str = "GBP";
    }

    impl SupportedCurrency for GBP {
        fn get_xe(rates: &Rates) -> &Rate<Self> {
            &rates.gbp
        }
    }
}
