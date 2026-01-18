use crate::{FxService, PriceAdjustment, PriceLimit};
use ario_client::{ByteSize, Client};
use ario_core::money::{Money, Winston};
use ario_core::wallet::{Wallet, WalletAddress};
use async_trait::async_trait;
use bon::bon;
use std::fmt::Display;
use std::sync::Arc;
use thiserror::Error;

pub struct Uploader {
    client: Client,
    mode: Box<dyn UploadMode + Send + Sync + 'static>,
    price_limit: Option<PriceLimit>,
    fx_service: Option<Arc<FxService>>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("fx_service is required due to fiat price limit")]
    FxServiceRequired,
}

#[bon]
impl Uploader {
    #[builder]
    pub fn new(
        client: Client,
        mode: Box<dyn UploadMode + Send + Sync + 'static>,
        price_limit: Option<PriceLimit>,
        fx_service: Option<Arc<FxService>>,
    ) -> Result<Self, Error> {
        if let Some(price_limit) = price_limit.as_ref() {
            if !price_limit.is_native() && fx_service.is_none() {
                Err(Error::FxServiceRequired)?
            }
        }

        Ok(Self {
            client,
            mode,
            price_limit,
            fx_service,
        })
    }
}

pub struct Direct {
    client: Client,
    wallet: Wallet,
    address: WalletAddress,
    price_adjustment: PriceAdjustment,
}

impl Direct {
    pub fn new(client: Client, wallet: Wallet, price_adjustment: PriceAdjustment) -> Self {
        Self {
            client,
            address: wallet.address(),
            wallet,
            price_adjustment,
        }
    }
}

#[derive(Error, Debug)]
pub enum UploadModeError {
    #[error("backend error: {0}")]
    BackendError(String),
}

#[async_trait]
impl UploadMode for Direct {
    async fn current_price(&self, data_size: ByteSize) -> Result<Money<Winston>, UploadModeError> {
        Ok(self
            .client
            .price(data_size.as_u64(), Some(&self.address))
            .await
            .map_err(|e| UploadModeError::BackendError(e.to_string()))?)
    }
}

pub struct Turbo;

impl Turbo {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl UploadMode for Turbo {
    async fn current_price(&self, data_size: ByteSize) -> Result<Money<Winston>, UploadModeError> {
        todo!()
    }
}

#[async_trait]
pub trait UploadMode {
    async fn current_price(&self, data_size: ByteSize) -> Result<Money<Winston>, UploadModeError>;
}
