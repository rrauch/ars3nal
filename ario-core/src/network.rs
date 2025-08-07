use crate::typed::Typed;
use bon::Builder;
use serde::Serializer;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};

pub struct NetworkIdKind;
pub type NetworkIdentifier = Typed<NetworkIdKind, Cow<'static, str>>;

impl NetworkIdentifier {
    pub(crate) const fn new(name: Cow<'static, str>) -> Self {
        Self::new_from_inner(name)
    }
}

impl Display for NetworkIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.serialize_str(self.0.as_ref())
    }
}

pub trait Network {
    fn id(&self) -> &NetworkIdentifier;
}

static MAINNET_ID: NetworkIdentifier = NetworkIdentifier::new(Cow::Borrowed("arweave.N.1"));

pub struct Mainnet;

impl Network for Mainnet {
    fn id(&self) -> &NetworkIdentifier {
        &MAINNET_ID
    }
}

pub struct Testnet;
static TESTNET_ID: NetworkIdentifier = NetworkIdentifier::new(Cow::Borrowed("arweave.testnet.N.1"));

impl Network for Testnet {
    fn id(&self) -> &NetworkIdentifier {
        &TESTNET_ID
    }
}

static DEFAULT_LOCAL_ID: NetworkIdentifier =
    NetworkIdentifier::new(Cow::Borrowed("arweave.localtest"));

#[derive(Builder, Debug, Clone, PartialEq, PartialOrd)]
pub struct Local {
    #[builder(with = |id: impl Into<Cow<'static, str>>|{
         NetworkIdentifier::new(id.into())
    }, default = DEFAULT_LOCAL_ID.clone())]
    id: NetworkIdentifier,
}

impl Network for Local {
    fn id(&self) -> &NetworkIdentifier {
        &self.id
    }
}
