use crate::typed::{Typed, WithSerde};
use serde::Serializer;
use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

pub struct NetworkIdKind;
pub type NetworkIdentifier = Typed<NetworkIdKind, Cow<'static, str>>;

impl WithSerde for NetworkIdentifier {}

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid network identifier: {0}")]
    InvalidNetworkIdentifier(Cow<'static, str>),
}

impl NetworkIdentifier {
    pub(crate) const fn try_new(name: Cow<'static, str>) -> Result<Self, Error> {
        if !Self::is_valid(&name) {
            return Err(Error::InvalidNetworkIdentifier(name));
        }
        Ok(Self::new_from_inner(name))
    }
    pub(crate) const fn new_const(name: Cow<'static, str>) -> Self {
        if !Self::is_valid(&name) {
            panic!("invalid network identifier");
        };
        Self::new_from_inner(name)
    }

    const fn is_valid(name: &Cow<'static, str>) -> bool {
        let bytes = match name {
            Cow::Borrowed(s) => s.as_bytes(),
            Cow::Owned(s) => s.as_bytes(),
        };

        if bytes.len() < 3 || bytes.len() > 100 {
            return false;
        }

        let mut i = 0;
        while i < bytes.len() {
            let byte = bytes[i];
            let is_valid_char = matches!(byte,
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_'
            );
            if !is_valid_char {
                return false;
            }
            i += 1;
        }

        true
    }
}

impl TryFrom<&'static str> for NetworkIdentifier {
    type Error = Error;

    fn try_from(value: &'static str) -> Result<Self, Self::Error> {
        Cow::Borrowed(value).try_into()
    }
}

impl TryFrom<String> for NetworkIdentifier {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Cow::<'static, str>::Owned(value).try_into()
    }
}

impl TryFrom<Cow<'static, str>> for NetworkIdentifier {
    type Error = Error;

    fn try_from(value: Cow<'static, str>) -> Result<Self, Self::Error> {
        NetworkIdentifier::try_new(value)
    }
}

impl Display for NetworkIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.serialize_str(self.0.as_ref())
    }
}

pub trait Network: Clone + Debug + Send + Sync + 'static {
    fn id(&self) -> &NetworkIdentifier;
}

static MAINNET_ID: NetworkIdentifier = NetworkIdentifier::new_const(Cow::Borrowed("arweave.N.1"));

#[derive(Clone, Debug)]
pub struct Mainnet;

impl Network for Mainnet {
    fn id(&self) -> &NetworkIdentifier {
        &MAINNET_ID
    }
}

#[derive(Clone, Debug)]
pub struct Testnet;
static TESTNET_ID: NetworkIdentifier =
    NetworkIdentifier::new_const(Cow::Borrowed("arweave.testnet.N.1"));

impl Network for Testnet {
    fn id(&self) -> &NetworkIdentifier {
        &TESTNET_ID
    }
}

static LOCAL_ID: NetworkIdentifier =
    NetworkIdentifier::new_const(Cow::Borrowed("arweave.localtest"));

#[derive(Clone, Debug)]
pub struct Local;

impl Network for Local {
    fn id(&self) -> &NetworkIdentifier {
        &LOCAL_ID
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Custom {
    id: NetworkIdentifier,
}

impl Network for Custom {
    fn id(&self) -> &NetworkIdentifier {
        &self.id
    }
}

impl From<NetworkIdentifier> for Custom {
    fn from(id: NetworkIdentifier) -> Self {
        Self { id }
    }
}

#[cfg(test)]
mod tests {
    use crate::network::NetworkIdentifier;

    #[test]
    fn local() -> anyhow::Result<()> {
        let _ = NetworkIdentifier::try_from("foobar123")?;
        assert!(NetworkIdentifier::try_from("    sfvjwl   493  ").is_err());
        Ok(())
    }
}
