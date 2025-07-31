use crate::blob::Blob;
use crate::{JsonError, JsonValue};

pub trait JsonSource {
    fn try_into_json(self) -> Result<JsonValue, JsonError>;
}

impl JsonSource for JsonValue {
    fn try_into_json(self) -> Result<JsonValue, JsonError> {
        Ok(self)
    }
}

impl JsonSource for &Vec<u8> {
    fn try_into_json(self) -> Result<JsonValue, JsonError> {
        serde_json::from_slice(self.as_slice())
    }
}

impl JsonSource for &[u8] {
    fn try_into_json(self) -> Result<JsonValue, JsonError> {
        serde_json::from_slice(self)
    }
}

impl JsonSource for &str {
    fn try_into_json(self) -> Result<JsonValue, JsonError> {
        serde_json::from_str(self)
    }
}

impl JsonSource for &String {
    fn try_into_json(self) -> Result<JsonValue, JsonError> {
        serde_json::from_str(self.as_str())
    }
}

impl JsonSource for &Blob<'_> {
    fn try_into_json(self) -> Result<JsonValue, JsonError> {
        serde_json::from_slice(self.bytes())
    }
}
