use ario_core::*;
use std::str::FromStr;

pub fn foo() {
    let tx_id = TxId::from_str("Kx7IKKdBzaYiZpYLgtL5tWoOseFt0vjXQMyirrTPc-E").unwrap();
    println!("{:?}", tx_id);
}
