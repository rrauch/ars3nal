pub(crate) mod serde_tag;
mod types;

#[cfg(test)]
mod tests {
    use ario_client::Client;
    use ario_client::graphql::{TxQuery, TxQueryFilterCriteria};
    use ario_core::Gateway;
    use ario_core::network::Network;
    use ario_core::tx::TxId;
    use futures_lite::stream::StreamExt;
    use std::str::FromStr;

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    #[ignore]
    #[tokio::test]
    async fn foo() -> anyhow::Result<()> {
        dotenv::dotenv().ok();
        init_tracing();

        let arlocal = std::env::var("ARLOCAL_URL").unwrap();
        let network_id = std::env::var("ARLOCAL_ID").unwrap_or("arlocal".to_string());

        let client = Client::builder()
            .network(Network::Local(network_id.try_into()?))
            .gateways([Gateway::from_str(arlocal.as_str())?])
            .enable_netwatch(false)
            .build()
            .await?;

        let filter_criteria = TxQueryFilterCriteria::builder()
            .ids([TxId::from_str(
                "pN4sJr5CEuJzt2qPT9_hVlagEcHAStaTWo5HWcH1YWg",
            )?])
            .build();

        let tx_query = TxQuery::builder().filter_criteria(filter_criteria).build();

        let mut stream = client.query_transactions(tx_query);
        while let Some(item) = stream.try_next().await? {
            println!("item: {:?}", item);
        }
        Ok(())
    }
}
