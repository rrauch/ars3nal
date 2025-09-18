use crate::api::RequestMethod::Post;
use crate::api::{Api, ApiRequest, ApiRequestBody, ContentType, ViaJson};
use crate::{Client, api};
use ario_core::Gateway;
use bytesize::ByteSize;
pub use cynic::QueryBuilder as GraphQlQueryBuilder;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use cynic;

#[cynic::schema("arweave")]
pub mod schema {}

pub trait QueryBuilder<V: Serialize>: GraphQlQueryBuilder<V> + for<'de> Deserialize<'de> {}
impl<V: Serialize, Q: GraphQlQueryBuilder<V> + for<'de> Deserialize<'de>> QueryBuilder<V> for Q where
    Q: cynic::QueryFragment<SchemaType = schema::Query>
{
}

#[derive(Error, Debug)]
pub enum GraphQlError {
    #[error("graphql error: {0}")]
    Other(String),
}

impl Api {
    async fn graphql_query<V: Serialize, Q: QueryBuilder<V>>(
        &self,
        gateway: &Gateway,
        variables: V,
    ) -> Result<Option<Q>, api::Error> {
        let query = Q::build(variables);

        let req = ApiRequest::builder()
            .endpoint(gateway.join("./graphql").map_err(api::Error::InvalidUrl)?)
            .request_method(Post)
            .max_response_len(ByteSize::mib(1))
            .body(
                ApiRequestBody::builder()
                    .content_type(ContentType::Json)
                    .payload((&query).try_into()?)
                    .build(),
            )
            .build();

        let resp = self
            .send_api_request::<ViaJson<cynic::GraphQlResponse<Q>>>(req)
            .await?
            .0;

        if let Some(mut errors) = resp.errors {
            if !errors.is_empty() {
                return Err(GraphQlError::Other(errors.drain(..).next().unwrap().message).into());
            }
        }

        Ok(resp.data)
    }
}

impl Client {
    pub async fn graphql_query<V: Serialize, Q: QueryBuilder<V>>(
        &self,
        variables: V,
    ) -> Result<Option<Q>, super::Error> {
        Ok(self
            .with_gw(async |gw| self.0.api.graphql_query(gw, variables).await)
            .await?)
    }
}

#[cfg(feature = "graphql-codegen")]
pub fn register_schema() {
    cynic_codegen::register_schema("arweave")
        .from_sdl(include_str!("../graphql/arweave-schema.graphql"))
        .unwrap()
        .as_default()
        .unwrap();
}

#[cfg(test)]
mod tests {
    use crate::api::Api;
    use crate::graphql::schema;
    use ario_core::Gateway;
    use ario_core::network::Network;
    use cynic::QueryFragment;
    use reqwest::Client;
    use std::str::FromStr;

    #[derive(cynic::QueryVariables, Debug)]
    pub struct TxByIdQueryVariables<'a> {
        pub tx_id: &'a cynic::Id,
    }

    #[derive(cynic::QueryFragment, Debug)]
    #[cynic(graphql_type = "Query", variables = "TxByIdQueryVariables")]
    pub struct TxByIdQuery {
        #[arguments(id: $tx_id)]
        pub transaction: Option<Transaction>,
    }

    #[derive(cynic::QueryFragment, Debug)]
    pub struct Transaction {
        pub id: cynic::Id,
    }

    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_test_writer()
            .try_init();
    }

    #[ignore]
    #[tokio::test]
    async fn tx_query_live() -> anyhow::Result<()> {
        let gw = Gateway::from_str("https://arweave.net")?;
        let api = Api::new(Client::new(), Network::default(), false);

        init_tracing();

        let tx = api
            .graphql_query::<_, TxByIdQuery>(
                &gw,
                TxByIdQueryVariables {
                    tx_id: (&"G-1t0Lqysin897HC3IV8xu_Mr884B-Mo5YEnlhUH54k".to_string()).into(),
                },
            )
            .await?;
        assert_eq!(
            tx.unwrap().transaction.unwrap().id.inner(),
            "G-1t0Lqysin897HC3IV8xu_Mr884B-Mo5YEnlhUH54k"
        );
        Ok(())
    }
}
