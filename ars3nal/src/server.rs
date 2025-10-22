use crate::s3::ArS3;

use arfs::ArFs;
use http::{Extensions, HeaderMap, Method, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use s3s::route::S3Route;
use s3s::service::S3ServiceBuilder;
use s3s::{Body, S3Request, S3Response, S3Result};
use tokio::net::TcpListener;
use tokio_util::sync::{CancellationToken, DropGuard};
use tower::Service;

pub struct Server {
    ct: CancellationToken,
    listener: TcpListener,
    ars3s: ArS3,
    _drop_guard: DropGuard,
}

#[bon::bon]
impl Server {
    #[builder(derive(Debug))]
    pub async fn new(
        #[builder(default = "localhost")] host: &str,
        #[builder(default = 3000)] port: u16,
    ) -> anyhow::Result<Self> {
        let ct = CancellationToken::new();
        let listener = TcpListener::bind(format!("{}:{}", host, port)).await?;
        let _drop_guard = ct.clone().drop_guard();
        Ok(Self {
            ct,
            listener,
            ars3s: ArS3::new(),
            _drop_guard,
        })
    }

    pub fn ct(&self) -> CancellationToken {
        self.ct.clone()
    }

    pub fn insert_bucket(&mut self, name: impl AsRef<str>, arfs: ArFs) -> anyhow::Result<()> {
        self.ars3s.insert(name, arfs)
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let mut builder = S3ServiceBuilder::new(self.ars3s);
        builder.set_route(CustomRoute::build());
        let service = builder.build();

        let http_server = ConnBuilder::new(TokioExecutor::new());
        let graceful = hyper_util::server::graceful::GracefulShutdown::new();

        let ct = self.ct.clone();
        loop {
            let (socket, _) = tokio::select! {
                res =  self.listener.accept() => {
                    match res {
                        Ok(conn) => conn,
                        Err(err) => {
                            tracing::error!("error accepting connection: {err}");
                            continue;
                        }
                    }
                }
                _ = ct.cancelled() => {
                    break;
                }
            };

            let conn = http_server.serve_connection(TokioIo::new(socket), service.clone());
            let conn = graceful.watch(conn.into_owned());
            tokio::spawn(async move {
                let _ = conn.await;
            });
        }

        graceful.shutdown().await;

        Ok(())
    }
}

pub struct CustomRoute {
    router: axum::Router,
}

impl CustomRoute {
    pub fn build() -> Self {
        Self {
            router: handlers::register(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Extra {
    pub credentials: Option<s3s::auth::Credentials>,
    pub region: Option<String>,
    pub service: Option<String>,
}

fn convert_request(req: S3Request<Body>) -> http::Request<Body> {
    let (mut parts, _) = http::Request::new(Body::empty()).into_parts();
    parts.method = req.method;
    parts.uri = req.uri;
    parts.headers = req.headers;
    parts.extensions = req.extensions;
    parts.extensions.insert(Extra {
        credentials: req.credentials,
        region: req.region,
        service: req.service,
    });
    http::Request::from_parts(parts, req.input)
}

fn convert_response(resp: http::Response<axum::body::Body>) -> S3Response<Body> {
    let (parts, body) = resp.into_parts();
    let mut s3_resp = S3Response::new(Body::http_body_unsync(body));
    s3_resp.status = Some(parts.status);
    s3_resp.headers = parts.headers;
    s3_resp.extensions = parts.extensions;
    s3_resp
}

#[async_trait::async_trait]
impl S3Route for CustomRoute {
    fn is_match(
        &self,
        _method: &Method,
        uri: &Uri,
        _headers: &HeaderMap,
        _extensions: &mut Extensions,
    ) -> bool {
        let path = uri.path();
        let prefix = const_str::concat!(self::handlers::PREFIX, "/");
        path.starts_with(prefix)
    }

    async fn check_access(&self, req: &mut S3Request<Body>) -> S3Result<()> {
        if req.credentials.is_none() {
            tracing::debug!("anonymous access");
        }
        Ok(()) // allow all requests
    }

    async fn call(&self, req: S3Request<Body>) -> S3Result<S3Response<Body>> {
        let mut service = self.router.clone().into_service::<Body>();
        let req = convert_request(req);
        let result = service.call(req).await;
        match result {
            Ok(resp) => Ok(convert_response(resp)),
            Err(e) => match e {},
        }
    }
}

mod handlers {
    use std::collections::HashMap;

    use axum::Router;
    use axum::body::Body;
    use axum::extract::Path;
    use axum::extract::Query;
    use axum::extract::Request;
    use axum::http::Response;
    use axum::routing::get;
    use axum::routing::post;

    pub async fn echo(req: Request) -> Response<Body> {
        Response::new(req.into_body())
    }

    pub async fn hello() -> &'static str {
        "Hello, World!"
    }

    pub async fn show_path(Path(path): Path<String>) -> String {
        path
    }

    pub async fn show_query(Query(query): Query<HashMap<String, String>>) -> String {
        format!("{query:?}")
    }

    pub const PREFIX: &str = "/custom";

    pub fn register() -> Router {
        let router = Router::new()
            .route("/echo", post(echo))
            .route("/hello", get(hello))
            .route("/show_path/{*path}", get(show_path))
            .route("/show_query", get(show_query));

        Router::new().nest(PREFIX, router)
    }
}
