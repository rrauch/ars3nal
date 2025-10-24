use crate::s3::ArS3;
use arfs::ArFs;
use async_stream::stream;
use futures_lite::Stream;
use http::{Extensions, HeaderMap, Method, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use s3s::auth::SimpleAuth;
use s3s::route::S3Route;
use s3s::service::S3ServiceBuilder;
use s3s::{Body, S3Request, S3Response, S3Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};
use tower::Service;

pub struct Server {
    listener: TcpListener,
    ars3s: ArS3,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Status {
    Serving,
    ShuttingDown,
    Finished,
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Handle(Arc<Inner>);

impl Handle {
    pub fn status(&self) -> impl Stream<Item = Status> + Send + Unpin {
        let mut rx = self.0.status.clone();

        Box::pin(stream! {
            let mut status = rx.borrow_and_update().clone();
            loop {
                match status {
                    Status::Finished => {
                        yield Status::Finished;
                        break;
                    }
                    other => yield other,
                }

                if let Err(_) = rx.changed().await {
                    yield Status::Finished;
                    break;
                }
                status = rx.borrow_and_update().clone();
            }
        })
    }

    pub fn shutdown(&self) {
        self.0.ct.cancel();
    }
}

#[derive(Debug)]
struct Inner {
    ct: CancellationToken,
    status: watch::Receiver<Status>,
    _drop_guard: DropGuard,
}

#[bon::bon]
impl Server {
    #[builder(derive(Debug))]
    pub async fn new(
        #[builder(default = "localhost")] host: &str,
        #[builder(default = 6767)] port: u16,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(format!("{}:{}", host, port)).await?;
        Ok(Self {
            listener,
            ars3s: ArS3::new(),
        })
    }

    pub fn insert_bucket(&mut self, name: impl AsRef<str>, arfs: ArFs) -> anyhow::Result<()> {
        self.ars3s.insert(name, arfs)
    }

    pub fn serve(self) -> Handle {
        let ct = CancellationToken::new();
        let _drop_guard = ct.clone().drop_guard();
        let mut jh = {
            let ct = ct.clone();
            tokio::spawn(async move { self.run(ct).await })
        };

        let (mut tx, rx) = watch::channel(Status::Serving);
        {
            let ct = ct.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut jh => {
                            let _ = tx.send(Status::Finished);
                            break;
                        }
                        _ = ct.cancelled() => {
                            let _ = tx.send(Status::ShuttingDown);
                            break;
                        }
                    }
                }
                let _ = jh.await;
                let _ = tx.send(Status::Finished);
            });
        }

        Handle(Arc::new(Inner {
            ct,
            status: rx,
            _drop_guard,
        }))
    }

    async fn run(mut self, ct: CancellationToken) -> anyhow::Result<()> {
        let mut builder = S3ServiceBuilder::new(self.ars3s);
        builder.set_route(CustomRoute::build());
        //builder.set_auth(SimpleAuth::from_single("dummy", "dummy"));
        let service = builder.build();

        let http_server = ConnBuilder::new(TokioExecutor::new());
        let graceful = hyper_util::server::graceful::GracefulShutdown::new();

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
