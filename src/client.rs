use futures_util::{select, FutureExt};
use http::{Request, Response, Uri};
use hyper::body::Incoming;
use hyper_boring::v1::HttpsConnector;
use hyper_util::{
    client::legacy::connect::HttpConnector,
    rt::{TokioExecutor, TokioIo},
};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tower::{
    retry::backoff::{Backoff, ExponentialBackoffMaker, MakeBackoff},
    util::rng::HasherRng,
    BoxError, Service,
};

#[derive(Clone)]
pub(crate) struct ProxyClient {
    tx: mpsc::Sender<(
        Request<http_body_util::Empty<&'static [u8]>>,
        oneshot::Sender<hyper::Result<Response<Incoming>>>,
    )>,
}

impl ProxyClient {
    pub(crate) fn new(mut connector: HttpsConnector<HttpConnector>, proxy: Uri) -> Self {
        let (tx, mut rx) = mpsc::channel(64);

        let client = Self { tx };

        tokio::spawn(async move {
            let mut request_sender = None;

            while let Some((req, mut tx)) = rx.recv().await {
                let sender = select! {
                    sender = get_proxy_request_sender(&mut connector, proxy.clone(), &mut request_sender).fuse() => sender,
                    _ = tx.closed().fuse() => {
                        tracing::info!("client request cancelled");

                        continue
                    },
                };

                tokio::spawn(sender.send_request(req).then(async |res| {
                    let _ = tx.send(res);
                }));
            }
        });

        client
    }

    pub(crate) async fn request(
        &self,
        req: Request<http_body_util::Empty<&'static [u8]>>,
    ) -> hyper::Result<Response<Incoming>> {
        let (tx, rx) = oneshot::channel();

        self.tx.send((req, tx)).await.unwrap();

        rx.await.unwrap()
    }
}

type ProxyRequestSender =
    hyper::client::conn::http2::SendRequest<http_body_util::Empty<&'static [u8]>>;

async fn get_proxy_request_sender<'c>(
    connector: &mut HttpsConnector<HttpConnector>,
    proxy: Uri,
    request_sender: &'c mut Option<ProxyRequestSender>,
) -> &'c mut ProxyRequestSender {
    match request_sender.take() {
        Some(mut sender) => match sender.ready().await {
            Ok(()) => return request_sender.insert(sender),
            Err(e) => {
                tracing::info!(error = ?e, "old proxy connection is closed, reconnecting");
            }
        },
        None => {
            tracing::info!(proxy = ?proxy, "establishing initial connection");
        }
    }

    let mut exponential_backoff = ExponentialBackoffMaker::new(
        Duration::from_millis(200),
        Duration::from_secs(5),
        0.1,
        HasherRng::default(),
    )
    .unwrap()
    .make_backoff();

    loop {
        tracing::debug!(proxy = ?proxy, "connecting to proxy");

        match connect(connector, proxy.clone()).await {
            Ok(sender) => return request_sender.insert(sender),
            Err(e) => tracing::error!(error = ?e, "failed to connect to proxy"),
        }

        exponential_backoff.next_backoff().await;
    }
}

async fn connect(
    connector: &mut HttpsConnector<HttpConnector>,
    proxy: Uri,
) -> Result<ProxyRequestSender, BoxError> {
    let stream = connector.call(proxy).await?;

    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::error!(error = ?e, "proxy connection errored out");
        }
    });

    Ok(sender)
}
