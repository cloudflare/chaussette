use anyhow::Context as _;
use boring::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod},
    x509::{store::X509StoreBuilder, X509},
};
use futures_util::{select, FutureExt};
use http::{Request, Response, Uri};
use hyper::{body::Incoming, upgrade};
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
    #[allow(clippy::type_complexity)]
    tx: mpsc::Sender<(
        Request<http_body_util::Empty<bytes::Bytes>>,
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
        req: Request<http_body_util::Empty<bytes::Bytes>>,
    ) -> anyhow::Result<Response<Incoming>> {
        let (tx, rx) = oneshot::channel();

        self.tx
            .send((req, tx))
            .await
            .context("proxy client connection closed")?;

        rx.await
            .context("proxy response channel closed")?
            .context("proxy request failed")
    }
}

type ProxyRequestSender =
    hyper::client::conn::http2::SendRequest<http_body_util::Empty<bytes::Bytes>>;

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

impl super::ProxyClient for ProxyClient {
    async fn new(config: &mut crate::Config) -> anyhow::Result<Self> {
        let connector = {
            let mut http = HttpConnector::new();

            http.enforce_http(false);

            let mut ssl = SslConnector::builder(SslMethod::tls())?;

            ssl.set_alpn_protos(b"\x02h2")?;

            if let Some(proxy_ca) = &config.proxy_ca {
                let mut builder = X509StoreBuilder::new()?;

                builder.add_cert(X509::from_pem(&std::fs::read(proxy_ca)?)?)?;
                ssl.set_verify_cert_store(builder.build())?;
            }

            match (config.client_cert.take(), config.client_key.take()) {
                (None, None) => {}
                (None, Some(_)) => anyhow::bail!("client cert is missing"),
                (Some(_), None) => anyhow::bail!("client key is missing"),
                (Some(client_cert), Some(client_key)) => {
                    ssl.set_certificate(&*X509::from_pem(client_cert.as_ref())?)?;
                    ssl.set_private_key(&*PKey::private_key_from_pem(client_key.as_ref())?)?;
                }
            }

            HttpsConnector::with_connector(http, ssl)?
        };

        Ok(Self::new(connector, config.proxy.as_str().parse()?))
    }

    async fn connect(
        self,
        request: hyper::Request<http_body_util::Empty<bytes::Bytes>>,
    ) -> anyhow::Result<impl tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin + Send + 'static>
    {
        let response = self.request(request).await?;
        tracing::info!(headers = ?response.headers(), status = %response.status(), "connected to proxy");
        anyhow::ensure!(
            response.status().is_success(),
            "proxy connection failed with status: {}",
            response.status()
        );

        tracing::debug!("upgrading connection");
        let stream = upgrade::on(response).await?;
        Ok(TokioIo::new(stream))
    }
}
