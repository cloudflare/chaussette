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
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tower::{
    retry::backoff::{Backoff, ExponentialBackoffMaker, MakeBackoff},
    util::rng::HasherRng,
    BoxError, Service,
};

#[derive(Clone)]
pub(crate) struct ProxyClient {
    tx: mpsc::Sender<ProxyRequest>,
}

impl ProxyClient {
    pub(crate) fn new(
        mut connector: HttpsConnector<HttpConnector>,
        proxy: Uri,
        keepalive: Option<crate::Http2KeepAliveConfig>,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel(64);

        let client = Self { tx };

        tokio::spawn(async move {
            let mut proxy_connection = match keepalive {
                Some(_) => Some(connect_with_retry(&mut connector, proxy.clone(), keepalive).await),
                None => None,
            };

            loop {
                let request = if keepalive.is_some() {
                    let closed = &mut proxy_connection
                        .as_mut()
                        .expect("eager recovery maintains a proxy connection")
                        .closed;

                    tokio::select! {
                        request = rx.recv() => request,
                        _ = closed => {
                            tracing::info!("proxy connection is closed, reconnecting eagerly");
                            proxy_connection = Some(
                                connect_with_retry(&mut connector, proxy.clone(), keepalive).await,
                            );
                            continue;
                        }
                    }
                } else {
                    rx.recv().await
                };

                let Some((request, mut response_sender)) = request else {
                    break;
                };

                let proxy_connection = select! {
                    proxy_connection = get_proxy_connection(
                        &mut connector,
                        proxy.clone(),
                        &mut proxy_connection,
                        keepalive,
                    ).fuse() => proxy_connection,
                    _ = response_sender.closed().fuse() => {
                        tracing::info!("client request cancelled");

                        continue
                    },
                };

                tokio::spawn(proxy_connection.request_sender.send_request(request).then(
                    async |response| {
                        let _ = response_sender.send(response);
                    },
                ));
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

type ProxyRequest = (
    Request<http_body_util::Empty<bytes::Bytes>>,
    oneshot::Sender<hyper::Result<Response<Incoming>>>,
);

type ProxyRequestSender =
    hyper::client::conn::http2::SendRequest<http_body_util::Empty<bytes::Bytes>>;

struct ProxyConnection {
    request_sender: ProxyRequestSender,
    closed: oneshot::Receiver<()>,
}

async fn get_proxy_connection<'c>(
    connector: &mut HttpsConnector<HttpConnector>,
    proxy: Uri,
    proxy_connection: &'c mut Option<ProxyConnection>,
    keepalive: Option<crate::Http2KeepAliveConfig>,
) -> &'c mut ProxyConnection {
    let connection_is_ready = match proxy_connection.as_mut() {
        Some(connection) => match connection.request_sender.ready().await {
            Ok(()) => true,
            Err(e) => {
                tracing::info!(error = ?e, "old proxy connection is closed, reconnecting");
                false
            }
        },
        None => {
            tracing::info!(proxy = ?proxy, "establishing initial connection");
            false
        }
    };

    if connection_is_ready {
        return proxy_connection
            .as_mut()
            .expect("ready proxy connection remains available");
    }

    *proxy_connection = None;
    proxy_connection.insert(connect_with_retry(connector, proxy, keepalive).await)
}

async fn connect_with_retry(
    connector: &mut HttpsConnector<HttpConnector>,
    proxy: Uri,
    keepalive: Option<crate::Http2KeepAliveConfig>,
) -> ProxyConnection {
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

        match connect(connector, proxy.clone(), keepalive).await {
            Ok(connection) => return connection,
            Err(e) => tracing::error!(error = ?e, "failed to connect to proxy"),
        }

        exponential_backoff.next_backoff().await;
    }
}

async fn connect(
    connector: &mut HttpsConnector<HttpConnector>,
    proxy: Uri,
    keepalive: Option<crate::Http2KeepAliveConfig>,
) -> Result<ProxyConnection, BoxError> {
    let stream = connector.call(proxy).await?;

    handshake_proxy_connection(stream, keepalive).await
}

async fn handshake_proxy_connection<T>(
    stream: T,
    keepalive: Option<crate::Http2KeepAliveConfig>,
) -> Result<ProxyConnection, BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());

    if let Some(keepalive) = keepalive {
        builder
            .timer(TokioTimer::new())
            .keep_alive_interval(keepalive.interval)
            .keep_alive_timeout(keepalive.timeout)
            .keep_alive_while_idle(true);
    }

    let (request_sender, connection) = builder.handshake(TokioIo::new(stream)).await?;
    let (closed_sender, closed) = oneshot::channel();

    tokio::spawn(async move {
        match connection.await {
            Ok(()) => tracing::info!("proxy connection closed"),
            Err(e) => tracing::error!(error = ?e, "proxy connection errored out"),
        }

        let _ = closed_sender.send(());
    });

    Ok(ProxyConnection {
        request_sender,
        closed,
    })
}

impl super::ProxyClient for ProxyClient {
    async fn new(config: &mut crate::Config) -> anyhow::Result<Self> {
        if let Some(keepalive) = config.http2_keepalive {
            anyhow::ensure!(
                keepalive.interval > Duration::ZERO,
                "HTTP/2 keepalive interval must be greater than zero"
            );
            anyhow::ensure!(
                keepalive.timeout > Duration::ZERO,
                "HTTP/2 keepalive timeout must be greater than zero"
            );
        }

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

        Ok(Self::new(
            connector,
            config.proxy.as_str().parse()?,
            config.http2_keepalive,
        ))
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

#[cfg(test)]
mod tests {
    use super::{handshake_proxy_connection, ProxyClient};
    use crate::Http2KeepAliveConfig;
    use boring::ssl::{SslConnector, SslMethod};
    use hyper_boring::v1::HttpsConnector;
    use hyper_util::client::legacy::connect::HttpConnector;
    use std::{future::pending, time::Duration};
    use tokio::{net::TcpListener, sync::oneshot};

    #[tokio::test]
    async fn keepalive_closes_an_unresponsive_http2_connection() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            let _connection = ::h2::server::handshake(server_stream).await.unwrap();

            pending::<()>().await;
        });

        let connection = handshake_proxy_connection(
            client_stream,
            Some(Http2KeepAliveConfig {
                interval: Duration::from_millis(20),
                timeout: Duration::from_millis(20),
            }),
        )
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(1), connection.closed)
            .await
            .unwrap()
            .unwrap();

        server_task.abort();
    }

    #[tokio::test]
    async fn configured_keepalive_reconnects_without_waiting_for_a_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let (first_connected_sender, first_connected) = oneshot::channel();
        let (close_first_sender, close_first) = oneshot::channel();
        let (second_connected_sender, second_connected) = oneshot::channel();

        let server_task = tokio::spawn(async move {
            let (first_stream, _) = listener.accept().await.unwrap();
            let first_connection = ::h2::server::handshake(first_stream).await.unwrap();
            first_connected_sender.send(()).unwrap();

            close_first.await.unwrap();
            drop(first_connection);

            let (second_stream, _) = listener.accept().await.unwrap();
            let _second_connection = ::h2::server::handshake(second_stream).await.unwrap();
            second_connected_sender.send(()).unwrap();

            pending::<()>().await;
        });

        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let ssl = SslConnector::builder(SslMethod::tls()).unwrap();
        let connector = HttpsConnector::with_connector(http, ssl).unwrap();
        let client = ProxyClient::new(
            connector,
            proxy,
            Some(Http2KeepAliveConfig {
                interval: Duration::from_secs(60),
                timeout: Duration::from_secs(60),
            }),
        );

        tokio::time::timeout(Duration::from_secs(1), first_connected)
            .await
            .unwrap()
            .unwrap();
        close_first_sender.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), second_connected)
            .await
            .unwrap()
            .unwrap();

        drop(client);
        server_task.abort();
    }
}
