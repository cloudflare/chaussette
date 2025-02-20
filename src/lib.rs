//Copyright 2025 Cloudflare Inc.

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{anyhow, Context as _};
use boring::pkey::PKey;
use boring::ssl::{SslConnector, SslMethod};
use boring::x509::store::X509StoreBuilder;
use boring::x509::X509;
use futures_util::future::BoxFuture;
use http::header::HOST;
use http::Uri;
use hyper::{upgrade, Version};
use hyper_boring::v1::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use socks5_server::connection::connect::state::NeedReply;
use socks5_server::connection::state::NeedAuthenticate;
use socks5_server::{Connect, IncomingConnection};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;
use tokio::task;
use tower_service::Service;
use tracing::field::Empty;
use tracing::{info_span, Instrument};
use url::Url;

pub struct Config {
    pub proxy: Url,
    pub geohash: String,
    pub request_timeout: Option<u64>,
    pub masque_preshared_key: Option<String>,
    pub proxy_ca: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
}

pub async fn start(
    config: Config,
    listen_addr: &str,
) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
    let listener = TcpListener::bind(listen_addr).await?;

    start_with_listener(config, listener)
}

pub fn start_with_listener(
    mut config: Config,
    listener: TcpListener,
) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
    tracing::info!(
        "Listen for socks connections @ {}",
        listener.local_addr().unwrap()
    );

    let connector = {
        let mut http = HttpConnector::new();

        http.enforce_http(false);

        let mut ssl = SslConnector::builder(SslMethod::tls())?;

        ssl.set_alpn_protos(b"\x02h2")?;

        if let Some(proxy_ca) = &config.proxy_ca {
            let mut builder = X509StoreBuilder::new()?;

            builder.add_cert(X509::from_pem(&load_file(proxy_ca)?)?)?;
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

        ProxyConnector {
            inner: HttpsConnector::with_connector(http, ssl)?,
            proxy: config.proxy.as_str().parse().unwrap(),
        }
    };

    let client = hyper_util::client::legacy::Builder::new(TokioExecutor::new())
        .http2_only(true)
        .build(connector);

    let server = socks5_server::Server::new(listener, Arc::new(socks5_server::auth::NoAuth));

    Ok(Box::pin(serve(Arc::new(config), client, server)))
}

type Client =
    hyper_util::client::legacy::Client<ProxyConnector, http_body_util::Empty<&'static [u8]>>;

async fn serve(
    opt: Arc<Config>,
    client: Client,
    server: socks5_server::Server<()>,
) -> anyhow::Result<()> {
    let mut id = 0;
    // Standard TCP accept loop
    while let Ok((conn, peer)) = server.accept().await {
        let opt = Arc::clone(&opt);
        let client = client.clone();

        task::spawn(
            async move {
                match serve_socks5(id, conn, opt, client).await {
                    Ok(()) => {}
                    Err(err) => tracing::error!("failed to serve socks5 connect {:#}", &err),
                }
            }
            .instrument(info_span!("connection", ?peer)),
        );
        id += 1;
    }
    Ok(())
}

#[tracing::instrument(skip(socket, opt, client), fields(geohash, target, scid))]
async fn serve_socks5(
    id: usize,
    socket: IncomingConnection<(), NeedAuthenticate>,
    opt: Arc<Config>,
    client: Client,
) -> anyhow::Result<()> {
    let (socket, ()) = socket.authenticate().await.map_err(fst)?;
    let command = socket.wait().await.map_err(fst)?;
    let (connect, address) = match command {
        socks5_server::Command::Connect(connect, address) => (connect, address),
        socks5_server::Command::Associate(associate, address) => {
            return associate
                .reply(socks5_proto::Reply::CommandNotSupported, address)
                .await
                .map(|_| ())
                .map_err(fst)
                .context("failed to reply");
        }
        socks5_server::Command::Bind(bind, address) => {
            return bind
                .reply(socks5_proto::Reply::CommandNotSupported, address)
                .await
                .map(|_| ())
                .map_err(fst)
                .context("failed to reply");
        }
    };

    let target = match &address {
        socks5_proto::Address::SocketAddress(socket_addr) => format!("{socket_addr}"),
        socks5_proto::Address::DomainAddress(vec, port) => {
            format!("{}:{port}", std::str::from_utf8(vec)?)
        }
    };

    tracing::Span::current()
        .record("geohash", &opt.geohash)
        .record("target", &target);

    tracing::debug!("proxying over H2");
    proxy_h2(opt, client, connect, address, &target).await?;

    Ok(())
}

async fn proxy_h2(
    config: Arc<Config>,
    client: Client,
    connect: Connect<NeedReply>,
    address: socks5_proto::Address,
    target: &str,
) -> Result<(), anyhow::Error> {
    let proxy = async {
        let mut request = hyper::Request::connect(target)
        .version(Version::HTTP_11)
        .header(HOST.as_str(), target)
        .header("sec-ch-geohash", &config.geohash);

        if let Some(preshared_key) = &config.masque_preshared_key {
            request = request.header(
                "Proxy-Authorization", format!("Preshared {preshared_key}"),
            );
        }

        let request = request
            .body(<http_body_util::Empty<&[u8]>>::new())
            .unwrap();

        tracing::debug!("sending H2 CONNECT request");

        let response = tokio::time::timeout(
            Duration::from_secs(config.request_timeout.unwrap_or(u64::MAX)),
            client.request(request)
        )
            .await.inspect_err(|err| {
                tracing::error!("CONNECT request timed out: {err}");
            })??;

        tracing::info!(headers = ?response.headers(), status = %response.status(), "connected to proxy");
        anyhow::ensure!(
            response.status().is_success(),
            "proxy connection failed with status: {}",
            response.status()
        );

        tracing::debug!("upgrading connection");
        let stream = upgrade::on(response).await?;
        Ok(stream)
    }
    .instrument(info_span!("connecting to proxy", "scid" = Empty))
    .await;

    let mut stream = match proxy {
        Ok(stream) => TokioIo::new(stream),
        Err(e) => {
            tracing::error!(error = ?e, "failed to connect to proxy");
            return connect
                .reply(socks5_proto::Reply::GeneralFailure, address)
                .await
                .map_err(fst)
                .map(|_| ())
                .context("failed to reply");
        }
    };
    tracing::trace!("sending socks5 success response");
    let mut ready = connect
        .reply(socks5_proto::Reply::Succeeded, address)
        .await
        .map_err(fst)?;
    tracing::debug!("copying bytes between socks5 connection and H3 CONNECT");
    let (body_read, ready_read) =
        tokio::io::copy_bidirectional(&mut stream, ready.get_mut()).await?;
    tracing::debug!(
        bytes_sent_upstream = ready_read,
        bytes_send_downstream = body_read,
        "shutting down proxy task"
    );
    async move { stream.shutdown().await.map_err(|e| anyhow!("{e}")) }
        .in_current_span()
        .await?;
    Ok(())
}

#[derive(Clone)]
struct ProxyConnector {
    inner: HttpsConnector<HttpConnector>,
    proxy: Uri,
}

impl Service<Uri> for ProxyConnector {
    type Response = <HttpsConnector<HttpConnector> as Service<Uri>>::Response;
    type Error = <HttpsConnector<HttpConnector> as Service<Uri>>::Error;
    type Future = <HttpsConnector<HttpConnector> as Service<Uri>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, _req: Uri) -> Self::Future {
        self.inner.call(self.proxy.clone())
    }
}

fn fst<A, B>((a, _): (A, B)) -> A {
    a
}

fn load_file<P: AsRef<Path> + Copy>(path: P) -> io::Result<Vec<u8>> {
    let mut buf = vec![];

    File::open(path).and_then(|mut f| f.read_to_end(&mut buf))?;

    Ok(buf)
}
