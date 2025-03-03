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

mod h2;
mod h3;

use anyhow::{anyhow, Context as _};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::header::HOST;
use hyper::Version;
use socks5_server::connection::connect::state::NeedReply;
use socks5_server::connection::state::NeedAuthenticate;
use socks5_server::{Connect, IncomingConnection};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::task;
use tracing::field::Empty;
use tracing::{info_span, Instrument};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    H2,
    H3,
}

pub struct Config {
    pub proxy: Url,
    pub geohash: String,
    pub request_timeout: Option<u64>,
    pub masque_preshared_key: Option<String>,
    pub proxy_ca: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub http_version: HttpVersion,
}

pub async fn start(
    config: Config,
    listen_addr: &str,
) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
    let listener = TcpListener::bind(listen_addr).await?;

    start_with_listener(config, listener)
}

pub fn start_with_listener(
    config: Config,
    listener: TcpListener,
) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
    tracing::info!(
        "Listen for socks connections @ {}",
        listener.local_addr().unwrap()
    );
    let server = socks5_server::Server::new(listener, Arc::new(socks5_server::auth::NoAuth));

    Ok(match config.http_version {
        HttpVersion::H2 => Box::pin(serve::<h2::ProxyClient>(config, server)),
        HttpVersion::H3 => Box::pin(serve::<h3::ProxyClient>(config, server)),
    })
}

trait ProxyClient: Clone + Send + Sync {
    async fn new(config: &mut Config) -> anyhow::Result<Self>;

    fn connect(
        self,
        request: hyper::Request<http_body_util::Empty<Bytes>>,
    ) -> impl Future<Output = anyhow::Result<impl AsyncWrite + AsyncRead + Unpin + Send + 'static>> + Send;
}

#[tracing::instrument(skip(opt, server), fields(scid))]
async fn serve<C: ProxyClient + 'static>(
    mut opt: Config,
    server: socks5_server::Server<()>,
) -> anyhow::Result<()> {
    let mut id = 0;
    // Standard TCP accept loop
    let client = C::new(&mut opt).await?;
    let opt = Arc::new(opt);
    while let Ok((conn, peer)) = server.accept().await {
        tracing::debug!("accepted a connection");
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

#[tracing::instrument(skip(socket, opt, client), fields(geohash, target))]
async fn serve_socks5(
    id: usize,
    socket: IncomingConnection<(), NeedAuthenticate>,
    opt: Arc<Config>,
    client: impl ProxyClient,
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

    tracing::debug!("proxying over {:?}", opt.http_version);
    proxy(opt, client, connect, address, &target).await?;
    Ok(())
}

async fn proxy<C: ProxyClient>(
    config: Arc<Config>,
    client: C,
    connect: Connect<NeedReply>,
    address: socks5_proto::Address,
    target: &str,
) -> anyhow::Result<()> {
    let stream = async {
        let mut request = hyper::Request::connect(target)
            .version(Version::HTTP_11)
            .header(HOST.as_str(), target)
            .header("sec-ch-geohash", &config.geohash);

        if let Some(preshared_key) = &config.masque_preshared_key {
            request = request.header("Proxy-Authorization", format!("Preshared {preshared_key}"));
        }

        let request = request.body(http_body_util::Empty::new()).unwrap();

        tracing::debug!("sending CONNECT request");

        tokio::time::timeout(
            Duration::from_secs(config.request_timeout.unwrap_or(u64::MAX)),
            client.connect(request),
        )
        .await
        .inspect_err(|err| {
            tracing::error!("CONNECT request timed out: {err}");
        })?
    }
    .instrument(info_span!("connecting to proxy", "scid" = Empty))
    .await;

    let mut stream = match stream {
        Ok(stream) => stream,
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
    tracing::debug!("copying bytes between socks5 connection and upstream CONNECT");
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

fn fst<A, B>((a, _): (A, B)) -> A {
    a
}
