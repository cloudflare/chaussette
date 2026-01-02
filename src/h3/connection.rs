use super::body::{send_hyper_body, BoxedBody, H3Body};
use bytes::Bytes;
use h2::ext::Protocol;
use http::{Method, Request, Response, Version};
use http_body::Body;
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tokio_quiche::datagram_socket::ShutdownConnectionExt as _;
use tokio_quiche::http3::driver;
use tokio_quiche::http3::driver::{ClientH3Event, H3Event, IncomingH3Headers, NewClientRequest};
use tokio_quiche::http3::driver::{InboundFrameStream, OutboundFrameSender};
use tokio_quiche::quic::{ConnectionShutdownBehaviour, QuicCommand};
use tokio_quiche::quiche;
use tokio_quiche::quiche::h3::{self, NameValue as _};
use tokio_quiche::{BoxError, ClientH3Connection, QuicResult};
use tokio_util::sync::CancellationToken;

pub(crate) type FlowMap = Arc<Mutex<HashMap<u64, (InboundFrameStream, OutboundFrameSender)>>>;

pub(crate) struct H3ConnectionState {
    pub flow_map: FlowMap,
    pub peer_settings: OnceLock<Vec<(u64, u64)>>,
}

struct PendingRequest {
    /// A sender used by the [Connection] to send [Response]s back to the user-facing task.
    response: oneshot::Sender<Response<H3Body>>,
}

/// A [`Connection`] is a high-level HTTP/3 client-side connection to some
/// remote server. [`Connection`]s should be spawned and driven with
/// [`Connection::run`].
pub struct Connection {
    pub(crate) state: Arc<H3ConnectionState>,
    pub(crate) client_req_sender: mpsc::UnboundedSender<ClientRequest>,
    pub(crate) client_req_receiver: mpsc::UnboundedReceiver<ClientRequest>,
    pub(crate) new_request_sender: driver::ClientRequestSender,
    pub(crate) h3_event_receiver: driver::ClientEventStream,
    pending_requests: HashMap<u64, PendingRequest>,
    stream_id_to_request_id: HashMap<u64, u64>,
    pub(crate) cancel_token: CancellationToken,
    pub(crate) quic_connection: ClientH3Connection,
    client_shutdown_sender: mpsc::UnboundedSender<ConnectionShutdownBehaviour>,
    client_shutdown_receiver: mpsc::UnboundedReceiver<ConnectionShutdownBehaviour>,
}

impl From<ClientH3Connection> for Connection {
    fn from(connection: ClientH3Connection) -> Self {
        Self::new_with_connection(connection)
    }
}

impl Connection {
    pub fn new_with_connection(mut quic_connection: ClientH3Connection) -> Self {
        let state = H3ConnectionState {
            flow_map: FlowMap::default(),
            peer_settings: OnceLock::new(),
        };

        let (client_req_sender, client_req_receiver) = mpsc::unbounded_channel();
        let (client_shutdown_sender, client_shutdown_receiver) = mpsc::unbounded_channel();

        Self {
            state: Arc::new(state),
            client_req_sender,
            client_req_receiver,
            new_request_sender: quic_connection.h3_controller.request_sender(),
            h3_event_receiver: quic_connection.h3_controller.take_event_receiver(),
            pending_requests: Default::default(),
            stream_id_to_request_id: Default::default(),
            cancel_token: CancellationToken::new(),
            quic_connection,
            client_shutdown_sender,
            client_shutdown_receiver,
        }
    }

    pub fn request_sender(&self) -> SendRequest {
        SendRequest {
            sender: self.client_req_sender.clone(),
        }
    }

    /// This channel can be used by the client to send a shutdown request to the underlying connection
    pub fn client_shutdown_sender(&self) -> mpsc::UnboundedSender<ConnectionShutdownBehaviour> {
        self.client_shutdown_sender.clone()
    }

    pub async fn run(mut self) -> QuicResult<()> {
        loop {
            select! {
                biased;
                req = self.h3_event_receiver.recv() => match req {
                    Some(req) => self.handle_event(req).await?,
                    None => return Ok(()), // The sender was dropped, implying connection was terminated
                },
                Some(request) = self.client_req_receiver.recv() => {
                    self.handle_client_req(request)?;
                }
                Some(shutdown_request) = self.client_shutdown_receiver.recv() => {
                    tracing::debug!("Sending client-requested shutdown request={shutdown_request:?} to the H3 Controller");
                    let h3_cmd_sender = self.quic_connection.h3_controller.cmd_sender();
                    let _ = h3_cmd_sender.send(QuicCommand::ConnectionClose(shutdown_request));
                    self.cancel_token.cancel();
                }
                () = self.cancel_token.cancelled() => {
                    let _ = self.quic_connection.shutdown_connection().await;
                    return Ok(())
                },
            }
        }
    }

    pub(crate) async fn handle_event(&mut self, event: ClientH3Event) -> QuicResult<()> {
        let state = &self.state;

        let event = match event {
            ClientH3Event::Core(e) => e,

            ClientH3Event::NewOutboundRequest {
                stream_id,
                request_id,
            } => {
                self.stream_id_to_request_id.insert(stream_id, request_id);
                return Ok(());
            }
        };

        match event {
            // Received an explicit connection level error.
            H3Event::ConnectionError(err) => QuicResult::Err(Box::new(err)),

            // If the connection's been shut down, we're done
            H3Event::ConnectionShutdown(_) => QuicResult::Err(Box::new(quiche::Error::Done)),

            // Received a new UDP flow.
            H3Event::NewFlow {
                flow_id,
                recv,
                send,
            } => {
                // Insert the new flow into the map.
                state.flow_map.lock().unwrap().insert(flow_id, (recv, send));
                Ok(())
            }

            // Received connection settings
            H3Event::IncomingSettings { settings } => {
                state
                    .peer_settings
                    .set(settings)
                    .map_err(|_| anyhow::anyhow!("settings already set - received duplicate settings from peer"))?;
                Ok(())
            }

            // Received response headers for a request.
            H3Event::IncomingHeaders(incoming_headers) => {
                let IncomingH3Headers {
                    stream_id,
                    headers,
                    send,
                    recv,
                    read_fin,
                    h3_audit_stats: _,
                } = incoming_headers;

                tracing::debug!("got a response for stream_id={stream_id}, headers={headers:?}");

                let Some(request_id) = self.stream_id_to_request_id.remove(&stream_id) else {
                    Err(format!("got headers for unknown stream_id={stream_id}"))?
                };

                let Some(PendingRequest { response }) = self.pending_requests.remove(&request_id)
                else {
                    tracing::warn!("missing request_id={request_id}");
                    return Ok(());
                };

                let res = h3_response_to_hyper_response(headers)?;

                let h3_body = H3Body::new(stream_id, send.clone(), Some(recv), read_fin);

                // Send the response back to the user.
                let res = res.map(|()| h3_body);
                let _ = response.send(res);

                Ok(())
            }

            H3Event::ResetStream { stream_id } => {
                if let Some(request_id) = self.stream_id_to_request_id.get(&stream_id) {
                    self.pending_requests.remove(request_id);
                }

                Ok(())
            }

            H3Event::BodyBytesReceived { .. } | H3Event::StreamClosed { .. } => Ok(()),
        }
    }

    /// Receives a [ClientRequest] from the user-facing task and forwards it into the
    /// [Connection]'s underlying H3Driver for processing.
    fn handle_client_req(&mut self, client_request: ClientRequest) -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicU64, Ordering};

        static REQUEST_ID: AtomicU64 = AtomicU64::new(0);
        let request_id = REQUEST_ID.fetch_add(1, Ordering::SeqCst);

        let ClientRequest { request, response } = client_request;

        let is_connect = request.method() == Method::CONNECT;

        let (parts, body) = request.into_parts();
        let headers = hyper_request_parts_to_h3_headers(parts);

        let has_body = body.size_hint().exact() != Some(0);

        let (body_writer_tx, body_writer_rx) = oneshot::channel();
        let body_writer = (is_connect || has_body).then_some(body_writer_tx);

        // Send the request into the H3Driver for processing
        if let Err(e) = self.new_request_sender
            .send(NewClientRequest {
                request_id,
                headers,
                body_writer,
            }) {
            return Err(anyhow::anyhow!("unable to send new client request to IO worker: {:?}", e));
        }

        self.pending_requests
            .insert(request_id, PendingRequest { response });

        if has_body {
            tokio::spawn(async move {
                match body_writer_rx.await {
                    Ok(h3_body) => {
                        tokio::spawn(send_hyper_body(body, h3_body));
                    }
                    Err(e) => {
                        tracing::error!("unable to get writer for client body: {:?}", e);
                    }
                }
            });
        }

        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

pub(super) fn hyper_request_parts_to_h3_headers(parts: http::request::Parts) -> Vec<h3::Header> {
    let mut h3_headers = Vec::new();
    h3_headers.push(h3::Header::new(
        b":method",
        parts.method.as_str().as_bytes(),
    ));

    if let Some(protocol) = parts.extensions.get::<Protocol>() {
        h3_headers.push(h3::Header::new(b":protocol", protocol.as_str().as_bytes()));
    }

    if let Some(scheme) = parts.uri.scheme_str() {
        h3_headers.push(h3::Header::new(b":scheme", scheme.as_bytes()));
    }

    if let Some(authority) = parts.uri.authority() {
        h3_headers.push(h3::Header::new(
            b":authority",
            authority.as_str().as_bytes(),
        ));
    }

    if let Some(path) = parts.uri.path_and_query() {
        h3_headers.push(h3::Header::new(b":path", path.as_str().as_bytes()));
    }

    for (name, value) in parts.headers.iter() {
        h3_headers.push(h3::Header::new(name.as_str().as_bytes(), value.as_bytes()));
    }

    h3_headers
}

fn h3_response_to_hyper_response(headers: Vec<h3::Header>) -> QuicResult<Response<()>> {
    let mut builder = http::response::Builder::new();

    for header in headers {
        if header.name() == b":status" {
            builder = builder.status(header.value());
        } else {
            builder = builder.header(header.name(), header.value());
        }
    }

    builder
        .version(Version::HTTP_3)
        .body(())
        .map_err(Into::into)
}

pub(crate) struct ClientRequest {
    pub(crate) request: Request<BoxedBody>,
    pub(crate) response: oneshot::Sender<Response<H3Body>>,
}

#[derive(Clone)]
pub struct SendRequest {
    pub(crate) sender: mpsc::UnboundedSender<ClientRequest>,
}

impl SendRequest {
    pub async fn send_request<B>(&self, request: Request<B>) -> QuicResult<Response<H3Body>>
    where
        B: Body<Data = Bytes> + Send + Sync + 'static,
        <B as Body>::Error: Into<BoxError>,
    {
        let (tx, rx) = oneshot::channel();

        let request = request.map(|body| Box::pin(body.map_err(Into::into)) as BoxedBody);

        self.sender
            .send(ClientRequest {
                request,
                response: tx,
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "connection to h3 client driver closed",
                )
            })?;

        Ok(rx.await?)
    }
}
