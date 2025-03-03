use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body::Body;
use http_body_util::BodyDataStream;
use std::fmt::Debug;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{fmt, io};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_quiche::buf_factory::{BufFactory, PooledBuf};
use tokio_quiche::http3::driver::{
    InboundFrame, InboundFrameStream, OutboundFrame, OutboundFrameSender,
};
use tokio_quiche::QuicResultExt as _;
use tokio_quiche::{BoxError, QuicResult};

pub(crate) type BoxedBody =
    Pin<Box<dyn Body<Data = Bytes, Error = BoxError> + Send + Sync + 'static>>;

#[derive(Error, Debug)]
pub enum H3WriteError {
    #[error("H3 write: wrote fin")]
    WroteFin,
    #[error("H3 write: no stream state")]
    NoStreamState,
    #[error("H3 write: no connection state")]
    NoConnectionState,
}

impl From<H3WriteError> for io::Error {
    fn from(value: H3WriteError) -> Self {
        io::Error::new(io::ErrorKind::Other, value)
    }
}

/// [`H3Body`] serves as a "proxy" for HTTP/3 messages between the `io_worker` and
/// other interested parties.
///
/// For those interested parties it implements both a stream
/// socket interface and a datagram socket interface.
pub struct H3Body {
    stream_id: u64,
    wrote_fin: bool,
    read_fin: bool,

    send: OutboundFrameSender,
    recv: Option<InboundFrameStream>,

    /// A frame already queued from recv
    pending_recv: Option<(PooledBuf, bool)>,
}

impl H3Body {
    pub fn new(
        stream_id: u64,
        send: OutboundFrameSender,
        recv: Option<InboundFrameStream>,
        read_fin: bool,
    ) -> Self {
        Self {
            stream_id,
            send,
            recv,
            wrote_fin: false,
            read_fin,
            pending_recv: None,
        }
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
        fin: bool,
    ) -> Poll<io::Result<usize>> {
        if self.wrote_fin {
            return Poll::Ready(Err(H3WriteError::WroteFin).into_io());
        }

        let mut sent = None;
        // Always prefer to stay within the buffer pool limits.
        let mut buf_chunks = buf.chunks(BufFactory::MAX_BUF_SIZE);

        // Make sure if no chunks exist, to append an empty one if `fin` is needed.
        while let Some(chunk) = buf_chunks.next().or((buf.is_empty() && fin).then_some(&[])) {
            match self.send.poll_reserve(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(H3WriteError::NoStreamState).into_io())
                }
                Poll::Pending => {
                    return match sent {
                        Some(sent) => Poll::Ready(Ok(sent)),
                        None => Poll::Pending,
                    };
                }
            }

            // Only send fin with the last chunk
            let fin = (sent.unwrap_or_default() + chunk.len() == buf.len()) && fin;

            let body = OutboundFrame::body(BufFactory::buf_from_slice(chunk), fin);

            match self.send.send_item(body) {
                Ok(()) => {
                    self.wrote_fin |= fin;
                    if fin {
                        break;
                    }
                    *sent.get_or_insert(0) += chunk.len();
                }
                Err(_) => return Poll::Ready(Err(H3WriteError::NoStreamState).into_io()),
            }
        }

        Poll::Ready(Ok(sent.unwrap_or_default()))
    }

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<QuicResult<()>> {
        let mut did_read = false;
        loop {
            if let Some((pending, fin)) = self.pending_recv.as_mut() {
                let fin = *fin;

                let capacity = buf.remaining();
                if pending.len() > capacity {
                    buf.put_slice(&pending[..capacity]);
                    pending.pop_front(capacity);
                    return Poll::Ready(Ok(()));
                }

                buf.put_slice(pending);
                self.pending_recv.take();
                did_read = true;
                self.read_fin |= fin;
            }

            if self.read_fin {
                if let Some(chan) = self.recv.as_mut() {
                    chan.close();
                }
                return Poll::Ready(Ok(()));
            }

            let recv_inner = match self.recv.as_mut() {
                Some(recv) => recv,
                // This indicates the original quiche stream was closed.
                None => return Poll::Ready(Ok(())),
            };

            match recv_inner.poll_recv(cx) {
                Poll::Ready(None) => {
                    // This indicates the original quiche stream was closed.
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(InboundFrame::Body(msg, fin))) => {
                    assert!(self.pending_recv.replace((msg, fin)).is_none());
                }
                Poll::Ready(Some(InboundFrame::Datagram(_))) => unreachable!(),
                Poll::Pending => {
                    return if did_read {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    }
                }
            };
        }
    }
}

impl AsyncRead for H3Body {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        H3Body::poll_read(self, cx, buf).map(|read_res| read_res.into_io())
    }
}

impl AsyncWrite for H3Body {
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        H3Body::poll_write(self, cx, buf, false)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if !self.wrote_fin {
            let poll = H3Body::poll_write(self.as_mut(), cx, &[], true).map(|_| Ok(()));

            match poll {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(_)) => return Poll::Ready(Ok(())), // Indicates already shutdown
                Poll::Pending => return poll,
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl fmt::Debug for H3Body {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("H3Body")
            .field("stream_id", &self.stream_id)
            .field("wrote_fin", &self.wrote_fin)
            .finish()
    }
}

pub(crate) async fn send_hyper_body<B>(body: B, mut frame_sender: OutboundFrameSender) -> Option<()>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Send + Debug,
{
    let mut body_stream = BodyDataStream::new(body);

    while let Some(maybe_chunk) = body_stream.next().await {
        match maybe_chunk {
            Ok(chunk) => {
                for chunk in chunk.chunks(BufFactory::MAX_BUF_SIZE) {
                    // Is it too many levels of chunking?
                    let chunk = OutboundFrame::body(BufFactory::buf_from_slice(chunk), false);
                    frame_sender.send(chunk).await.ok()?;
                }
            }
            Err(error) => {
                tracing::debug!(
                    "error" = format!("{:?}", error),
                    "Received error when sending or receiving HTTP body"
                );

                let fin_chunk = OutboundFrame::PeerStreamError;
                frame_sender.send(fin_chunk).await.ok()?;

                return None;
            }
        }
    }

    let fin_chunk = OutboundFrame::body(BufFactory::get_empty_buf(), true);
    frame_sender.send(fin_chunk).await.ok()?;

    Some(())
}
