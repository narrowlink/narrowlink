use std::{
    collections::HashMap,
    sync::{atomic::AtomicUsize, Arc},
    task::{Context, Poll},
};

use futures_util::{FutureExt, Sink, SinkExt, Stream, StreamExt};
use narrowlink_types::{
    agent::{EventInBound as AgentEventInBound, EventOutBound as AgentEventOutBound},
    client::{EventInBound as ClientEventInBound, EventOutBound as ClientEventOutBound},
};
use tokio::sync::{mpsc, oneshot};

use crate::{error::NetworkError, UniversalStream};

pub struct NarrowEvent<T, U> {
    req_sender: mpsc::UnboundedSender<Option<(usize, T, oneshot::Sender<U>)>>,
    req_receiver: mpsc::UnboundedReceiver<Option<(usize, T, oneshot::Sender<U>)>>,
    sender: mpsc::UnboundedSender<T>,
    receiver: mpsc::UnboundedReceiver<T>,
    inner_stream: Box<dyn UniversalStream<String, NetworkError>>,
    last_req_id: Arc<AtomicUsize>,
    requests: HashMap<usize, oneshot::Sender<U>>,
}

#[derive(Debug, Clone)]
pub struct NarrowEventRequest<T, U> {
    req_id: Arc<AtomicUsize>,
    sender: mpsc::UnboundedSender<Option<(usize, T, oneshot::Sender<U>)>>,
}

impl<'a, T, U> NarrowEventRequest<T, U>
where
    T: RequestManager,
{
    pub async fn request(&self, mut req: T) -> Result<U, NetworkError> {
        let req_id = self.req_id.load(std::sync::atomic::Ordering::SeqCst);
        self.req_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        req.set_id(req_id);
        let (cur_req_sender, cur_req_receiver) = oneshot::channel();

        let _ = self.sender.send(Some((req_id, req, cur_req_sender))); //todo error

        cur_req_receiver
            .await
            .map_err(|_| NetworkError::RequestCanceled)
    }
    pub async fn shutdown(&self) {
        let _ = self.sender.send(None);
    }
}

impl<T, U> NarrowEvent<T, U> {
    pub fn new(stream: impl UniversalStream<String, NetworkError>) -> Self {
        let (req_sender, req_receiver) = mpsc::unbounded_channel();
        let (sender, receiver) = mpsc::unbounded_channel();
        Self {
            req_sender,
            req_receiver,
            sender,
            receiver,
            inner_stream: Box::new(stream),
            last_req_id: Arc::new(AtomicUsize::new(0)),
            requests: HashMap::new(),
        }
    }
    pub fn get_sender(&self) -> mpsc::UnboundedSender<T> {
        self.sender.clone()
    }
    pub fn get_request(&self) -> NarrowEventRequest<T, U> {
        NarrowEventRequest {
            req_id: self.last_req_id.clone(),
            sender: self.req_sender.clone(),
        }
    }
}
impl<T, U> Unpin for NarrowEvent<T, U> {}

impl<T, U> Stream for NarrowEvent<T, U>
where
    U: ResponseManager + for<'a> serde::de::Deserialize<'a>,
    T: serde::ser::Serialize,
{
    type Item = Result<U, NetworkError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        loop {
            match self.inner_stream.poll_next_unpin(cx)? {
                Poll::Ready(Some(item)) => {
                    let item = serde_json::from_str::<U>(&item)?;
                    if let Some(msg_response) =
                        item.get_id().and_then(|id| self.requests.remove(&id))
                    {
                        let _ = msg_response.send(item);
                        continue;
                    }
                    return Poll::Ready(Some(Ok(item)));
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => match self.req_receiver.poll_recv(cx) {
                    Poll::Ready(Some(Some((req_id, msg, msg_response)))) => {
                        match self
                            .inner_stream
                            .send(serde_json::to_string(&msg)?)
                            .poll_unpin(cx)
                        {
                            Poll::Ready(Ok(())) => {
                                self.requests.insert(req_id, msg_response);
                                continue;
                            }
                            Poll::Ready(Err(_)) => return Poll::Ready(None),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    Poll::Ready(None) | Poll::Ready(Some(None)) => return Poll::Ready(None),
                    Poll::Pending => match self.receiver.poll_recv(cx) {
                        Poll::Ready(Some(msg)) => match self
                            .inner_stream
                            .send(serde_json::to_string(&msg)?)
                            .poll_unpin(cx)
                        {
                            Poll::Ready(Ok(())) => {
                                continue;
                            }
                            Poll::Ready(Err(_)) => return Poll::Ready(None),
                            Poll::Pending => return Poll::Pending,
                        },
                        Poll::Ready(None) => return Poll::Ready(None),
                        Poll::Pending => return Poll::Pending,
                    },
                },
            }
        }
    }
}

impl<T, U> Sink<T> for NarrowEvent<T, U>
where
    T: serde::ser::Serialize,
{
    type Error = NetworkError;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner_stream.poll_ready_unpin(cx)
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.inner_stream
            .start_send_unpin(serde_json::to_string(&item)?)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner_stream.poll_flush_unpin(cx)
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.inner_stream.poll_close_unpin(cx)
    }
}

impl<S, E> From<Box<dyn UniversalStream<String, NetworkError>>> for NarrowEvent<S, E> {
    fn from(stream: Box<dyn UniversalStream<String, NetworkError>>) -> Self {
        let (req_sender, req_receiver) = mpsc::unbounded_channel();
        let (sender, receiver) = mpsc::unbounded_channel();
        Self {
            req_sender,
            req_receiver,
            sender,
            receiver,
            inner_stream: stream,
            last_req_id: Arc::new(AtomicUsize::new(0)),
            requests: HashMap::new(),
        }
    }
}

pub trait RequestManager {
    fn set_id(&mut self, id: usize) -> Option<usize>;
}

pub trait ResponseManager {
    fn get_id(&self) -> Option<usize>;
}

impl RequestManager for AgentEventOutBound {
    fn set_id(&mut self, id: usize) -> Option<usize> {
        if let AgentEventOutBound::Request(_id, _) = self {
            let old_id = *_id;
            *_id = id;
            Some(old_id)
        } else {
            None
        }
    }
}

impl RequestManager for AgentEventInBound {
    fn set_id(&mut self, _id: usize) -> Option<usize> {
        None
    }
}

impl ResponseManager for AgentEventOutBound {
    fn get_id(&self) -> Option<usize> {
        None
    }
}

impl ResponseManager for AgentEventInBound {
    fn get_id(&self) -> Option<usize> {
        if let AgentEventInBound::Response(id, _) = self {
            Some(*id)
        } else {
            None
        }
    }
}

impl RequestManager for ClientEventOutBound {
    fn set_id(&mut self, id: usize) -> Option<usize> {
        #[allow(irrefutable_let_patterns)]
        if let ClientEventOutBound::Request(_id, _) = self {
            let old_id = *_id;
            *_id = id;
            Some(old_id)
        } else {
            None
        }
    }
}

impl RequestManager for ClientEventInBound {
    fn set_id(&mut self, _id: usize) -> Option<usize> {
        None
    }
}
impl ResponseManager for ClientEventInBound {
    fn get_id(&self) -> Option<usize> {
        #[allow(irrefutable_let_patterns)]
        if let ClientEventInBound::Response(id, _) = self {
            Some(*id)
        } else {
            None
        }
    }
}

impl ResponseManager for ClientEventOutBound {
    fn get_id(&self) -> Option<usize> {
        None
    }
}
