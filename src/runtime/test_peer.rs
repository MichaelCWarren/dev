//! Test-only support shared by more than one runtime's test suite, alongside
//! `fake_daemon.rs`: a recording [`SessionPeer`] fake and a bound on awaits that
//! could otherwise hang a test.

use crate::error::DevError;
use crate::runtime::BoxFut;
use crate::runtime::terminal_relay::{SessionPeer, UnitFut};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

/// Bounds an await that could stall, turning a hang into a failed assertion
/// instead of a stuck test.
pub(crate) async fn bounded<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .expect("must not hang")
}

/// How the next `copy_in` call answers; the queue defaults to success once it
/// runs dry.
pub(crate) enum Reply {
    Succeed,
    Fail(String),
    Stall,
}

/// An in-memory [`SessionPeer`] that records every resize and copy it was
/// asked to perform, answering `copy_in` from a queue of [`Reply`]s, so a
/// runtime's relay behaviour can be asserted without a real container.
pub(crate) struct RecordingPeer {
    pub(crate) resizes: Mutex<Vec<(u16, u16)>>,
    pub(crate) copies: Mutex<Vec<(String, Vec<u8>)>>,
    replies: Mutex<VecDeque<Reply>>,
}

impl RecordingPeer {
    pub(crate) fn accepting() -> Self {
        Self::queued(Vec::new())
    }

    pub(crate) fn refusing(msg: &str) -> Self {
        Self::queued(vec![Reply::Fail(msg.to_string())])
    }

    pub(crate) fn stalling() -> Self {
        Self::queued(vec![Reply::Stall])
    }

    pub(crate) fn queued(replies: Vec<Reply>) -> Self {
        Self {
            resizes: Mutex::new(Vec::new()),
            copies: Mutex::new(Vec::new()),
            replies: Mutex::new(replies.into()),
        }
    }
}

impl SessionPeer for RecordingPeer {
    fn resize(&self, cols: u16, rows: u16) -> UnitFut<'_> {
        self.resizes.lock().unwrap().push((cols, rows));
        Box::pin(async {})
    }

    fn copy_in<'a>(&'a self, bytes: Vec<u8>, target: &'a str) -> BoxFut<'a, ()> {
        self.copies
            .lock()
            .unwrap()
            .push((target.to_string(), bytes));
        match self.replies.lock().unwrap().pop_front() {
            Some(Reply::Fail(msg)) => Box::pin(async move { Err(DevError::Runtime(msg)) }),
            Some(Reply::Stall) => Box::pin(std::future::pending()),
            Some(Reply::Succeed) | None => Box::pin(async { Ok(()) }),
        }
    }
}
