//! Poison-tolerant access to `std::sync::Mutex`.
//!
//! A `std::sync::Mutex` becomes *poisoned* when a thread panics while holding
//! the guard; thereafter every `lock()` returns `Err`. The previous registry
//! code handled that with `.lock().ok()` / `if let Ok(..)`, which silently
//! treats a poisoned lock as **empty** — so a single panic-while-locked would
//! turn `BindingStore::get` into a 404 and `PeerRegistry::originate` into
//! `UnknownPeer`, *dropping subscriber state network-wide* with no signal.
//!
//! Recovering the guard is strictly safer: the protected maps only ever see
//! atomic `insert`/`get`/`remove`, which cannot leave the map torn, so the
//! data behind a poisoned lock is intact. The IWF data plane has no panics
//! inside these critical sections (reviewed), so this is defence-in-depth: it
//! guarantees a future panic can never silently delete sessions.
//!
//! (`Mutex::clear_poison` would let us un-poison + alarm once, but it is
//! stable only from Rust 1.77; this build pins 1.75, so we recover silently.)

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Lock `m`, recovering the guard if the mutex was poisoned (never panics,
/// never reports failure — a poisoned lock yields the intact data).
pub(crate) fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
