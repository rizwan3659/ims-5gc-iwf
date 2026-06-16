//! In-memory [`BindingStore`]: session→5GC-resource bindings for the
//! server-push and teardown flows (Sh subscriptions, Rx app-sessions, Ro
//! charging refs).
//!
//! Bindings are held only for the process lifetime — on restart the peer
//! re-subscribes / re-establishes, which is standard Diameter session
//! behavior. The [`BindingStore`] port leaves room for a shared/persistent
//! backend without touching the engine or notification server.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use iwf_core::ports::{Binding, BindingStore};

/// Process-local binding store.
#[derive(Debug, Default)]
pub struct InMemoryBindings {
    map: Mutex<HashMap<String, Binding>>,
}

#[async_trait]
impl BindingStore for InMemoryBindings {
    async fn put(&self, id: String, binding: Binding) {
        if let Ok(mut m) = self.map.lock() {
            m.insert(id, binding);
        }
    }

    async fn get(&self, id: &str) -> Option<Binding> {
        self.map.lock().ok()?.get(id).cloned()
    }

    async fn take(&self, id: &str) -> Option<Binding> {
        self.map.lock().ok()?.remove(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(kind: &str) -> Binding {
        Binding {
            peer_host: "as.ims.example.org".to_owned(),
            peer_realm: "ims.example.org".to_owned(),
            identity: "sip:alice@ims.example.org".to_owned(),
            session_id: Some("as;1;1".to_owned()),
            resource_ref: Some("res-1".to_owned()),
            kind: kind.to_owned(),
        }
    }

    #[tokio::test]
    async fn put_get_take() {
        let store = InMemoryBindings::default();
        store.put("id-1".to_owned(), binding("sh")).await;
        assert_eq!(
            store.get("id-1").await.map(|b| b.kind),
            Some("sh".to_owned())
        );
        // take removes.
        assert!(store.take("id-1").await.is_some());
        assert!(store.get("id-1").await.is_none());
        assert!(store.take("id-1").await.is_none());
    }
}
