//! Cluster node cache (watcher) for fast lookup by name.

use std::collections::HashMap;
use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Node;
use kube::api::ListParams;
use kube::runtime::WatchStreamExt;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client, ResourceExt};
use tokio::sync::RwLock;

/// In-memory store of cluster nodes, kept fresh by a background watcher task.
#[derive(Clone, Default)]
pub struct NodeStore {
    nodes: Arc<RwLock<HashMap<String, Node>>>,
}

impl NodeStore {
    /// List all nodes once, then spawn a background task keeping the store up to date.
    pub async fn start(client: Client) -> Result<Self, kube::Error> {
        let api: Api<Node> = Api::all(client);
        let store = Self::default();
        let list = api.list(&ListParams::default()).await?;
        {
            let mut guard = store.nodes.write().await;
            for node in list.items {
                guard.insert(node.name_any(), node);
            }
        }

        let writer = store.clone();
        tokio::spawn(async move {
            // default_backoff(): exponential backoff (client-go conventions)
            // between polls after an error, instead of hot-looping.
            let stream = watcher::watcher(api, watcher::Config::default()).default_backoff();
            tokio::pin!(stream);
            while let Some(event) = stream.next().await {
                match event {
                    Ok(event) => writer.apply(event).await,
                    // The watcher restarts the watch by itself (re-watch from the
                    // last resourceVersion, or full re-list on 410 Gone).
                    Err(err) => {
                        tracing::warn!(error = %err, "node watcher error; stream will retry")
                    }
                }
            }
            tracing::warn!("node watcher stream ended unexpectedly");
        });
        Ok(store)
    }

    /// Apply one watcher event to the cache.
    async fn apply(&self, event: Event<Node>) {
        match event {
            Event::Apply(node) | Event::InitApply(node) => {
                self.nodes.write().await.insert(node.name_any(), node);
            }
            Event::Delete(node) => {
                self.nodes.write().await.remove(&node.name_any());
            }
            // On re-list (e.g. after a 410 Gone), the cache is rebuilt from
            // scratch: clear it so nodes deleted during the outage don't linger.
            Event::Init => {
                self.nodes.write().await.clear();
            }
            Event::InitDone => {}
        }
    }

    pub async fn get(&self, name: &str) -> Option<Node> {
        self.nodes.read().await.get(name).cloned()
    }

    pub async fn len(&self) -> usize {
        self.nodes.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn node(name: &str) -> Node {
        Node {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn apply_handles_watch_events_and_relist() {
        let store = NodeStore::default();
        store.apply(Event::InitApply(node("a"))).await;
        store.apply(Event::Apply(node("b"))).await;
        assert_eq!(store.len().await, 2);
        assert!(store.get("a").await.is_some());

        store.apply(Event::Delete(node("a"))).await;
        assert!(store.get("a").await.is_none());

        // Re-list after a connection loss: the cache is rebuilt from scratch.
        store.apply(Event::Init).await;
        assert_eq!(store.len().await, 0);
        store.apply(Event::InitApply(node("c"))).await;
        store.apply(Event::InitDone).await;
        assert_eq!(store.len().await, 1);
        assert!(store.get("c").await.is_some());
        assert!(store.get("b").await.is_none());
    }
}
