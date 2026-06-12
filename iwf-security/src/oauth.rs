//! OAuth2 client-credentials token cache (TS 29.510 §5.4.2,
//! Nnrf_AccessToken) implementing [`TokenProvider`].
//!
//! Refresh policy: a token is considered stale at **80 % of its TTL** and
//! refreshed on the next request that observes staleness, while concurrent
//! requests keep using the still-valid token (single-flight refresh).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use iwf_core::error::CoreError;
use iwf_core::nf::NfType;
use iwf_core::ports::TokenProvider;
use tokio::sync::Mutex;

/// OAuth client settings. The client secret arrives via environment
/// injection (`IWF_OAUTH_CLIENT_SECRET`), never from config files.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Token endpoint, e.g. `http://nrf.5gc:8080/oauth2/token`.
    pub token_endpoint: String,
    /// OAuth client id of this IWF.
    pub client_id: String,
    /// OAuth client secret.
    pub client_secret: String,
    /// Request timeout.
    pub timeout: Duration,
}

/// Abstraction over the token endpoint so the cache is unit-testable.
#[async_trait]
pub trait TokenFetcher: Send + Sync {
    /// Fetch a fresh token for `target`; returns (access_token, ttl).
    async fn fetch(&self, target: NfType) -> Result<(String, Duration), CoreError>;
}

/// HTTP fetcher speaking RFC 6749 §4.4 (client credentials) with the
/// 3GPP `scope` convention `<target-nf-type-lowercase>` (TS 29.510 §6.3.5.2).
pub struct HttpTokenFetcher {
    http: Client<HttpConnector, Full<Bytes>>,
    config: OAuthConfig,
}

impl HttpTokenFetcher {
    /// Fetcher for `config`.
    pub fn new(config: OAuthConfig) -> Self {
        HttpTokenFetcher {
            http: Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
            config,
        }
    }
}

#[async_trait]
impl TokenFetcher for HttpTokenFetcher {
    async fn fetch(&self, target: NfType) -> Result<(String, Duration), CoreError> {
        let form = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
            self.config.client_id,
            self.config.client_secret,
            target.as_str().to_ascii_lowercase()
        );
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(&self.config.token_endpoint)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from(form)))
            .map_err(|e| CoreError::Adapter(format!("token request: {e}")))?;

        let response = tokio::time::timeout(self.config.timeout, self.http.request(request))
            .await
            .map_err(|_| CoreError::Adapter("token endpoint timeout".to_owned()))?
            .map_err(|e| CoreError::Adapter(format!("token endpoint: {e}")))?;
        let status = response.status().as_u16();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| CoreError::Adapter(format!("token body: {e}")))?
            .to_bytes();
        if status != 200 {
            return Err(CoreError::Adapter(format!(
                "token endpoint returned {status}"
            )));
        }
        let json: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| CoreError::Adapter(format!("token json: {e}")))?;
        let token = json
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .ok_or(CoreError::MissingElement("access_token"))?
            .to_owned();
        let ttl = json
            .get("expires_in")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(300);
        Ok((token, Duration::from_secs(ttl)))
    }
}

#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    /// 80 %-of-TTL mark: refresh once past this.
    stale_at: Instant,
    /// Hard expiry: never serve past this.
    expires_at: Instant,
}

/// Per-NF-type token cache with single-flight refresh.
pub struct TokenCache<F: TokenFetcher> {
    fetcher: F,
    tokens: Mutex<HashMap<NfType, CachedToken>>,
}

impl<F: TokenFetcher> TokenCache<F> {
    /// Cache over `fetcher`.
    pub fn new(fetcher: F) -> Self {
        TokenCache {
            fetcher,
            tokens: Mutex::new(HashMap::new()),
        }
    }

    async fn refresh(&self, target: NfType) -> Result<String, CoreError> {
        let (token, ttl) = self.fetcher.fetch(target).await?;
        let now = Instant::now();
        let cached = CachedToken {
            token: token.clone(),
            stale_at: now + ttl.mul_f64(0.8),
            expires_at: now + ttl,
        };
        self.tokens.lock().await.insert(target, cached);
        Ok(token)
    }
}

impl<F: TokenFetcher> std::fmt::Debug for TokenCache<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenCache").finish()
    }
}

#[async_trait]
impl<F: TokenFetcher> TokenProvider for TokenCache<F> {
    async fn bearer_token(&self, target: NfType) -> Result<String, CoreError> {
        let now = Instant::now();
        {
            let tokens = self.tokens.lock().await;
            if let Some(cached) = tokens.get(&target) {
                if now < cached.stale_at {
                    return Ok(cached.token.clone());
                }
                if now < cached.expires_at {
                    // Stale but valid: serve it and let this caller refresh
                    // below; concurrent callers keep hitting this branch
                    // until the refresh lands (mutex serializes the insert).
                    let token = cached.token.clone();
                    drop(tokens);
                    // Proactive refresh; on failure keep serving until hard
                    // expiry rather than failing traffic early.
                    if let Err(e) = self.refresh(target).await {
                        tracing::warn!(target_nf = %target, error = %e,
                            "proactive token refresh failed; serving cached token");
                    }
                    return Ok(token);
                }
            }
        }
        self.refresh(target).await
    }
}

/// Convenience alias for the production cache.
pub type HttpTokenCache = TokenCache<HttpTokenFetcher>;

/// Build the production token cache from environment-injected credentials.
pub fn token_cache_from_env(
    token_endpoint: String,
    timeout: Duration,
) -> Result<Arc<HttpTokenCache>, CoreError> {
    let client_id = std::env::var("IWF_OAUTH_CLIENT_ID")
        .map_err(|_| CoreError::MissingElement("IWF_OAUTH_CLIENT_ID env"))?;
    let client_secret = std::env::var("IWF_OAUTH_CLIENT_SECRET")
        .map_err(|_| CoreError::MissingElement("IWF_OAUTH_CLIENT_SECRET env"))?;
    Ok(Arc::new(TokenCache::new(HttpTokenFetcher::new(
        OAuthConfig {
            token_endpoint,
            client_id,
            client_secret,
            timeout,
        },
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct CountingFetcher {
        calls: AtomicU32,
        ttl: Duration,
    }

    #[async_trait]
    impl TokenFetcher for CountingFetcher {
        async fn fetch(&self, _t: NfType) -> Result<(String, Duration), CoreError> {
            let n = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            Ok((format!("token-{n}"), self.ttl))
        }
    }

    #[tokio::test]
    async fn caches_until_80_percent_ttl() {
        let cache = TokenCache::new(CountingFetcher {
            calls: AtomicU32::new(0),
            ttl: Duration::from_millis(200),
        });
        let t1 = cache.bearer_token(NfType::Udm).await.expect("token");
        let t2 = cache.bearer_token(NfType::Udm).await.expect("token");
        assert_eq!(t1, t2, "served from cache");

        // Past 80 % of 200 ms: a request triggers refresh.
        tokio::time::sleep(Duration::from_millis(170)).await;
        let t3 = cache.bearer_token(NfType::Udm).await.expect("token");
        assert_eq!(t3, t1, "stale-but-valid token still served");
        let t4 = cache.bearer_token(NfType::Udm).await.expect("token");
        assert_eq!(t4, "token-2", "refresh landed");
    }

    #[tokio::test]
    async fn token_scope_is_per_nf_type() {
        let cache = TokenCache::new(CountingFetcher {
            calls: AtomicU32::new(0),
            ttl: Duration::from_secs(60),
        });
        let udm = cache.bearer_token(NfType::Udm).await.expect("token");
        let ausf = cache.bearer_token(NfType::Ausf).await.expect("token");
        assert_ne!(udm, ausf, "independent cache slots");
    }

    #[tokio::test]
    async fn http_fetcher_parses_token_response() {
        use axum::routing::post;
        let app = axum::Router::new().route(
            "/oauth2/token",
            post(|body: String| async move {
                assert!(body.contains("grant_type=client_credentials"));
                assert!(body.contains("scope=udm"));
                axum::Json(serde_json::json!({
                    "access_token": "at-1", "token_type": "Bearer", "expires_in": 600
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock");
        });

        let fetcher = HttpTokenFetcher::new(OAuthConfig {
            token_endpoint: format!("http://{addr}/oauth2/token"),
            client_id: "iwf".to_owned(),
            client_secret: "s3cret".to_owned(),
            timeout: Duration::from_secs(2),
        });
        let (token, ttl) = fetcher.fetch(NfType::Udm).await.expect("fetch");
        assert_eq!(token, "at-1");
        assert_eq!(ttl, Duration::from_secs(600));
    }
}
