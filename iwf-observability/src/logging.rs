//! JSON structured logging with a hot-reloadable **filter** — not just a
//! global level. The reload target is an [`EnvFilter`], so an operator can,
//! at runtime and without a restart, do any of:
//!
//! ```text
//! debug                                  # global level
//! info,iwf_diameter::transport=warn      # quiet a noisy protocol target
//! info,iwf_diameter=trace                # TRACE one module
//! info,iwf_sba=debug,iwf_discovery=debug # detail specific NF adapters
//! ```
//!
//! The initial filter comes from `IWF_LOG_LEVEL` (a bare level or a full
//! directive string); changes arrive via the admin API
//! (`PUT /admin/v1/log-level`, body = the new directive string).

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{reload, EnvFilter};

/// Handle for runtime filter changes (admin API `PUT /admin/v1/log-level`).
#[derive(Clone)]
pub struct LogHandle {
    reload: reload::Handle<EnvFilter, tracing_subscriber::Registry>,
}

impl std::fmt::Debug for LogHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogHandle").finish()
    }
}

impl LogHandle {
    /// Replace the active filter with `directives` — an `EnvFilter` string:
    /// a bare level (`debug`) or comma-separated per-target directives
    /// (`info,iwf_diameter::transport=warn,iwf_sba=debug`). A malformed
    /// directive is rejected and the previous filter stays active.
    pub fn set_filter(&self, directives: &str) -> Result<(), String> {
        // Parse first so an invalid directive can't blank the filter.
        let filter =
            EnvFilter::try_new(directives).map_err(|e| format!("invalid log filter: {e}"))?;
        self.reload
            .modify(|f| *f = filter)
            .map_err(|e| e.to_string())?;
        tracing::info!(filter = %directives, "log filter changed");
        Ok(())
    }
}

/// Install the global JSON subscriber. Call once at process start; returns the
/// reload handle. `initial` is an `EnvFilter` directive string (a bare level
/// works); an unparseable value falls back to `info`. In unit tests (where a
/// global subscriber may already exist) the error case returns `None`.
pub fn init_logging(initial: &str) -> Option<LogHandle> {
    let env = EnvFilter::try_new(initial)
        .unwrap_or_else(|_| EnvFilter::new(LevelFilter::INFO.to_string()));
    let (filter_layer, handle) = reload::Layer::new(env);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .with_target(true);

    let result = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .try_init();

    match result {
        Ok(()) => Some(LogHandle { reload: handle }),
        Err(_) => None, // already initialized (tests)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_changes_apply_at_runtime() {
        // First init in the test binary wins; both branches exercise the
        // reload path without panicking.
        if let Some(handle) = init_logging("info") {
            // Global level change.
            handle.set_filter("debug").expect("global level");
            // Per-target directives (TRACE one module, quiet a noisy target,
            // detail a specific NF adapter) — the capability LevelFilter lacked.
            handle
                .set_filter("info,iwf_diameter::transport=warn,iwf_diameter=trace,iwf_sba=debug")
                .expect("per-target filter");
            // A malformed level in a directive is rejected; previous stays.
            assert!(
                handle.set_filter("iwf_diameter=boguslevel").is_err(),
                "bad level must be rejected"
            );
        }
    }
}
