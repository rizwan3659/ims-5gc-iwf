//! JSON structured logging with a hot-switchable level.

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;

/// Handle for runtime log-level changes (admin API `PUT /admin/v1/log-level`).
#[derive(Clone)]
pub struct LogHandle {
    reload: reload::Handle<LevelFilter, tracing_subscriber::Registry>,
}

impl std::fmt::Debug for LogHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogHandle").finish()
    }
}

impl LogHandle {
    /// Switch the active level. Accepts `trace|debug|info|warn|error|off`.
    pub fn set_level(&self, level: &str) -> Result<(), String> {
        let filter: LevelFilter = level
            .parse()
            .map_err(|_| format!("unknown log level {level}"))?;
        self.reload
            .modify(|f| *f = filter)
            .map_err(|e| e.to_string())?;
        tracing::info!(%level, "log level changed");
        Ok(())
    }
}

/// Install the global JSON subscriber. Call once at process start; returns
/// the reload handle. In unit tests (where a global subscriber may already
/// exist) the error case returns `None`.
pub fn init_logging(initial_level: &str) -> Option<LogHandle> {
    let filter: LevelFilter = initial_level.parse().unwrap_or(LevelFilter::INFO);
    let (filter_layer, handle) = reload::Layer::new(filter);

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
    fn level_changes_apply() {
        // First init in the test binary wins; both branches give a handle
        // path we can exercise without panicking.
        if let Some(handle) = init_logging("info") {
            handle.set_level("debug").expect("switch to debug");
            handle.set_level("warn").expect("switch to warn");
            assert!(handle.set_level("verbose").is_err(), "bogus level rejected");
        }
    }
}
