//! # iwf-translation
//!
//! Rule-driven translation between Diameter (Cx/Sh) requests and 5GC
//! service-based-interface operations.
//!
//! The engine is configuration-first: which AVPs are extracted, which NF is
//! called, and how HTTP statuses map back to Diameter answers is all
//! declared in a YAML/TOML rule document (schema in [`rule`]), hot-swappable
//! at runtime via [`rule::RuleStore`]. Custom logic beyond the DSL plugs in
//! through the [`plugin::TranslationPlugin`] trait.
//!
//! Spec-clause documentation for every field mapping lives in [`mapping`].

#![deny(warnings)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod engine;
pub mod mapping;
pub mod plugin;
pub mod rule;

pub use engine::TranslationEngine;
pub use plugin::{PluginRegistry, TranslationPlugin};
pub use rule::{Action, Rule, RuleSet, RuleStore, Trigger};
