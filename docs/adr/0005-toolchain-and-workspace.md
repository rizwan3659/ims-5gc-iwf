# ADR-0005: Exact dependency pinning for rustc 1.75; iwf-node addition

## Status
Accepted.

## Context
The build toolchain is rustc/cargo 1.75, which does not do MSRV-aware
dependency resolution; floating semver ranges pull releases requiring newer
compilers (observed: indexmap, time, clap, rayon, half).

## Decision
- All direct dependencies pinned `=x.y.z` in `[workspace.dependencies]`.
- Offending transitive releases pinned via `cargo update --precise`
  (recorded in Cargo.lock, which is committed).
- The mandated workspace listed 10 library crates and no executable; the
  composition-root binary lives in an 11th member, `iwf-node`, keeping
  hexagonal wiring (adapters composed at the edge) out of the libraries.

## Consequences
- Dependency upgrades are explicit, reviewed events (CI gates on the lock).
- When the fleet toolchain moves to a current rustc, relax pins to caret
  ranges plus `rust-version` enforcement in CI instead.
