# IWF — Engineering Review Bundle

Production-grade review artifacts for the IMS ↔ 5G Core Interworking Function
(IWF). Generated for handover to a new engineering team.

## Documents (table of contents)

| # | Document | Covers |
|---|---|---|
| 01 | [Executive Summary](01-ExecutiveSummary.md) | Overview, assessment, strengths/concerns, top recommendations |
| 02 | [Architecture (HLD + LLD, Mermaid)](02-Architecture.md) | Component/flow/sequence/state diagrams, deployment, boundaries |
| 03 | [Code Review Report](03-CodeReviewReport.md) | Per-module review, defect & risk register, maintainability scores |
| 04 | [Security Assessment](04-SecurityReport.md) | OWASP-mapped findings, exploit scenarios, mitigations |
| 05 | [Performance Assessment](05-PerformanceReport.md) | Hotspots, allocations, locking, optimization roadmap |
| 06 | [Test Strategy & Cases + Load Generation](06-TestStrategy.md) | Coverage, detailed test cases, how to generate load |
| 07 | [Dependency Review](07-DependencyReview.md) | Every dependency: purpose, version, license, risk, action |
| 08 | [Improvement Roadmap](08-Roadmap.md) | Immediate / short / medium / long-term, prioritized |

## Reused (already in the repo — not duplicated here)

| Topic | Location |
|---|---|
| High-Level Design (prose + failure-mode table) | `docs/hld.md` |
| Low-Level Design (per-crate structure, lock inventory) | `docs/lld.md` |
| Architecture Decision Records | `docs/adr/0001..0005-*.md` |
| Operations runbook | `docs/runbook.md` |
| Production-readiness checklist | `docs/production-readiness.md` |
| Admin API (OpenAPI 3.0) | `iwf-admin/openapi/iwf-admin.yaml` |
| Build/deploy/test against Open5GS | `docs/deploy-open5gs.md`, `deploy/cdot/STEPS.md` |
| Simple test steps / Wireshark | `docs/TEST-STEPS.md`, `docs/WIRESHARK.md` |
| FHS runtime kit + control script + functional tests | `deploy/cdot/` |

## Database review — N/A (stated explicitly)

The IWF is **stateless** (ADR-0004): it holds only transaction-scoped state
(pending correlation, discovery cache, OAuth tokens) — no database, no schema,
no migrations. The only datastore in the wider system is Open5GS's MongoDB
(subscriber data), which is **external** and out of scope for this codebase.
Therefore Section 13 (Database Review) and ER diagrams are intentionally
omitted; see `docs/adr/0004-clustering-model.md`.

## Generating the PDFs

No PDF converter is installed on the build host, so these artifacts ship as
Markdown (renders with diagrams on GitHub/GitLab/VS Code). To produce the
requested PDFs, install `pandoc` + a LaTeX engine (or `mermaid-filter` for
diagram rendering) and run:

```bash
bash docs/review/build-pdfs.sh
# emits: HLD.pdf LLD.pdf CodeReviewReport.pdf TestStrategy.pdf OperationsGuide.pdf
```

## Scope & method

- Reviewed: all 30 Rust source files (~9,800 LoC) across 11 crates, plus
  config, deploy, and CI artifacts.
- Verified live: the system was deployed and exercised end-to-end against a
  real Open5GS core (see `docs/deploy-open5gs.md`); findings marked
  *(verified)* were observed, not inferred.
- Depth: exhaustive at the **module and public-API** level and for the
  **defect/security/performance** registers; representative (not
  symbol-by-symbol) at the private-helper level, since every public surface
  already carries `///` rustdoc. Run `cargo doc --workspace --no-deps` for the
  generated per-symbol API reference.
