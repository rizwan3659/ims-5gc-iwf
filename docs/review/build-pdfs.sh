#!/usr/bin/env bash
# build-pdfs.sh — render the review Markdown into the requested PDFs.
#
# Requires (not bundled — install on the doc host):
#   pandoc, a LaTeX engine (texlive-xetex), and for Mermaid diagrams either
#   mermaid-filter (npm i -g mermaid-filter) or pre-rendered SVGs.
#
# Without mermaid-filter, ```mermaid blocks render as code (still readable).
set -euo pipefail
cd "$(dirname "$0")"

command -v pandoc >/dev/null || { echo "install pandoc (+texlive-xetex) first"; exit 1; }
MERMAID_FILTER=()
command -v mermaid-filter >/dev/null && MERMAID_FILTER=(-F mermaid-filter)

PDF_OPTS=(--toc --toc-depth=3 -V geometry:margin=2cm --pdf-engine=xelatex "${MERMAID_FILTER[@]}")
REPO=../..

emit() { # <out.pdf> <title> <md...>
  local out="$1" title="$2"; shift 2
  echo "[pdf] $out"
  pandoc "${PDF_OPTS[@]}" -M title="$title" -o "$out" "$@"
}

# HLD.pdf  — architecture (mermaid) + prose HLD + ADRs
emit HLD.pdf "IWF — High-Level Design" \
  02-Architecture.md "$REPO/docs/hld.md" \
  "$REPO/docs/adr/0001-async-runtime.md" "$REPO/docs/adr/0002-diameter-codec.md" \
  "$REPO/docs/adr/0003-translation-dsl.md" "$REPO/docs/adr/0004-clustering-model.md" \
  "$REPO/docs/adr/0005-toolchain-and-workspace.md"

# LLD.pdf  — low-level design + architecture sequence/state diagrams
emit LLD.pdf "IWF — Low-Level Design" "$REPO/docs/lld.md" 02-Architecture.md

# CodeReviewReport.pdf — exec summary + code review + security + perf + deps + maintainability + roadmap
emit CodeReviewReport.pdf "IWF — Code Review Report" \
  01-ExecutiveSummary.md 03-CodeReviewReport.md 04-SecurityReport.md \
  05-PerformanceReport.md 07-DependencyReview.md 08-Roadmap.md

# TestStrategy.pdf — test strategy + cases + load generation
emit TestStrategy.pdf "IWF — Test Strategy & Load Generation" 06-TestStrategy.md

# OperationsGuide.pdf — runbook + deploy + control script + readiness
emit OperationsGuide.pdf "IWF — Operations Guide" \
  "$REPO/docs/runbook.md" "$REPO/deploy/cdot/STEPS.md" \
  "$REPO/docs/deploy-open5gs.md" "$REPO/docs/production-readiness.md"

echo "[pdf] done: HLD.pdf LLD.pdf CodeReviewReport.pdf TestStrategy.pdf OperationsGuide.pdf"
