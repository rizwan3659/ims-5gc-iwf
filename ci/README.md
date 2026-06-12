# CI workflow

`github-actions-ci.yml` is the GitHub Actions pipeline (lint, test, coverage,
image build, helm lint). It lives here instead of `.github/workflows/` because
the token used for the initial push lacked the `workflow` OAuth scope.

To enable it:
```bash
gh auth refresh -s workflow          # one-time, grants workflow scope
mkdir -p .github/workflows
git mv ci/github-actions-ci.yml .github/workflows/ci.yml
git commit -m "Enable GitHub Actions CI" && git push
```
(Or paste the file via the repo's Actions tab in the web UI.)
