# How to submit the upstream PR (requires your GitHub auth)

Upstream lives at ossf/cve-bin-tool (github.com/intel/cve-bin-tool
redirects there).

## 0. Review the patch first

Author + Signed-off-by are prepared as `Elaria <3.14hell@gmail.com>`;
amend if that is not what you want to attest.

## 1. Fork once

Web UI: https://github.com/ossf/cve-bin-tool/fork
or: `gh repo fork ossf/cve-bin-tool --clone=false`

## 2. Clone your fork, branch off main

    git clone https://github.com/<YOUR_GH_USER>/cve-bin-tool
    cd cve-bin-tool
    git checkout -b fix/populate-metrics-before-source-gather origin/main

## 3. Apply the prepared patch

    git am path/to/docs/upstream/0001-fix-populate-static-metric-definitions-before-data-s.patch

The two hunks are byte-identical in v3.4, 3.4.1rc0 and current main
(verified 2026-07-16; only line offsets differ). If main has drifted
since: `git apply --check` first, or `git am --3way`.

## 4. Local sanity

    python -m pytest tests/test_cvedb.py -q

## 5. Push and open the PR

    git push -u origin fix/populate-metrics-before-source-gather
    gh pr create --repo ossf/cve-bin-tool \
      --title "$(cat PR_TITLE.txt)" \
      --body-file PR_BODY.md

## Why this was not opened automatically

Forking/pushing to GitHub and creating the PR require an interactive
GitHub credential that does not exist non-interactively in this
environment (and api.github.com is TLS-intercepted on some routes in
the contour). Everything else -- root-cause analysis, the patch, apply
verification against v3.4 / 3.4.1rc0 / main context -- is done.
