#!/usr/bin/env sh
# Remove generated / cached artefacts from the working tree.
#
# Why not just `git clean -fdX`?
# This script is intentionally portable to non-git checkouts (CI artefact
# tarballs, air-gapped environments, Docker build contexts where .git is
# absent).  `git clean` is faster and more thorough when a .git directory is
# present — use it when you have one.  This script covers the baseline case.
set -eu

find . -type d -name __pycache__ -prune -exec rm -rf {} +
rm -rf .pytest_cache
rm -f artifacts/scanner-artifacts.zip
