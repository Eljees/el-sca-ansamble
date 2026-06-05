# bundle/ — the runnable offline bundle, shipped via Git LFS

This directory carries the **container images + vulnerability DBs** through GitLab
itself (Git LFS), so a target host needs only:

```bash
git lfs install
git clone <repo>
cd el-sca-ansamble
./scripts/deploy_light.sh          # reads this bundle/ by default
```

— no scp, no USB, no registry login.

## What goes here (put these in before committing)

- `el-sca-images-light.tar`   — all stack images (Trivy + Grype + Syft + helpers)
- `grype-db.tar.gz`           — Grype vulnerability DB
- `trivy-cache.tar.gz`        — Trivy vulnerability DB

These files are tracked by **Git LFS** (see `.gitattributes`).  `git clone`
downloads them automatically when `git lfs` is installed.

## Refreshing the bundle (on a machine with network)

```bash
./scripts/pack_light.sh              # builds tar + db-image/*.tar.gz
cp ../el-sca-images-light.tar bundle/        # or wherever pack wrote it
cp ../artifacts/db-image/grype-db.tar.gz bundle/
cp ../artifacts/db-image/trivy-cache.tar.gz bundle/
git add bundle && git commit -m "refresh bundle" && git push
```

> If GitLab LFS is disabled or quota-limited, use the Container Registry path
> instead (`scripts/export_db_image.sh --push` + push images) — see
> `docs/SHIP_AND_DEPLOY.md`.
