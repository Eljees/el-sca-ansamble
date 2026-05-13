# Security Notes

Do not store secrets in repository config files. Use environment variables, `.env`, or a dedicated secret manager.

Pin image versions and, in production, prefer digests and verified signatures where available. Hash validation matters most for mirrored Grype artifacts because the wrapper activates only validated content.

Last-known-good data is a resilience tool, not a license to run stale forever. The policy should keep a clear maximum age and fail closed when the retained data is too old.

Insecure modes such as validation disablement, insecure registries, or indefinite stale acceptance are intentionally excluded from defaults in this MVP.
