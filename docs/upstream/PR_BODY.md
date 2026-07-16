## Summary

`CVEDB.refresh_cache_and_update_db()` gathers all data sources
(`run_coroutine(self.refresh())` -> `get_data()` -> `source.get_cve_data()`)
**before** it initializes the database and populates the static metric
definitions (`populate_db()` -> `populate_metrics()`). Any source that
resolves its metric id from the `metrics` table *while fetching* therefore
sees an empty -- or, on a fresh cache, missing -- table.

This PR hoists `init_database()` + `populate_metrics()` above the source
gather and removes the now-redundant `populate_metrics()` call from
`populate_db()`. Both hoisted calls are idempotent
(`CREATE TABLE IF NOT EXISTS` / `INSERT or REPLACE`) and depend on no
source output. A `cachedir` existence guard is added because `refresh()`
used to be the first thing that created it.

## Why: a reproducible crash in released 3.4

In cve-bin-tool 3.4 (current latest on PyPI) the EPSS source resolves its
metric id during the gather:

```python
def EPSS_id_finder(self, cursor):
    """Search for metric id in EPSS table"""
    query = """
    SELECT metrics_id FROM metrics
    WHERE metrics_name = "EPSS"
    """
    cursor.execute(query)
    self.epss_metric_id = cursor.fetchall()[0][0]   # <- IndexError
```

At that point `populate_metrics()` has not run yet, so the lookup raises
`IndexError: list index out of range` (or `sqlite3.OperationalError: no
such table: metrics` on a completely fresh cache). The exception is
swallowed by the broad `except Exception` in `get_cve_data()`, so EPSS
silently ends at 0 entries with "Unable to fetch EPSS, skipping EPSS."

(Stock 3.4 additionally calls `await self.update_epss()` without the
required `cursor` argument; that separate bug is already gone on `main`
after the EPSS source rewrite, so this PR does not touch it. It is
mentioned because on stock 3.4 that TypeError fires first and hides the
ordering bug behind the same swallowed-exception log line.)

## Why it still matters on main

On `main` the EPSS source now uses the `EPSS_METRIC_ID` constant instead
of a DB lookup, so the crash is masked -- but metric definitions are still
written only after every source has finished gathering, and
`init_database()` carries an `ensure_unknown_metric()` band-aid for exactly
this class of problem. The existing comment in `populate_db()` ("It can't
be run before creation of metrics table.") states the dependency; this
change makes the execution order actually satisfy it, for current and
future sources. The hunks also apply cleanly to v3.4 for anyone
backporting.

## Testing

- Static verification: the patched module compiles; an AST check confirms
  the call order `init_database -> populate_metrics -> gather ->
  populate_db`, and that `populate_db` no longer calls `populate_metrics`.
- `populate_metrics()` uses `INSERT or REPLACE`, so running it before the
  gather (and repeatedly) is idempotent; `metric_finder()` and
  `store_epss_data()` read the same rows as before.
- Please run the full suite in CI; happy to adjust if any test pins the
  old ordering.
