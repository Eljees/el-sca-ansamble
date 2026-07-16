# Issue draft for ossf/cve-bin-tool (submit manually)

**Title:** Please cut a 3.4.1 release: EPSS enrichment is completely broken in 3.4

**Body:**

The latest stable release (3.4, also latest on PyPI) ships a broken EPSS
source — EPSS data can never reach the database:

1. `Epss_Source.get_cve_data()` calls `await self.update_epss()` while the
   3.4 signature is `update_epss(self, cursor)` — an instant `TypeError`,
   swallowed by the broad `except` ("Unable to fetch EPSS, skipping EPSS."),
   so the failure is invisible unless debug logging is on.
2. Even with a cursor, `EPSS_id_finder()` reads the `metrics` table during
   the source gather, which runs before `populate_db()` →
   `populate_metrics()` seeds it: fresh cache → `no such table: metrics`,
   empty table → `IndexError` from `fetchall()[0][0]`.

Both layers are already fixed on `main` by the "metric ids as constants"
change, and `3.4.1rc0` (2025-06-13) contains the fix — but there has been no
final release since, so every `pip install cve-bin-tool` user silently gets
no EPSS data.

Could you finalize 3.4.1 (ideally including the EPSS URL move to
epss.empiricalsecurity.com, which rc0 still lacks)? Happy to contribute an
offline regression test for the 3.4 failure mode if useful.
