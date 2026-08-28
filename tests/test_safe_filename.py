"""Stored-name sanitising must not eat the whole name.

CYBERSEC-12318: a 1.3 GB delivery called "Сборки на проверку ИБ.zip" was
stored as the single word "zip" — every non-ASCII character became "-" and
.strip(".-") then removed the dashes along with the dot. The artifact card,
the run directory (zip-20260810-124849) and the report's "Target" all
inherited it, which defeats the object-identification the report relies on.
"""

from __future__ import annotations

from resilient_updates.artifact_catalog import _safe_filename


def test_cyrillic_name_is_transliterated_not_erased():
    assert _safe_filename("Сборки на проверку ИБ.zip") == "Sborki-na-proverku-IB.zip"


def test_extension_survives_a_fully_non_ascii_stem():
    out = _safe_filename("Отчёт.tar.gz")
    assert out.endswith(".gz")
    assert out.startswith("Otch")


def test_spaces_become_dashes_and_extension_is_kept():
    assert _safe_filename("prometheus 3.11 linux-amd64.tar.gz") == "prometheus-3.11-linux-amd64.tar.gz"


def test_plain_ascii_names_are_untouched():
    assert _safe_filename("avandoc-client-1.0.0.5.tar.gz") == "avandoc-client-1.0.0.5.tar.gz"


def test_degenerate_names_still_yield_something_usable():
    assert _safe_filename("....zip") == "artifact.zip"
    assert _safe_filename("") == "artifact.bin"
    assert _safe_filename("no-extension") == "no-extension"


def test_path_traversal_is_still_stripped():
    assert _safe_filename("../../etc/passwd") == "passwd"
    assert "/" not in _safe_filename("a/b/c.zip")
