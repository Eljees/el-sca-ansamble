"""Palettes for the dashboard skin.

Ten variants were designed for the GUI; ``rose-phosphor`` is the one currently
applied.  They live here as *data* rather than dead CSS so that the picker in
the header can render real previews today, and so that switching themes at
runtime is a small step later (write the vars into ``:root`` and persist the
choice) instead of a rewrite.

The mutagen barrels are deliberately NOT themeable: they are acid green in
every variant, because their colour carries meaning (fill level of a DB).
"""

from __future__ import annotations

from typing import Any

# The skin currently rendered by dashboard._GUI_HTML.  Keep in sync with :root.
ACTIVE_THEME_ID = "rose-phosphor"


def _t(
    theme_id: str,
    name: str,
    tagline: str,
    *,
    bg: str,
    panel: str,
    fg: str,
    accent: str,
    accent2: str,
) -> dict[str, Any]:
    return {
        "id": theme_id,
        "name": name,
        "tagline": tagline,
        "swatch": {"bg": bg, "panel": panel, "fg": fg, "accent": accent, "accent2": accent2},
    }


#: Ordered as they were presented.  A–E: phosphor family. F–J: red/pink family.
THEMES: list[dict[str, Any]] = [
    _t(
        "phosphor-bright",
        "Phosphor Bright",
        "Тот же фосфор, но светлее и без виньетки",
        bg="#04170c",
        panel="#07240f",
        fg="#c7ffdd",
        accent="#4dffa0",
        accent2="#4dffa0",
    ),
    _t(
        "neon-grid",
        "Neon Grid",
        "Фоновая сетка и циановый второй акцент",
        bg="#03150c",
        panel="#062010",
        fg="#c9ffe0",
        accent="#3dffb0",
        accent2="#22d3ee",
    ),
    _t(
        "toxic-bloom",
        "Toxic Bloom",
        "Кислотный градиент, в одном ключе с бочками",
        bg="#06180a",
        panel="#0a2610",
        fg="#d6ffc2",
        accent="#a3ff3d",
        accent2="#a3ff3d",
    ),
    _t(
        "terminal-aurora",
        "Terminal Aurora",
        "Зелёный с фиолетовым полярным переходом",
        bg="#04140f",
        panel="#08211a",
        fg="#c6ffe8",
        accent="#38ffc2",
        accent2="#a78bfa",
    ),
    _t(
        "hazard-neon",
        "Hazard Neon",
        "Фосфор плюс янтарь на предупреждениях",
        bg="#0f1508",
        panel="#161f0c",
        fg="#e6ffc9",
        accent="#c6ff2e",
        accent2="#ffb020",
    ),
    _t(
        "magenta-bloom",
        "Magenta Bloom",
        "Маджента ведёт, мятный второй голос",
        bg="#0a0713",
        panel="#130a1e",
        fg="#f0d9ff",
        accent="#ff2d95",
        accent2="#3dffb0",
    ),
    _t(
        "crimson-terminal",
        "Crimson Terminal",
        "Бордовый терминал, зелень бочек бьёт контрастом",
        bg="#120406",
        panel="#1c070b",
        fg="#ffd9dd",
        accent="#ff3b47",
        accent2="#ffb020",
    ),
    _t(
        "vaporwave-ward",
        "Vaporwave Ward",
        "Розовый, циан и фиолет разом — самый пёстрый",
        bg="#0d0718",
        panel="#170c26",
        fg="#ffe3f5",
        accent="#ff6ec7",
        accent2="#22d3ee",
    ),
    _t(
        "blood-neon",
        "Blood Neon",
        "Алый и электрожёлтый. Жёстко и тревожно",
        bg="#0b0507",
        panel="#15080b",
        fg="#ffe0e3",
        accent="#ff1e3c",
        accent2="#f5ff2e",
    ),
    _t(
        "rose-phosphor",
        "Rose Phosphor",
        "Фосфорный текст, розовый хром",
        bg="#0f0a10",
        panel="#1a1019",
        fg="#c9ffd9",
        accent="#ff77c8",
        accent2="#4dffa0",
    ),
]


def active_theme() -> dict[str, Any]:
    """The theme currently baked into the GUI stylesheet."""
    return next(t for t in THEMES if t["id"] == ACTIVE_THEME_ID)


def render_theme_picker() -> str:
    """Header widget: a disabled picker that still previews every palette.

    Deliberately not wired up — the summary opens, the swatches render, and
    every "Выбрать" button is ``disabled``.  Switching is planned, not shipped;
    a control that looks live but does nothing is worse than one that says so.
    """
    cards = []
    for theme in THEMES:
        s = theme["swatch"]
        is_active = theme["id"] == ACTIVE_THEME_ID
        chips = "".join(
            f'<i style="background:{s[k]}"></i>' for k in ("bg", "panel", "fg", "accent", "accent2")
        )
        badge = '<span class="theme-active">активна</span>' if is_active else ""
        cards.append(
            '<li class="theme-card">'
            f'<div class="theme-chips" aria-hidden="true">{chips}</div>'
            f'<div class="theme-name">{theme["name"]}{badge}</div>'
            f'<div class="theme-tag">{theme["tagline"]}</div>'
            '<button type="button" disabled title="Переключение тем ещё не реализовано">'
            "Выбрать</button>"
            "</li>"
        )
    return (
        '<details class="theme-picker">'
        f'<summary title="Превью палитр. Переключение появится позже.">'
        f'🎨 Темы · {len(THEMES)} <span class="soon">скоро</span></summary>'
        '<div class="theme-panel">'
        '<p class="theme-note">Превью палитр. Выбор пока недоступен — '
        "бочки с мутагеном остаются зелёными в любой теме.</p>"
        f'<ul class="theme-grid">{"".join(cards)}</ul>'
        "</div></details>"
    )
