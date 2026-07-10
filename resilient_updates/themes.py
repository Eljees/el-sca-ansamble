"""Skins for the dashboard: colour palettes and neon edge treatments.

Two independent axes, both switchable at runtime:

* **theme** — the palette (``:root[data-theme=...]`` custom properties);
* **edge**  — how a project card's border is drawn (``:root[data-edge=...]``).

Design rules that are NOT negotiable per skin, because colour carries meaning
here and a dashboard that looks pretty while hiding a failure is worse than an
ugly one:

* ``--err`` is the same scarlet in every theme.  A failed stage, an unavailable
  source (✕) and "Удалить навсегда" must never blend into decoration.
* The mutagen barrels stay acid green everywhere: their fill encodes DB level.
* An edge is coloured by *status*, never by the preset.  Yellow = never scanned,
  toxic green = has saved runs, pink = legacy (evidence, cannot be purged).
  The ten presets differ in geometry alone.

Switching is persisted per browser (``localStorage``), not on the server: the
dashboard is served without authentication, so a server-side "current theme"
would let anyone on the network restyle the UI for everybody.
"""

from __future__ import annotations

from typing import Any

ACTIVE_THEME_ID = "rose-phosphor"
ACTIVE_EDGE_ID = "hazard"

#: Semantic colours, identical in every theme.
ERR = "#ff5f56"
#: Status colours for card edges (Cyberpunk-2077 palette).
EDGE_NEW = "#fcee0a"  # ещё не сканировали
EDGE_SCANNED = "#39ff14"  # есть сохранённые прогоны
EDGE_LEGACY = "#ff2e88"  # представление evidence, удалять нельзя


# ── tiny hex helpers (no colour lib in the runtime deps) ────────────────────


def _rgb(hex_colour: str) -> tuple[int, int, int]:
    h = hex_colour.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _hex(rgb: tuple[float, float, float]) -> str:
    r, g, b = (max(0, min(255, round(c))) for c in rgb)
    return f"#{r:02x}{g:02x}{b:02x}"


def _mix(a: str, b: str, t: float) -> str:
    """Blend ``a`` towards ``b`` by ``t`` (0..1)."""
    ra, ga, ba = _rgb(a)
    rb, gb, bb = _rgb(b)
    return _hex((ra + (rb - ra) * t, ga + (gb - ga) * t, ba + (bb - ba) * t))


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
    active: str = "#ffd166",
) -> dict[str, Any]:
    """Derive the full variable set from five anchor colours."""
    surface = _mix(panel, fg, 0.06)
    variables = {
        "--bg": bg,
        "--panel": panel,
        "--surface": surface,
        "--line": _mix(bg, accent, 0.28),
        "--line2": _mix(bg, accent, 0.42),
        "--fg": fg,
        "--muted": _mix(fg, bg, 0.45),
        "--accent": accent,
        "--ok": accent2,
        "--active": active,
        "--err": ERR,
        "--glow": accent + "66",
    }
    return {
        "id": theme_id,
        "name": name,
        "tagline": tagline,
        "vars": variables,
        "swatch": {"bg": bg, "panel": panel, "fg": fg, "accent": accent, "accent2": accent2},
    }


#: A–E: phosphor family.  F–J: red/pink family.
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
        "Кислотный градиент, в одном ключе как бочки",
        bg="#06180a",
        panel="#0a2610",
        fg="#d6ffc2",
        accent="#a3ff3d",
        accent2="#a3ff3d",
    ),
    _t(
        "terminal-aurora",
        "Terminal Aurora",
        "Зелёный и фиолетовый полярный переход",
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


def _e(edge_id: str, name: str, tagline: str, css: str, *, animated: bool = False) -> dict[str, Any]:
    return {"id": edge_id, "name": name, "tagline": tagline, "css": css.strip(), "animated": animated}


_CARD = ':root[data-edge="{id}"] .artifact-card'

#: Ten neon edge treatments.  Geometry only — the colour comes from `--edge`,
#: which the status class sets.  Animated ones are disabled under
#: prefers-reduced-motion (see render_skin_styles).
EDGES: list[dict[str, Any]] = [
    _e(
        "rail",
        "Триколор-рельс",
        "Контур акцентом, рёбра по бокам",
        f"""
{_CARD.format(id="rail")} {{ border-radius:10px; border:1px solid var(--edge); box-shadow:0 0 18px -7px var(--edge); }}
{_CARD.format(id="rail")}::before,
{_CARD.format(id="rail")}::after {{ content:""; position:absolute; top:12px; bottom:12px; width:2px;
    border-radius:2px; background:var(--edge); box-shadow:0 0 10px var(--edge); }}
{_CARD.format(id="rail")}::before {{ left:0; }}
{_CARD.format(id="rail")}::after {{ right:0; }}
""",
    ),
    _e(
        "hud",
        "HUD-скобки",
        "Угловые скобки, «оружейный прицел»",
        f"""
{_CARD.format(id="hud")} {{ border-radius:2px; border:1px solid var(--line); }}
{_CARD.format(id="hud")}::before,
{_CARD.format(id="hud")}::after {{ content:""; position:absolute; width:18px; height:18px;
    pointer-events:none; filter:drop-shadow(0 0 5px var(--edge)); }}
{_CARD.format(id="hud")}::before {{ top:0; left:0; border-top:2px solid var(--edge); border-left:2px solid var(--edge); }}
{_CARD.format(id="hud")}::after {{ bottom:0; right:0; border-bottom:2px solid var(--edge); border-right:2px solid var(--edge); }}
""",
    ),
    _e(
        "gradient",
        "Градиентный контур",
        "Живой перетекающий контур",
        f"""
{_CARD.format(id="gradient")} {{ border-radius:10px; border:2px solid transparent;
    background:linear-gradient(var(--surface),var(--surface)) padding-box,
               linear-gradient(90deg,var(--edge),var(--accent),var(--edge)) border-box;
    background-size:100% 100%,300% 100%; animation:edge-sweep 6s linear infinite; }}
@keyframes edge-sweep {{ to {{ background-position:0 0,300% 0; }} }}
""",
        animated=True,
    ),
    _e(
        "bevel",
        "Скошенные углы",
        "Фирменный бевел 2077 (свечение только внутри)",
        f"""
{_CARD.format(id="bevel")} {{ border:0; border-radius:0;
    clip-path:polygon(0 0,calc(100% - 16px) 0,100% 16px,100% 100%,16px 100%,0 calc(100% - 16px));
    box-shadow:inset 0 0 0 1px var(--edge), inset 0 0 26px -18px var(--edge); }}
""",
    ),
    _e(
        "double",
        "Двойной контур",
        "Внутренний по статусу, внешний по акценту",
        f"""
{_CARD.format(id="double")} {{ border-radius:8px; border:1px solid var(--edge); overflow:visible;
    box-shadow:0 0 0 1px var(--bg),0 0 0 3px var(--glow),0 0 20px -6px var(--edge); }}
""",
    ),
    _e(
        "glitch",
        "Глитч",
        "Хроматическое раздвоение края",
        f"""
{_CARD.format(id="glitch")} {{ border-radius:6px; border:1px solid #ffffff18; overflow:visible;
    box-shadow:-3px 0 0 -1px var(--edge),3px 0 0 -1px var(--accent),0 0 24px -10px var(--edge); }}
{_CARD.format(id="glitch")}:hover {{ box-shadow:-5px 0 0 -1px var(--edge),5px 0 0 -1px var(--accent),0 0 28px -8px var(--edge); }}
""",
    ),
    _e(
        "hazard",
        "Hazard-полоса",
        "Жёлтая/зелёная/розовая полоса сверху = статус",
        f"""
{_CARD.format(id="hazard")} {{ border-radius:8px; border:1px solid var(--line); box-shadow:0 0 18px -9px var(--edge); }}
{_CARD.format(id="hazard")}::before {{ content:""; position:absolute; top:0; left:0; right:0; height:4px;
    background:repeating-linear-gradient(45deg,var(--edge) 0 7px,transparent 7px 14px);
    box-shadow:0 0 10px var(--edge); }}
{_CARD.format(id="hazard")}:hover {{ border-color:var(--edge); }}
""",
    ),
    _e(
        "trace",
        "Дорожки с узлами",
        "Пунктир и горящие узлы в углах",
        f"""
{_CARD.format(id="trace")} {{ border-radius:4px; border:1px dashed var(--edge); overflow:visible;
    box-shadow:0 0 16px -9px var(--edge); }}
{_CARD.format(id="trace")}::before,
{_CARD.format(id="trace")}::after {{ content:""; position:absolute; width:6px; height:6px; border-radius:50%;
    background:var(--edge); box-shadow:0 0 8px var(--edge); }}
{_CARD.format(id="trace")}::before {{ top:-3px; left:-3px; }}
{_CARD.format(id="trace")}::after {{ bottom:-3px; right:-3px; }}
""",
    ),
    _e(
        "underglow",
        "Подсветка снизу",
        "Неоновая вывеска на стене",
        f"""
{_CARD.format(id="underglow")} {{ border-radius:10px; border:1px solid var(--line); overflow:visible;
    box-shadow:0 10px 26px -12px var(--edge),0 3px 0 -1px var(--edge); }}
""",
    ),
    _e(
        "ticker",
        "Бегущий тикер",
        "Полоска бежит по верхнему ребру",
        f"""
{_CARD.format(id="ticker")} {{ border-radius:8px; border:1px solid var(--line); box-shadow:0 0 16px -9px var(--edge); }}
{_CARD.format(id="ticker")}::before {{ content:""; position:absolute; top:0; left:0; right:0; height:2px;
    background:linear-gradient(90deg,transparent,var(--edge),var(--accent),transparent);
    background-size:50% 100%; animation:edge-ticker 2.6s linear infinite; }}
@keyframes edge-ticker {{ from {{ background-position:-100% 0; }} to {{ background-position:200% 0; }} }}
""",
        animated=True,
    ),
]


def active_theme() -> dict[str, Any]:
    return next(t for t in THEMES if t["id"] == ACTIVE_THEME_ID)


def active_edge() -> dict[str, Any]:
    return next(e for e in EDGES if e["id"] == ACTIVE_EDGE_ID)


def render_skin_styles() -> str:
    """``<style>`` with every palette and every edge preset."""
    blocks: list[str] = []
    for theme in THEMES:
        decls = " ".join(f"{k}:{v};" for k, v in theme["vars"].items())
        blocks.append(f':root[data-theme="{theme["id"]}"] {{ {decls} }}')

    # Status drives the edge colour; the preset only draws the geometry.
    blocks.append(
        f".artifact-card {{ --edge:{EDGE_SCANNED}; }}\n"
        f".artifact-card.st-new {{ --edge:{EDGE_NEW}; }}\n"
        f".artifact-card.st-scanned {{ --edge:{EDGE_SCANNED}; }}\n"
        f".artifact-card.st-legacy {{ --edge:{EDGE_LEGACY}; }}"
    )
    blocks.extend(edge["css"] for edge in EDGES)

    # A hidden project loses its edge entirely — otherwise "скрыт" and "активен"
    # glow identically.  Wins on specificity over every preset rule above.
    blocks.append(
        ":root[data-edge] .artifact-card.deleted, .artifact-card.deleted {\n"
        "  opacity:.5; border-color:var(--line); box-shadow:none; transition:none; }\n"
        ":root[data-edge] .artifact-card.deleted::before,\n"
        ":root[data-edge] .artifact-card.deleted::after { display:none; }"
    )

    animated = [e["id"] for e in EDGES if e["animated"]]
    if animated:
        sel = ",\n".join(f'  :root[data-edge="{i}"] .artifact-card' for i in animated)
        blocks.append(f"@media (prefers-reduced-motion: reduce) {{\n{sel} {{ animation:none; }}\n}}")

    return "<style>\n" + "\n".join(blocks) + "\n</style>"


def _cards(items: list[dict[str, Any]], kind: str, active_id: str) -> str:
    out = []
    for item in items:
        is_active = item["id"] == active_id
        if kind == "theme":
            s = item["swatch"]
            preview = "".join(
                f'<i style="background:{s[k]}"></i>' for k in ("bg", "panel", "fg", "accent", "accent2")
            )
        else:
            preview = (
                f'<i style="background:{EDGE_NEW}"></i>'
                f'<i style="background:{EDGE_SCANNED}"></i>'
                f'<i style="background:{EDGE_LEGACY}"></i>'
                + ('<span class="theme-anim">анимация</span>' if item["animated"] else "")
            )
        badge = '<span class="theme-active">активна</span>' if is_active else ""
        out.append(
            f'<li class="theme-card" data-kind="{kind}" data-id="{item["id"]}">'
            f'<div class="theme-chips" aria-hidden="true">{preview}</div>'
            f'<div class="theme-name">{item["name"]}{badge}</div>'
            f'<div class="theme-tag">{item["tagline"]}</div>'
            f'<button type="button" class="skin-pick" data-kind="{kind}" data-id="{item["id"]}">'
            "Выбрать</button></li>"
        )
    return "".join(out)


def render_theme_picker() -> str:
    """Header widget: pick a palette and an edge treatment.

    Applied client-side and remembered per browser.  The barrels are absent from
    both lists on purpose — their green is data, not decoration.
    """
    return (
        '<details class="theme-picker">'
        f'<summary title="Палитра и обводка карточек. Выбор запоминается в этом браузере.">'
        f"🎨 Тема · {len(THEMES)} + {len(EDGES)}</summary>"
        '<div class="theme-panel">'
        '<p class="theme-note">Выбор хранится в этом браузере, других операторов не трогает. '
        "Цвет обводки задаёт статус проекта: жёлтый — не сканирован, зелёный — есть прогоны, "
        "розовый — legacy. Бочки остаются зелёными в любой теме.</p>"
        "<h3>Палитра</h3>"
        f'<ul class="theme-grid">{_cards(THEMES, "theme", ACTIVE_THEME_ID)}</ul>'
        "<h3>Обводка проектов</h3>"
        f'<ul class="theme-grid">{_cards(EDGES, "edge", ACTIVE_EDGE_ID)}</ul>'
        '<button type="button" id="skin-reset">Сбросить к умолчанию</button>'
        "</div></details>"
    )
