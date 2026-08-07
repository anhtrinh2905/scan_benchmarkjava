"""Chart specs for a `report_query.QueryResult` (v1.8 increment).

Library-style seam like the rest of `src/`: no Streamlit, no I/O, no network. Every
function is a pure map from a `QueryResult` to an Altair chart, so a chart can be built
and asserted on in a test (`chart.to_dict()`) without a browser or a running app.

Altair is not a new dependency — Streamlit already ships it, and `st.altair_chart` is the
supported way to render one. Nothing was added to `pyproject.toml` for this module.

Two rules, both inherited from DESIGN.md rather than invented here:

* **Colour is reinforcement, never the information.** Every bar is labelled with its
  category and its count in text; the severity tint repeats what the axis already says.
  The chart survives greyscale and colourblindness, exactly like the outcome table.
* **The chart draws the table, and only the table.** It never re-aggregates, re-sorts by a
  hidden key, or filters. If the number on the bar disagrees with the number in the table
  below it, that is a bug in this file, not a judgement call.
"""
from __future__ import annotations

from typing import Any

import altair as alt
import pandas as pd

from report_query import CONFIDENCE_ORDER, SEVERITY_ORDER, QueryResult

# The severity scale from DESIGN.md (2026-08-06), the same five values `app.py` badges
# with. Kept as a plain dict so a missing level degrades to the default scheme instead of
# raising while rendering.
SEVERITY_COLORS = {
    "critical": "#991B1B",
    "high": "#C2410C",
    "medium": "#A16207",
    "low": "#0369A1",
    "info": "#52525B",
}
CONFIDENCE_COLORS = {
    "high": "#065F46",
    "medium": "#A16207",
    "low": "#9A3412",
}
# One neutral for every nominal dimension (CWE, OWASP, file, tool). Distinct hues there
# would encode nothing — the category is already on the axis.
NEUTRAL = "#3B5BA5"

# Above this many rows a vertical bar chart's labels collide, so the orientation flips.
HORIZONTAL_THRESHOLD = 6
# Cap on rows drawn. `top_files` already limits upstream; this guards a `count_by cwe`
# that returns 25 categories from painting an unreadable chart.
MAX_BARS = 20

CHART_HEIGHT = 260
ROW_HEIGHT = 26

# Operations whose table is a count series and therefore chartable. `overview` is a list of
# mixed-type facts and `lookup` is one record — neither is a distribution, and forcing a
# chart onto them would be decoration, not information.
CHARTABLE_OPS = ("count_by", "top_files", "kb_coverage")


def _color_for(result: QueryResult) -> tuple[str, dict[str, str] | None]:
    """`(default_color, per_label_palette_or_None)`."""
    if result.op == "count_by" and result.dimension == "severity":
        return NEUTRAL, SEVERITY_COLORS
    if result.op == "count_by" and result.dimension == "confidence":
        return NEUTRAL, CONFIDENCE_COLORS
    return NEUTRAL, None


def _short_label(label: str) -> str:
    """File paths and OWASP doc ids are too long for an axis. The tail is the identifying
    part of both (`.../BenchmarkTest00023.java`, `owasp-top10/A03-injection`), so trimming
    from the left keeps what distinguishes one row from another."""
    if "/" in label and len(label) > 34:
        return "…/" + label.rsplit("/", 1)[-1]
    return label


def is_chartable(result: QueryResult) -> bool:
    """True when the result is a count distribution with at least one non-zero row. A
    chart of all zeroes is an empty rectangle, and an empty rectangle reads as a rendering
    failure rather than as 'nothing matched'."""
    if result.op not in CHARTABLE_OPS:
        return False
    if not result.table:
        return False
    return any(row.get("count", 0) for row in result.table)


def chart_frame(result: QueryResult) -> pd.DataFrame:
    """The rows the chart will draw, trimmed and labelled. Separate from `chart_for` so a
    test can assert on the data without touching Altair's spec format."""
    rows: list[dict[str, Any]] = [
        {
            "label": str(row["label"]),
            "short": _short_label(str(row["label"])),
            "count": int(row.get("count", 0)),
        }
        for row in result.table[:MAX_BARS]
    ]
    return pd.DataFrame(rows, columns=["label", "short", "count"])


def chart_for(result: QueryResult) -> alt.Chart | None:
    """The one entry point. Returns `None` for anything not a count distribution — the
    caller renders the table alone rather than a placeholder."""
    if not is_chartable(result):
        return None

    frame = chart_frame(result)
    default_color, palette = _color_for(result)
    horizontal = result.op == "top_files" or len(frame) > HORIZONTAL_THRESHOLD

    if palette:
        # Ordinal dimensions keep their scale order on the axis AND in the legend, so the
        # bars read critical → info left to right, not alphabetically.
        scale_order = SEVERITY_ORDER if result.dimension == "severity" else CONFIDENCE_ORDER
        domain = [level for level in scale_order if level in set(frame["label"])]
        color = alt.Color(
            "label:N",
            scale=alt.Scale(domain=domain, range=[palette[level] for level in domain]),
            legend=None,
        )
        category_sort: Any = list(domain)
    else:
        color = alt.value(default_color)
        # Already sorted by the query layer; `None` tells Altair to preserve that order
        # rather than re-sorting alphabetically behind the table's back.
        category_sort = None

    tooltip = [
        alt.Tooltip("label:N", title="Giá trị"),
        alt.Tooltip("count:Q", title="Số phát hiện"),
    ]

    if horizontal:
        base = alt.Chart(frame).mark_bar(cornerRadiusEnd=3).encode(
            y=alt.Y("short:N", sort=category_sort, title=None,
                    axis=alt.Axis(labelLimit=320)),
            x=alt.X("count:Q", title="Số phát hiện", axis=alt.Axis(format="d", tickMinStep=1)),
            color=color,
            tooltip=tooltip,
        )
        text = base.mark_text(align="left", dx=4, fontSize=11).encode(
            text=alt.Text("count:Q", format="d"), color=alt.value("#3F3F46")
        )
        height = max(CHART_HEIGHT, ROW_HEIGHT * len(frame))
    else:
        base = alt.Chart(frame).mark_bar(cornerRadiusEnd=3).encode(
            x=alt.X("short:N", sort=category_sort, title=None,
                    axis=alt.Axis(labelAngle=0)),
            y=alt.Y("count:Q", title="Số phát hiện", axis=alt.Axis(format="d", tickMinStep=1)),
            color=color,
            tooltip=tooltip,
        )
        text = base.mark_text(align="center", dy=-8, fontSize=11).encode(
            text=alt.Text("count:Q", format="d"), color=alt.value("#3F3F46")
        )
        height = CHART_HEIGHT

    # The count is printed on every bar (`text`), which is what makes the tint redundant
    # and therefore safe.
    return (base + text).properties(height=height).configure_view(strokeWidth=0)


# --- the fixed dashboard set ------------------------------------------------------

# Six panels, declared once. Closed on purpose: the model-driven chat can pick which of
# these to show, but it cannot invent a seventh, so every chart on screen is one somebody
# reviewed. `(title, op, dimension, help_text)`.
DASHBOARD_PANELS: tuple[tuple[str, str, str | None, str], ...] = (
    ("Mức độ nghiêm trọng", "count_by", "severity",
     "Mức cuối cùng sau khi Python kẹp đề xuất của mô hình trong ±1 bậc so với mức công cụ báo."),
    ("Nhóm OWASP Top 10", "count_by", "owasp",
     "Lấy từ tài liệu OWASP có điểm cao nhất trong các tài liệu KB được truy hồi cho nhóm."),
    ("Loại lỗi (CWE)", "count_by", "cwe",
     "CWE do công cụ quét báo, không phải do mô hình suy ra."),
    ("Tệp bị ảnh hưởng nhiều nhất", "top_files", None,
     "Xếp theo số phát hiện khác nhau chạm vào tệp, không phải số lần xuất hiện."),
    ("Độ tin cậy", "count_by", "confidence",
     "Do Python quyết định: mô hình chỉ đề xuất, và độ tin cậy bị ép sàn khi bằng chứng mỏng."),
    ("Độ phủ kho tri thức", "kb_coverage", None,
     "Số phát hiện trích dẫn được ít nhất một tài liệu KB — đo độ phủ của KB, không đo chất lượng phân tích."),
)
