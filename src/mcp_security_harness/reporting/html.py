"""HTML report generator for MCP Security Regression Harness."""

from __future__ import annotations

import html as _html
from datetime import UTC, datetime
from pathlib import Path


def generate_html_report(
    results: list[dict],
    out_path: Path | str,
    *,
    provider: str = "unknown",
    model: str = "unknown",
) -> Path:
    """Generate a self-contained HTML security regression report.

    Args:
        results: List of scenario result dicts, each containing:
            - scenario_id (str): Unique scenario identifier
            - result (str): One of pass/fail/error/not_run
            - assertions (list[dict]): Each with id, result, evidence
        out_path: Path to write the HTML file to.
        provider: Provider name for metadata (keyword-only).
        model: Model name for metadata (keyword-only).

    Returns:
        Path to the written HTML file.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(results)

    counts = {"pass": 0, "fail": 0, "error": 0, "not_run": 0}
    for r in results:
        key = r.get("result", "not_run")
        if key in counts:
            counts[key] += 1
        else:
            counts["error"] += 1

    rows_html = _build_rows(results)
    summary_html = _build_summary_cards(counts)

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MCP Security Regression Report</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                   Helvetica, Arial, sans-serif;
      background: #f5f6fa;
      color: #1a1a2e;
      padding: 2rem;
      line-height: 1.5;
    }}
    h1 {{
      font-size: 1.75rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      color: #0d1b2a;
    }}
    .meta {{
      font-size: 0.875rem;
      color: #555;
      margin-bottom: 1.5rem;
    }}
    .meta span {{ margin-right: 1.5rem; }}
    /* Summary cards */
    .summary {{
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
      margin-bottom: 2rem;
    }}
    .card {{
      flex: 1 1 120px;
      border-radius: 8px;
      padding: 1rem 1.25rem;
      color: #fff;
      min-width: 100px;
    }}
    .card-title {{ font-size: .75rem; text-transform: uppercase;
      letter-spacing: .05em; opacity: .85; }}
    .card-count {{ font-size: 2rem; font-weight: 700; margin-top: .25rem; }}
    .card-pass   {{ background: #27ae60; }}
    .card-fail   {{ background: #e74c3c; }}
    .card-error  {{ background: #e67e22; }}
    .card-skip   {{ background: #95a5a6; }}
    /* Table */
    .table-wrap {{
      overflow-x: auto;
      background: #fff;
      border-radius: 8px;
      box-shadow: 0 1px 4px rgba(0,0,0,.08);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }}
    th {{
      text-align: left;
      padding: .75rem 1rem;
      background: #0d1b2a;
      color: #fff;
      font-weight: 600;
      white-space: nowrap;
    }}
    td {{
      padding: .75rem 1rem;
      border-bottom: 1px solid #eef0f5;
      vertical-align: top;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tr:nth-child(even) td {{ background: #fafbfd; }}
    /* Badges */
    .badge {{
      display: inline-block;
      padding: .2em .65em;
      border-radius: 4px;
      font-size: .8rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: .04em;
    }}
    .badge-pass   {{ background: #d5f5e3; color: #1e8449; }}
    .badge-fail   {{ background: #fadbd8; color: #922b21; }}
    .badge-error  {{ background: #fdebd0; color: #a04000; }}
    .badge-not_run{{ background: #eaecee; color: #555; }}
    /* Assertions */
    .assertions {{ list-style: none; }}
    .assertions li {{ margin-bottom: .4rem; font-size: .82rem; }}
    .assert-id {{ font-family: monospace; color: #34495e; }}
    .assert-evidence {{ color: #777; font-style: italic; }}
  </style>
</head>
<body>
  <h1>MCP Security Regression Report</h1>
  <p class="meta">
    <span><strong>Timestamp:</strong> {_e(timestamp)}</span>
    <span><strong>Provider:</strong> {_e(provider)}</span>
    <span><strong>Model:</strong> {_e(model)}</span>
    <span><strong>Total Scenarios:</strong> {total}</span>
  </p>

  <div class="summary">
    {summary_html}
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Scenario</th>
          <th>Result</th>
          <th>Assertions</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>
</body>
</html>"""

    out_path.write_text(page, encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _e(text: str) -> str:
    """HTML-escape a string."""
    return _html.escape(str(text))


def _badge(result: str) -> str:
    safe_result = result if result in ("pass", "fail", "error", "not_run") else "error"
    label = result.replace("_", " ")
    return f'<span class="badge badge-{safe_result}">{_e(label)}</span>'


def _build_summary_cards(counts: dict) -> str:
    cards = [
        ("pass",    "Pass",  counts["pass"],    "card-pass"),
        ("fail",    "Fail",  counts["fail"],    "card-fail"),
        ("error",   "Error", counts["error"],   "card-error"),
        ("not_run", "Skip",  counts["not_run"], "card-skip"),
    ]
    parts = []
    for _, label, count, cls in cards:
        parts.append(
            f'<div class="card {cls}">'
            f'<div class="card-title">{label}</div>'
            f'<div class="card-count">{count}</div>'
            f"</div>"
        )
    return "\n    ".join(parts)


def _build_rows(results: list[dict]) -> str:
    if not results:
        return (
            '<tr><td colspan="3" style="text-align:center;color:#999;">'
            "No scenarios recorded.</td></tr>"
        )

    rows = []
    for r in results:
        scenario_id = r.get("scenario_id", "")
        result = r.get("result", "not_run")
        assertions = r.get("assertions", [])

        assertion_html = _build_assertions(assertions)

        rows.append(
            f"<tr>"
            f'<td><code>{_e(scenario_id)}</code></td>'
            f"<td>{_badge(result)}</td>"
            f"<td>{assertion_html}</td>"
            f"</tr>"
        )
    return "\n        ".join(rows)


def _build_assertions(assertions: list[dict]) -> str:
    if not assertions:
        return '<span style="color:#bbb;">—</span>'

    items = []
    for a in assertions:
        a_id = a.get("id", "")
        a_result = a.get("result", "")
        evidence = a.get("evidence", "")

        safe_result = a_result if a_result in ("pass", "fail", "error", "not_run") else "error"
        items.append(
            f'<li>'
            f'<span class="assert-id">{_e(a_id)}</span> '
            f'<span class="badge badge-{safe_result}"'
            f' style="font-size:.7rem;">{_e(a_result)}</span>'
            + (f' <span class="assert-evidence">{_e(str(evidence))}</span>' if evidence else "")
            + "</li>"
        )
    return f'<ul class="assertions">{"".join(items)}</ul>'
