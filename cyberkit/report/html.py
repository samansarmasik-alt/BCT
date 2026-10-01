"""Self-contained HTML report writer.

Everything (CSS, no JS) is inlined so a report can be mailed, archived, or
attached to a ticket as a single file with no external dependencies.
"""

from __future__ import annotations

import html
from pathlib import Path

from ..core.models import Finding, Host, Result, severity_rank, to_json

_SEVERITIES = ("critical", "high", "medium", "low", "info")

_CSS = """
:root{--bg:#0d1117;--panel:#161b22;--line:#272e38;--text:#e6edf3;--muted:#8b949e;
--accent:#2f81f7;--critical:#f85149;--high:#ff7b72;--medium:#d29922;--low:#3fb950;--info:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.55 ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif}
header{padding:28px 32px;border-bottom:1px solid var(--line);
background:linear-gradient(180deg,#161b22,#0d1117)}
h1{margin:0 0 6px;font-size:22px;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:13px}
main{padding:24px 32px;max-width:1180px;margin:0 auto}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:24px}
.card{flex:1 1 140px;background:var(--panel);border:1px solid var(--line);
border-radius:10px;padding:14px 16px}
.card .n{font-size:24px;font-weight:600}
.card .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
margin:28px 0 12px}
table{width:100%;border-collapse:collapse;background:var(--panel);
border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em;font-weight:600}
tr:last-child td{border-bottom:none}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;
font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.badge.critical{background:rgba(248,81,73,.15);color:var(--critical)}
.badge.high{background:rgba(255,123,114,.15);color:var(--high)}
.badge.medium{background:rgba(210,153,34,.15);color:var(--medium)}
.badge.low{background:rgba(63,185,80,.15);color:var(--low)}
.badge.info{background:rgba(88,166,255,.15);color:var(--info)}
.host{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:16px 18px;margin-bottom:14px}
.host h3{margin:0 0 10px;font-size:15px}
.muted{color:var(--muted)}
.detail{color:var(--muted);font-size:12.5px;margin-top:3px}
.fix{margin-top:6px;font-size:12.5px;color:#a5d6ff}
.errors{border-left:3px solid var(--critical);padding:8px 12px;background:var(--panel);
border-radius:0 8px 8px 0;margin-bottom:8px}
footer{padding:20px 32px;color:var(--muted);font-size:12px;border-top:1px solid var(--line)}
"""

_JS = """
(function(){
  var box=document.getElementById('sev-filter');
  if(!box)return;
  box.addEventListener('change',function(){
    var allowed=[];
    document.querySelectorAll('input[name=sev]:checked').forEach(function(i){allowed.push(i.value)});
    document.querySelectorAll('[data-sev]').forEach(function(row){
      row.style.display=allowed.indexOf(row.dataset.sev)===-1?'none':'';
    });
  });
})();
"""


def write_html(result: Result, path: str | Path, *, title: str = "CyberKit report") -> Path:
    """Render ``result`` into a single offline HTML file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result, title=title), encoding="utf-8")
    return path


def render_html(result: Result, *, title: str = "CyberKit report") -> str:
    payload = result.to_dict()
    findings = result.findings
    counts = result.counts()
    duration = payload["duration"]

    parts: list[str] = [
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head><body>",
        "<header><h1>CyberKit assessment report</h1>",
        f"<div class=\"sub\">Modules: {html.escape(', '.join(result.modules) or '-')} "
        f"&middot; {duration}s &middot; {len(result.hosts)} host(s) "
        f"&middot; {len(findings)} finding(s)</div></header>",
        "<main>",
        _cards(result, counts),
    ]

    if findings:
        parts.append('<h2>Findings</h2>')
        parts.append(_filter_ui(counts))
        parts.append(_findings_table(findings))
    else:
        parts.append('<h2>Findings</h2><p class="muted">No findings recorded.</p>')

    parts.append("<h2>Hosts</h2>")
    parts.extend(_host_block(host) for host in result.hosts)

    if result.notes:
        parts.append("<h2>Scope notes</h2>")
        parts.extend(f'<p class="muted">{html.escape(note)}</p>' for note in result.notes)
    if result.errors:
        parts.append("<h2>Errors</h2>")
        parts.extend(f'<div class="errors">{html.escape(err)}</div>' for err in result.errors)

    parts.append(
        "<h2>Raw data</h2><details><summary class=\"muted\">Embedded JSON</summary>"
        f"<pre><code>{html.escape(to_json(payload))}</code></pre></details>"
    )
    parts.append("</main><footer>Generated locally by CyberKit. "
                 "Use only against systems you are authorized to test.</footer>")
    parts.append(f"<script>{_JS}</script></body></html>")
    return "".join(parts)


def _cards(result: Result, counts: dict[str, int]) -> str:
    open_ports = sum(len(h.open_ports) for h in result.hosts)
    cards = [
        ("Hosts", len(result.hosts)),
        ("Open ports", open_ports),
        ("Findings", len(result.findings)),
    ]
    cards += [(sev.capitalize(), counts.get(sev, 0)) for sev in _SEVERITIES if counts.get(sev)]
    inner = "".join(
        f'<div class="card"><div class="n">{value}</div><div class="k">{html.escape(key)}</div></div>'
        for key, value in cards
    )
    return f'<div class="cards">{inner}</div>'


def _filter_ui(counts: dict[str, int]) -> str:
    boxes = "".join(
        f'<label style="margin-right:12px;font-size:12.5px">'
        f'<input type="checkbox" name="sev" value="{sev}" checked> {sev}</label>'
        for sev in _SEVERITIES
        if counts.get(sev)
    )
    return f'<div style="margin-bottom:10px">{boxes}</div><div id="sev-filter" hidden></div>'


def _findings_table(findings: list[Finding]) -> str:
    rows = []
    for finding in sorted(findings, key=lambda f: severity_rank(f.severity), reverse=True):
        rows.append(
            f'<tr data-sev="{html.escape(finding.severity)}">'
            f'<td><span class="badge {html.escape(finding.severity)}">'
            f'{html.escape(finding.severity)}</span></td>'
            f"<td>{html.escape(finding.title)}"
            + (f'<div class="detail">{html.escape(finding.detail)}</div>' if finding.detail else "")
            + (f'<div class="fix">Fix: {html.escape(finding.remediation)}</div>' if finding.remediation else "")
            + "</td>"
            f"<td><code>{html.escape(finding.target or '-')}</code></td>"
            f"<td class=\"muted\">{html.escape(finding.module)}</td></tr>"
        )
    head = "<tr><th>Severity</th><th>Finding</th><th>Target</th><th>Module</th></tr>"
    return f"<table>{head}{''.join(rows)}</table>"


def _host_block(host: Host) -> str:
    rows = "".join(
        f"<tr><td>{service.port}</td><td>{html.escape(service.service or '-')}</td>"
        f"<td>{html.escape(service.product or '-')}</td>"
        f"<td class=\"muted\"><code>{html.escape(service.banner or '-')[:160]}</code></td></tr>"
        for service in sorted(host.services, key=lambda s: s.port)
    )
    table = (
        "<table><tr><th>Port</th><th>Service</th><th>Product</th><th>Banner</th></tr>"
        f"{rows}</table>"
        if rows
        else '<p class="muted">No open services recorded.</p>'
    )
    names = (
        f'<p class="muted">Names: {html.escape(", ".join(host.hostnames))}</p>'
        if host.hostnames
        else ""
    )
    notes = "".join(f'<p class="muted">{html.escape(n)}</p>' for n in host.notes)
    return (
        f'<div class="host"><h3>{html.escape(host.target)} '
        f'<span class="muted">{html.escape(", ".join(host.addresses))}</span></h3>'
        f"{names}{table}{notes}</div>"
    )
