import html
import json
import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from pacu.core.lib import downloads_dir

if TYPE_CHECKING:
    from pacu.core.models import PacuSession


def generate_report(session: 'PacuSession') -> Path:
    """Generate a self-contained HTML report for the active Pacu session.

    Queries session data via SQLAlchemy and writes the report into
    the session's downloads directory.
    """
    aws_data = session.get_all_aws_data_fields_as_dict()
    keys = _get_keys_summary(session)
    timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')
    out_path = downloads_dir() / f'report_{session.name}_{timestamp}.html'
    out_path.write_text(_build_html(session, keys, aws_data), encoding='utf-8')
    return out_path


def _get_keys_summary(session: 'PacuSession') -> list:
    return [
        {
            'KeyAlias': k.key_alias or '',
            'AccessKeyId': _redact(k.access_key_id),
            'UserName': k.user_name or '',
            'Arn': k.arn or '',
            'AccountId': k.account_id or '',
        }
        for k in session.aws_keys.all()
    ]


def _redact(val) -> str:
    if not val or len(val) < 8:
        return '***'
    return val[:4] + '***' + val[-4:]


def _e(text) -> str:
    return html.escape(str(text))


def _build_html(session: 'PacuSession', keys: list, aws_data: dict) -> str:
    now = datetime.datetime.utcnow().isoformat()
    rows_keys = ''.join(
        f'<tr><td>{_e(k["KeyAlias"])}</td><td>{_e(k["AccessKeyId"])}</td>'
        f'<td>{_e(k["UserName"])}</td><td>{_e(k["Arn"])}</td>'
        f'<td>{_e(k["AccountId"])}</td></tr>'
        for k in keys
    ) or '<tr><td colspan="5">No keys configured</td></tr>'

    sections_data = ''
    for svc, data in sorted(aws_data.items()) if aws_data else []:
        sections_data += (
            f'<h3>{_e(svc)}</h3>'
            f'<pre>{_e(json.dumps(data, indent=2, default=str))}</pre>'
        )
    if not sections_data:
        sections_data = '<p>No enumerated data in this session.</p>'

    return f'''<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Pacu Report - {_e(session.name)}</title>
<style>
body{{font-family:monospace;margin:2em;background:#1a1a2e;color:#e0e0e0}}
h1,h2,h3{{color:#00d4ff}}
table{{border-collapse:collapse;width:100%;margin-bottom:1.5em}}
th,td{{border:1px solid #333;padding:6px 10px;text-align:left}}
th{{background:#16213e}}
pre{{background:#0f3460;padding:1em;overflow-x:auto;border-radius:4px}}
.warn{{color:#ff6b6b;font-size:0.85em}}
</style></head><body>
<h1>Pacu Session Report: {_e(session.name)}</h1>
<p>Generated: {_e(now)} UTC</p>
<p>Session created: {_e(str(session.created))}</p>
<p class="warn">This report may contain sensitive AWS data. Handle accordingly.</p>
<h2>AWS Keys</h2>
<table><tr><th>Alias</th><th>Access Key</th><th>User</th><th>ARN</th><th>Account</th></tr>
{rows_keys}</table>
<h2>Enumerated AWS Data</h2>
{sections_data}
</body></html>'''
