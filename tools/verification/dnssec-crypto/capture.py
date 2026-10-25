#!/usr/bin/env python3
"""Capture primary references and pinned offline dependencies; never overwrite raw bytes."""
import datetime
import hashlib
import json
import pathlib
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[3]
OUT = ROOT / 'docs/dnssec-expansion/numeric'
OUT.mkdir(parents=True, exist_ok=True)
LEDGER = OUT / 'capture-ledger.json'
rows = json.loads(LEDGER.read_text()) if LEDGER.exists() else []

def fetch(url, relative):
    path = OUT / relative
    if path.exists():
        return path.read_bytes()
    row = {'url': url, 'path': relative, 'capturedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'producer': 'python3 tools/verification/dnssec-crypto/capture.py'}
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
            row.update(status=response.status, finalUrl=response.url, headers=dict(response.headers))
    except urllib.error.HTTPError as error:
        data = error.read()
        row.update(status=error.code, error=str(error))
    except Exception as error:
        row.update(status=None, error=repr(error))
        rows.append(row)
        LEDGER.write_text(json.dumps(rows, indent=2) + '\n')
        raise
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    row.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    rows.append(row)
    LEDGER.write_text(json.dumps(rows, indent=2) + '\n')
    if row['status'] != 200:
        raise RuntimeError(row)
    return data

for number in (6605, 8080, 4509, 4034, 4035, 5155, 1982, 5011, 9276, 6840, 8945, 8976, 7344, 8078, 9824, 9859, 7477, 6672):
    fetch(f'https://www.rfc-editor.org/rfc/rfc{number}.txt', f'sources/rfc{number}.txt')
fetch('https://www.rfc-editor.org/errata/rfc8080', 'sources/rfc8080-errata.html')
fetch('https://errata.rfc-editor.org/search/?rfc_number=8078&presentation=records', 'sources/rfc8078-errata.html')
for name, version in [('dnspython', '2.8.0'), ('cryptography', '46.0.3'), ('cffi', '2.1.1'), ('pycparser', '3.12')]:
    meta = json.loads(fetch(f'https://pypi.org/pypi/{name}/{version}/json', f'dependencies/{name}-{version}.json'))
    for item in meta['urls']:
        file = item['filename']
        wheel = file.endswith('py3-none-any.whl') or (name == 'cryptography' and 'cp311-abi3-manylinux_2_34_x86_64' in file) or (name == 'cffi' and 'cp314-cp314-manylinux2014_x86_64' in file)
        if item['packagetype'] == 'sdist' or wheel:
            data = fetch(item['url'], f'dependencies/{file}')
            assert hashlib.sha256(data).hexdigest() == item['digests']['sha256']
print(json.dumps({'captures': len(rows), 'bytes': sum(r.get('bytes', 0) for r in rows), 'failures': [r for r in rows if r['status'] != 200]}, indent=2))
