#!/usr/bin/env python3
"""Execute only an explicitly named DNS19 numeric program; retain all run outputs."""
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[5]
HERE = pathlib.Path(__file__).resolve().parent
OUT = ROOT / 'docs/dnssec-expansion/numeric/post-freeze-completion/dns19'
OUT.mkdir(parents=True, exist_ok=True)
name = sys.argv[1]
if name not in ['produce.py', 'verify.py']:
    raise ValueError('Only independent DNS19 producer/verifier execution is permitted')
program = HERE / name
raw = program.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
snapshots = OUT / 'attempts'
snapshots.mkdir(exist_ok=True)
snapshot = snapshots / (program.stem + '-' + digest + '.py')
if not snapshot.exists():
    snapshot.write_bytes(raw)
command = [str(pathlib.Path(sys.executable).relative_to(ROOT)), str(program.relative_to(ROOT))]
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
row = {'schemaVersion': 1, 'kind': 'dns19-actual-command-capture', 'startedAt': started,
       'command': command, 'cwd': str(ROOT), 'programSha256': digest, 'programBytes': len(raw),
       'programSnapshot': str(snapshot.relative_to(ROOT)), 'exitCode': result.returncode,
       'stdout': result.stdout, 'stderr': result.stderr,
       'finishedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}
runs = OUT / 'runs'
runs.mkdir(exist_ok=True)
index = len(list(runs.glob('run-*.json'))) + 1
path = runs / ('run-' + str(index).zfill(3) + '.json')
with path.open('x') as output:
    json.dump(row, output, indent=2, sort_keys=True)
    output.write('\n')
print(json.dumps({'capture': str(path.relative_to(ROOT)), 'exitCode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}))
sys.exit(result.returncode)
