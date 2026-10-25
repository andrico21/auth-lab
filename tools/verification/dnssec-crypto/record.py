#!/usr/bin/env python3
"""Record exact argv/stdout/stderr/status, retaining every attempt."""
import datetime
import json
import pathlib
import subprocess
import sys
ROOT=pathlib.Path(__file__).resolve().parents[3]
OUT=ROOT/'docs/dnssec-expansion/numeric/runs'
OUT.mkdir(parents=True,exist_ok=True)
number=len(list(OUT.glob('run-*.json')))+1
result=subprocess.run(sys.argv[1:],cwd=ROOT,text=True,capture_output=True)
row={'schemaVersion':1,'argv':sys.argv[1:],'cwd':str(ROOT),'capturedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exitCode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
path=OUT/f'run-{number:03d}.json'
path.write_text(json.dumps(row,indent=2)+'\n')
print(result.stdout,end='')
print(result.stderr,end='',file=sys.stderr)
print('Captured '+str(path.relative_to(ROOT)))
sys.exit(result.returncode)
