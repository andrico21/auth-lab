
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[1]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Preserve the rejected03-literal attempt; correct only unsiged binding metadata to valid zz wire02."""
import datetime
import hashlib
import json
import pathlib
import sys
import urllib.error
import urllib.request
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import reference_bytes as v
ROOT=v.ROOT; OUT=v.OUT/'post-freeze-contract-errata'
source=OUT/'resolution-fixtures.json'; raw=source.read_bytes()
expected=generated_hash('post-freeze-contract-errata/resolution-fixtures.json')
if hashlib.sha256(raw).hexdigest()!=expected:
    raise RuntimeError('Failed candidate changed; preserve its exact bytes')
f=json.loads(raw)
if f['zzBinding']['canonicalOwnerWireHex']!='037a7a036c6162076578616d706c6500':
    raise RuntimeError('Initial failed literal is not the retained one')
actual=v.name_wire('zz.lab.example.').hex()
if actual!='027a7a036c6162076578616d706c6500':
    raise RuntimeError('Exact zz name wire differs')
# The current replay applies the already established correction, not a fictional failed run.
primary=OUT/'sources/rfc1035.txt'; primary.parent.mkdir(exist_ok=True)
from current_profile import HISTORICAL
primary.write_bytes((HISTORICAL/'post-freeze-contract-errata/sources/rfc1035.txt').read_bytes())
f['kind']='dnssec-resolution-post-freeze-audit-fixtures-owner-wire-corrected'
f['zzBinding']['canonicalOwnerWireHex']=actual
f['ownerWireCorrection']={'sourceCandidate':reference_path(source),'sourceCandidateSha256':expected,
 'incorrectRequestedLiteralWithdrawn':'037a7a036c6162076578616d706c6500','correctLiteral':actual,
 'reason':'RFC1035 section3.1: zz has2octets, not3; established metadata correction replayed offline.',
 'signedRrsetsUnchanged':True,'signedSignaturesUnchanged':True,'keyClockOwnerAndTtlsUnchanged':True,'source':'sources/rfc1035.txt'}
original=json.loads(raw)
if f['rrsets']!=original['rrsets'] or f['signatures']!=original['signatures']:
    raise RuntimeError('Correction must not change any RRset or signature')
result=(json.dumps(f,indent=2,sort_keys=True)+'\n').encode(); path=OUT/'resolution-fixtures-owner-wire-corrected.json'
if path.exists() and path.read_bytes()!=result:
    raise RuntimeError('Existing corrected fixture differs')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({'path':reference_path(path),'bytes':len(result),'sha256':hashlib.sha256(result).hexdigest(),'canonicalZzOwnerWireHex':actual,'retainedFailedCandidateSha256':expected,'signedObjectsUnchanged':True},indent=2))
