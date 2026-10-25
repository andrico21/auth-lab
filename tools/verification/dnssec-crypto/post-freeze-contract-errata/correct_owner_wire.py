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
expected='a0cd8ae6dc5c919a7df8fc5c9d9a39e9c05c28de87441b6120e473ec5e5a8641'
if hashlib.sha256(raw).hexdigest()!=expected:
    raise RuntimeError('Failed candidate changed; preserve its exact bytes')
f=json.loads(raw)
if f['zzBinding']['canonicalOwnerWireHex']!='037a7a036c6162076578616d706c6500':
    raise RuntimeError('Initial failed literal is not the retained one')
actual=v.name_wire('zz.lab.example.').hex()
if actual!='027a7a036c6162076578616d706c6500':
    raise RuntimeError('Exact zz name wire differs')
# Capture the actual first verifier source before applying its accepted literal correction.
verifier=pathlib.Path(__file__).resolve().parent/'verify.py'
snapshot=OUT/'attempts/verify-owner-wire-03-first-attempt.py.txt'
snapshot.parent.mkdir(exist_ok=True)
verifier_bytes=verifier.read_bytes()
if snapshot.exists() and snapshot.read_bytes()!=verifier_bytes:
    raise RuntimeError('First-attempt verifier snapshot differs')
if not snapshot.exists():
    snapshot.write_bytes(verifier_bytes)
# Capture the primary label-length definition without overwriting any frozen source ledger.
primary=OUT/'sources/rfc1035.txt'; primary.parent.mkdir(exist_ok=True)
metadata_path=OUT/'sources/rfc1035-capture.json'
if not primary.exists():
    meta={'url':'https://www.rfc-editor.org/rfc/rfc1035.txt','capturedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'producer':'tools/verification/dnssec-crypto/post-freeze-contract-errata/correct_owner_wire.py'}
    try:
        with urllib.request.urlopen(meta['url'],timeout=60) as response:
            data=response.read(); meta.update(status=response.status,finalUrl=response.url,headers=dict(response.headers))
    except urllib.error.HTTPError as error:
        data=error.read(); meta.update(status=error.code,error=str(error))
    except Exception as error:
        meta.update(status=None,error=repr(error)); metadata_path.write_text(json.dumps(meta,indent=2)+'\n'); raise
    primary.write_bytes(data); meta.update(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    metadata_path.write_text(json.dumps(meta,indent=2)+'\n')
    if meta['status']!=200:
        raise RuntimeError('Primary source capture failed; failure retained')
f['kind']='dnssec-resolution-post-freeze-audit-fixtures-owner-wire-corrected'
f['zzBinding']['canonicalOwnerWireHex']=actual
f['ownerWireCorrection']={'sourceFailedCandidate':str(source.relative_to(ROOT)),'sourceFailedCandidateSha256':expected,
 'failedAttempt':'runs/run-002.json','incorrectRequestedLiteralWithdrawn':'037a7a036c6162076578616d706c6500','correctLiteral':'027a7a036c6162076578616d706c6500',
 'reason':'RFC1035 section3.1: each label starts with its octet length; zz has2octets, not3. The auditor withdrew03 and accepted02. Actual originally produced RRset/signature already covered02.',
 'signedRrsetsUnchanged':True,'signedSignaturesUnchanged':True,'keyClockOwnerAndTtlsUnchanged':True,'source':'sources/rfc1035.txt','firstAttemptVerifierSnapshot':str(snapshot.relative_to(ROOT)),'firstAttemptVerifierSha256':hashlib.sha256(verifier_bytes).hexdigest()}
original=json.loads(raw)
if f['rrsets']!=original['rrsets'] or f['signatures']!=original['signatures']:
    raise RuntimeError('Correction must not change any RRset or signature')
result=(json.dumps(f,indent=2,sort_keys=True)+'\n').encode(); path=OUT/'resolution-fixtures-owner-wire-corrected.json'
if path.exists() and path.read_bytes()!=result:
    raise RuntimeError('Existing corrected fixture differs')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({'path':str(path.relative_to(ROOT)),'bytes':len(result),'sha256':hashlib.sha256(result).hexdigest(),'canonicalZzOwnerWireHex':actual,'retainedFailedCandidateSha256':expected,'firstAttemptVerifierSha256':hashlib.sha256(verifier_bytes).hexdigest(),'signedObjectsUnchanged':True},indent=2))
