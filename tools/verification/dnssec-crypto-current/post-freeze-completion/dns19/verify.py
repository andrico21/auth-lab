
# Maintained cryptography50 current fork; historical implementation remains immutable.
import sys as _current_sys
from pathlib import Path as _CurrentPath
_current_sys.path.insert(0, str(_CurrentPath(__file__).resolve().parents[2]))
from current_profile import ROOT, TOOLS as CURRENT_TOOLS, HISTORICAL_TOOLS, output_root, reference_path, generated_hash, require_runtime
require_runtime()
#!/usr/bin/env python3
"""Verify DNS19 via independent byte reconstruction, hashlib/HMAC, OpenSSL and fixed-clock dnspython."""
import hashlib
import importlib.metadata
import json
import pathlib
import platform
import struct
import subprocess
import tempfile
import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
import dns.tsig
import dns.zone
import dns.zonetypes
import independent_bytes as independent
ref = independent.ref

ROOT = ROOT
HERE = pathlib.Path(__file__).resolve().parent
NUM = output_root()
OUT = NUM / 'post-freeze-completion/dns19'
BASE = 1792713600
FIXTURE = OUT / 'dns19-fixtures.json'
raw = FIXTURE.read_bytes()
data = json.loads(raw)
checks = []
observations = []


def check(identity, actual, reference):
    if actual != reference:
        raise AssertionError({'id': identity, 'actual': actual, 'reference': reference})
    checks.append({'id': identity, 'result': 'pass'})


def identity(path):
    raw_ = path.read_bytes()
    return {'path': reference_path(path), 'sha256': hashlib.sha256(raw_).hexdigest(), 'bytes': len(raw_)}


check('pre-verification-generated-input-binding', hashlib.sha256(raw).hexdigest(), generated_hash('post-freeze-completion/dns19/dns19-fixtures.json'))
check('fixed-base-clock', data['baseClock'], BASE)
check('freeze-authority-hash', hashlib.sha256((ROOT / 'docs/dnssec-expansion/contract-freeze.json').read_bytes()).hexdigest(), data['freezeAuthoritySha256'])
for item in data['provenance']['inputs'] + data['provenance']['sources'] + [data['provenance']['producer']]:
    actual = identity(ROOT / item['path'])
    check('input-sha256:' + item['path'], actual['sha256'], item['sha256'])
    check('input-bytes:' + item['path'], actual['bytes'], item['bytes'])
versions = {name: importlib.metadata.version(name) for name in ['dnspython', 'cryptography', 'cffi', 'pycparser']}
check('pinned-package-versions', versions, {'dnspython': '2.8.0', 'cryptography': '50.0.0', 'cffi': '2.1.1', 'pycparser': '3.12'})
check('pinned-python-version', platform.python_version(), '3.14.4')

# Reject private/expectation field leakage anywhere in the new active public data.
def inspect_public(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key.startswith('expected') or key in ['fixtureOnlyPrivateHex', 'fixtureOnlySharedSecretHex', 'privateScalar', 'scalarOverride']:
                raise AssertionError('Forbidden public field ' + key)
            inspect_public(child)
    elif isinstance(value, list):
        for child in value:
            inspect_public(child)
    elif isinstance(value, str) and 'PRIVATE KEY-----' in value:
        raise AssertionError('Forbidden private key PEM')
inspect_public(data)
checks.append({'id': 'public-projection-no-private-or-application-expectation-fields', 'result': 'pass'})

# Every RRSIG: independent reconstruction, cryptography and system OpenSSL, then
# separately validate the literal RRset/RRSIG through pinned dnspython at actual fixed clocks.
with tempfile.TemporaryDirectory(prefix='dns19-public-openssl-', dir=OUT) as scratch_dir:
    scratch = pathlib.Path(scratch_dir)
    for sigid, sig in data['signatures'].items():
        rr = data['rrsets'][sig['rrsetId']]
        key = data['dnssecKeys'][sig['keyId']]
        canonical = ref.canonical(rr, sig)
        check(sigid + ':independent-signing-input', canonical.hex(), sig['signingInputHex'])
        check(sigid + ':input-sha256', hashlib.sha256(canonical).hexdigest(), sig['signingInputSha256'])
        check(sigid + ':rrsig-rdata', independent.rdata_text('RRSIG', sig['rrsigText']).hex(), sig['rrsigRdataHex'])
        check(sigid + ':cryptography-signature', ref.valid(key, bytes.fromhex(sig['signatureHex']), canonical), True)
        check(sigid + ':key-tag', ref.key_tag(ref.rdata('DNSKEY', key['text'])), sig['keyTag'])
        observations.append(ref.openssl_check(sigid, key, bytes.fromhex(sig['signatureHex']), canonical, scratch))
        librr = dns.rrset.from_text(rr['owner'], rr['ttl'], 'IN', rr['type'], *rr['records'])
        libsig = dns.rdata.from_text('IN', 'RRSIG', sig['rrsigText'])
        libkeys = {dns.name.from_text(key['owner']): dns.rrset.from_text(key['owner'], 3600, 'IN', 'DNSKEY', key['text'])}
        for now in [BASE + 120, BASE + 300]:
            dns.dnssec.validate_rrsig(librr, libsig, libkeys, now=now)
            check(sigid + ':independent-time:' + str(now), ref.time_state(now, sig['inception'], sig['expiration']), 'valid')
            observations.append({'id': sigid + ':dnspython-fixed-clock', 'now': now, 'result': 'pass'})

for prefix in ['root', 'example', 'child']:
    rr = data['rrsets'][prefix + '-dnskey-g1']
    check(prefix + ':ksk-in-dnskey', data['dnssecKeys'][prefix + '-ksk-g1']['text'] in rr['records'], True)
    check(prefix + ':zsk-in-dnskey', data['dnssecKeys'][prefix + '-zsk-g1']['text'] in rr['records'], True)
for rrid, keyid in [('root-example-ds', 'example-ksk-g1'), ('example-child-ds', 'child-ksk-g1')]:
    key = data['dnssecKeys'][keyid]
    fields = data['rrsets'][rrid]['records'][0].split()
    check(rrid + ':ds-digest', hashlib.sha256(ref.name_wire(key['owner']) + ref.rdata('DNSKEY', key['text'])).hexdigest(), fields[3].lower())
    check(rrid + ':ds-header', list(map(int, fields[:3])), [key['keyTag'], 13, 2])
observations.append({'id': 'synthetic-root-to-child-signature-digest-bindings', 'anchorKeyId': 'root-ksk-g1',
                     'orderedSignatureIds': ['root-dnskey-g1-by-ksk', 'root-example-ds-signature', 'example-dnskey-g1-by-ksk',
                                             'example-child-ds-signature', 'child-dnskey-g1-by-ksk'], 'result': 'pass'})

messages = {}
for mid, row in data['messages'].items():
    wire = bytes.fromhex(row['wireHex'])
    parsed = independent.read_message(wire)
    messages[mid] = parsed
    check(mid + ':unsigned-reconstructed-from-signed-wire', parsed['unsigned'].hex(), row['unsignedWireHex'])
    check(mid + ':message-id', parsed['id'], row['messageId'])
    check(mid + ':tcp-length-prefix', (struct.pack('!H', len(wire)) + wire).hex(), row['tcpFramedWireHex'])
    tsig = parsed['tsig']
    check(mid + ':last-tsig-owner', tsig['owner'], data['keys'][row['keyId']]['keyName'])
    check(mid + ':tsig-class-ttl', [tsig['class'], tsig['ttl']], [255, 0])
    check(mid + ':algorithm', tsig['algorithm'], 'hmac-sha256.')
    check(mid + ':fixed-signed-time', tsig['timeSigned'], BASE)
    check(mid + ':fudge', tsig['fudge'], 300)
    check(mid + ':time48', tsig['timeSigned'].to_bytes(6, 'big').hex(), row['timeSigned48Hex'])
    check(mid + ':original-id', tsig['originalId'], row['originalId'])
    check(mid + ':tsig-start', tsig['start'], row['tsigStart'])
    check(mid + ':tsig-rdata', tsig['rdata'].hex(), row['tsigRdataHex'])
    check(mid + ':transmitted-mac', tsig['mac'].hex(), row['macHex'])
    check(mid + ':error', tsig['error'], row['error'])
    check(mid + ':other', tsig['other'].hex(), row['otherHex'])
    check(mid + ':rcode', parsed['flags'] & 15, row['rcode'])
    if 'answerRecords' in row:
        check(mid + ':wire-decoded-answer-records', parsed['answer'], independent.text_records('\n'.join(row['answerRecords'])))

# Derive response requestMAC/priorMAC from actual received message order, not tuple hints.
bindings = {}
for sid, stream in data['streams'].items():
    request = stream['requestMessageId']
    bindings[request] = (b'', b'')
    request_mac = messages[request]['tsig']['mac']
    prior = b''
    for index, mid in enumerate(stream['responseMessageIds']):
        bindings[mid] = (request_mac if index == 0 else b'', prior)
        check(mid + ':response-id-bound-to-request', messages[mid]['id'], messages[request]['id'])
        check(mid + ':question-bound-to-request', messages[mid]['questions'], messages[request]['questions'])
        prior = messages[mid]['tsig']['mac']
    requested = stream['requestedSerial']
    if requested is not None:
        check(sid + ':IXFR-authority-SOA', independent.soa_serial(messages[request]['authority'][0]), requested)
for uid, update in data['updates'].items():
    request = update['requestMessageId']
    response = update['responseMessageId']
    bindings[request] = (b'', b'')
    bindings[response] = (messages[request]['tsig']['mac'], b'') if uid != 'mutatedRetainedMac' else (b'', b'')
check('every-message-has-wire-derived-chain-binding', set(bindings), set(messages))
tuples = {row['id']: row for row in data['macReferenceTuples']}
check('positive-mac-tuple-id-uniqueness', len(tuples), len(data['macReferenceTuples']))
used_tuples = set()
for mid, parsed in messages.items():
    row = data['messages'][mid]
    request_mac, prior_mac = bindings[mid]
    check(mid + ':request-mac-chain', request_mac.hex(), row['requestMacHex'])
    check(mid + ':prior-mac-chain', prior_mac.hex(), row['priorMacHex'])
    if mid == 'mutatedRetainedMac-response':
        check(mid + ':unsigned-badsig-notauth', [parsed['flags'] & 15, parsed['tsig']['error'], len(parsed['tsig']['mac'])], [9, 16, 0])
        observations.append({'id': mid, 'rcode': 9, 'tsigError': 16, 'macSize': 0, 'source': 'RFC8945 5.3.2'})
        continue
    mac_input = independent.mac_input(parsed, request_mac, prior_mac)
    keyname = parsed['tsig']['owner']
    computed = independent.hmac_sha256(keyname, mac_input)
    tuple_ = tuples[row['macReferenceTupleId']]
    used_tuples.add(tuple_['id'])
    check(mid + ':independent-mac-input', mac_input.hex(), tuple_['macInputHex'])
    check(mid + ':positive-hmac-tuple', computed.hex(), tuple_['macHex'])
    check(mid + ':tuple-unsigned-wire', parsed['unsigned'].hex(), tuple_['unsignedWireHex'])
    check(mid + ':tuple-key-fingerprint', hashlib.sha256(independent.hmac_secret(keyname)).hexdigest(), tuple_['keyFingerprint'])
    check(mid + ':key-object-fingerprint', tuple_['keyFingerprint'], data['keys'][row['keyId']]['fingerprint'])
    check(mid + ':tuple-request-mac', request_mac.hex(), tuple_['requestMacHex'])
    check(mid + ':tuple-prior-mac', prior_mac.hex(), tuple_['priorMacHex'])
    if mid == 'mutatedRetainedMac-request':
        if computed == parsed['tsig']['mac']:
            raise AssertionError('Mutated input unexpectedly retains equal HMAC')
        check(mid + ':retained-original-transmitted-mac', parsed['tsig']['mac'], messages['wwwAllowed-request']['tsig']['mac'])
        observations.append({'id': mid + ':actual-hmac-values', 'retainedTransmittedMacHex': parsed['tsig']['mac'].hex(),
                             'recomputedHmacHex': computed.hex(), 'changedOffset': row['changedOffset']})
    else:
        check(mid + ':transmitted-hmac', computed, parsed['tsig']['mac'])
    # Keep the synthetic secret out of public command captures and all errors.
    command = ['openssl', 'dgst', '-sha256', '-mac', 'HMAC', '-macopt', 'hexkey:' + independent.hmac_secret(keyname).hex()]
    result = subprocess.run(command, input=mac_input, capture_output=True)
    if result.returncode:
        raise RuntimeError({'id': mid + ':openssl-hmac', 'exitCode': result.returncode,
                            'stdout': result.stdout.decode(), 'stderr': result.stderr.decode()})
    openssl_mac = result.stdout.decode().strip().split()[-1]
    check(mid + ':openssl-hmac', openssl_mac, computed.hex())
    observations.append({'id': mid + ':openssl-hmac', 'command': command[:-1] + ['hexkey:<privately-regenerated-synthetic-secret>'],
                         'exitCode': result.returncode, 'stdout': result.stdout.decode(), 'stderr': result.stderr.decode()})
check('all-positive-mac-tuples-exercised', used_tuples, set(tuples))

# Separately exercise the real library validator at both required observation times.
for now in [BASE + 120, BASE + 300]:
    done = set()
    for sid, stream in data['streams'].items():
        ids = [stream['requestMessageId']] + stream['responseMessageIds']
        ctx = None
        request_mac = b''
        for index, mid in enumerate(ids):
            row = data['messages'][mid]
            parsed = messages[mid]
            tsig = dns.rdata.from_wire(255, 250, bytes.fromhex(row['tsigRdataHex']), 0, len(bytes.fromhex(row['tsigRdataHex'])))
            keyname = data['keys'][row['keyId']]['keyName']
            key = dns.tsig.Key(keyname, independent.hmac_secret(keyname), algorithm='hmac-sha256.')
            if index == 0:
                dns.tsig.validate(bytes.fromhex(row['wireHex']), key, key.name, tsig, now, b'', row['tsigStart'])
                request_mac = parsed['tsig']['mac']
            else:
                ctx = dns.tsig.validate(bytes.fromhex(row['wireHex']), key, key.name, tsig, now,
                                        request_mac if index == 1 else b'', row['tsigStart'], ctx=ctx, multi=True)
            observations.append({'id': mid + ':dnspython-tsig-fixed-clock', 'now': now, 'result': 'pass'})
            done.add(mid)
    for mid in sorted(set(messages) - done):
        row = data['messages'][mid]
        tsig = dns.rdata.from_wire(255, 250, bytes.fromhex(row['tsigRdataHex']), 0, len(bytes.fromhex(row['tsigRdataHex'])))
        keyname = data['keys'][row['keyId']]['keyName']
        key = dns.tsig.Key(keyname, independent.hmac_secret(keyname), algorithm='hmac-sha256.')
        try:
            dns.tsig.validate(bytes.fromhex(row['wireHex']), key, key.name, tsig, now,
                              bindings[mid][0], row['tsigStart'])
            actual = 'pass'
        except Exception as error:
            actual = type(error).__name__
            observations.append({'id': mid + ':dnspython-tsig-fixed-clock-failure', 'now': now,
                                 'exceptionClass': actual, 'message': str(error)})
        mathematical_case = {'mutatedRetainedMac-request': 'BadSignature', 'mutatedRetainedMac-response': 'PeerBadSignature'}.get(mid, 'pass')
        check(mid + ':library-observation:' + str(now), actual, mathematical_case)
        if actual == 'pass':
            observations.append({'id': mid + ':dnspython-tsig-fixed-clock', 'now': now, 'result': actual})
# Boundary immediately after inclusive fudge300: capture the actual library error.
row = data['messages']['wwwAllowed-request']
key = dns.tsig.Key('update-key.', independent.hmac_secret('update-key.'), algorithm='hmac-sha256.')
tsig = dns.rdata.from_wire(255, 250, bytes.fromhex(row['tsigRdataHex']), 0, len(bytes.fromhex(row['tsigRdataHex'])))
try:
    dns.tsig.validate(bytes.fromhex(row['wireHex']), key, key.name, tsig, BASE + 301, b'', row['tsigStart'])
    observed = 'pass'
except Exception as error:
    observed = type(error).__name__
    observations.append({'id': 'fudge300-plus-one', 'now': BASE + 301, 'exceptionClass': observed, 'message': str(error)})
check('actual-fudge300-plus-one-observation', observed, 'BadTime')

# Stream candidates come only from decoded actual answer wires and explicit base holdings.
for sid, stream in data['streams'].items():
    candidate, application = independent.apply_transfer(stream, messages)
    check(sid + ':received-applied-complete-zone', candidate, set(independent.text_records(stream['resultZoneText'])))
    manifest = []
    for rrid in stream['zoneRrsetIds']:
        rr = data['rrsets'][rrid]
        manifest += [(rr['owner'].lower(), rr['ttl'], 1, rr['typeCode'], ref.rdata(rr['type'], text)) for text in rr['records']]
    for sigid in stream['zoneSignatureIds']:
        sig = data['signatures'][sigid]
        rr = data['rrsets'][sig['rrsetId']]
        manifest.append((rr['owner'].lower(), rr['ttl'], 1, 46, independent.rdata_text('RRSIG', sig['rrsigText'])))
    check(sid + ':complete-zone-manifest', candidate, set(manifest))
    check(sid + ':final-a-records', sorted(record[4].hex() for record in candidate if record[0] == 'www.lab.example.' and record[3] == 1), ['c0000250', 'c0000251'])
    check(sid + ':final-SOA-serial', [independent.soa_serial(r) for r in candidate if r[3] == 6], [2026102302])
    check(sid + ':no-stale-apex-zonemd', [r for r in candidate if r[0] == 'lab.example.' and (r[3] == 63 or (r[3] == 46 and r[4][:2] == b'\x00?'))], [])
    nsecs = {r[0]: r for r in candidate if r[3] == 47}
    chain = ['lab.example.', '*.lab.example.', 'unsigned.lab.example.', 'www.lab.example.']
    check(sid + ':nsec-owner-set', set(nsecs), set(chain))
    for index, owner in enumerate(chain):
        record = nsecs[owner]
        nxt, pos = independent.wire_name(record[4], 0, fold=False)
        check(sid + ':nsec-next:' + owner, nxt, chain[(index + 1) % len(chain)])
        actual_types = sorted({r[3] for r in candidate if r[0] == owner})
        names = [typ for typ, number in ref.TYPES.items() if number in actual_types]
        check(sid + ':nsec-bitmap:' + owner, record[4][pos:], ref.bitmap(names))
        check(sid + ':nsec-TTL:' + owner, record[1], 300)
    observations.append({'id': sid + ':received-zone-application', **application,
                         'canonicalCandidateWireSha256': hashlib.sha256(independent.zone_input(stream['resultZoneText'])).hexdigest(),
                         'result': 'pass'})

# Actually apply the concrete RFC2136 delete/add section to initial A holdings.
allowed = messages['wwwAllowed-request']
initial = {r for r in independent.text_records(data['streams']['updateAxfr']['baseZoneText']) if r[0] == 'www.lab.example.' and r[3] == 1}
check('update-initial-only-A82', [r[4].hex() for r in initial], ['c0000252'])
for owner, ttl, cls, typ, rdata in allowed['authority']:
    if cls == 255:
        check('update-delete-rrset-zero-ttl-rdata', [ttl, len(rdata)], [0, 0])
        initial = {r for r in initial if not (r[0] == owner and r[3] == typ)}
    elif cls == 1:
        initial.add((owner, ttl, cls, typ, rdata))
    else:
        raise ValueError('Unsupported concrete UPDATE operation')
check('actual-update-direction-A82-to-A80-A81', sorted(r[4].hex() for r in initial), ['c0000250', 'c0000251'])
check('actual-noerror-signed-update-response', messages['wwwAllowed-response']['flags'] & 15, 0)
check('actual-refused-signed-policy-response', messages['apexNsDenied-response']['flags'] & 15, 5)
check('denied-update-targets-apex-NS', sorted({(r[0], r[3]) for r in messages['apexNsDenied-request']['authority']}), [('lab.example.', 2)])
observations.append({'id': 'actual-update-A-application', 'initialAddress': '192.0.2.82',
                     'resultAddresses': ['192.0.2.80', '192.0.2.81'], 'result': 'pass',
                     'scope': 'Concrete RFC2136 operation bytes, not an application/ACL acceptance oracle.'})

# Exact frozen checksum variant, with exact unsigned glue mutation. Independent
# text parsing+canonical collation is not imported from either frozen verifier.
frozen_zonemd = json.loads((NUM / 'zonemd-auth-fixtures.json').read_bytes())['zonemd']
ztuples = {row['id']: row for row in data['zonemdReferenceTuples']}
check('zonemd-exact-original-zoneText', ztuples['zonemd-original']['zoneText'], frozen_zonemd['zoneText'])
check('zonemd-exact-unsigned-glue-mutation', ztuples['zonemd-unsigned-glue-mutated']['zoneText'], frozen_zonemd['zoneText'].replace('192.0.2.200', '192.0.2.201'))
for tuple_ in data['zonemdReferenceTuples']:
    canonical = independent.zone_input(tuple_['zoneText'])
    check(tuple_['id'] + ':canonical-zone-input', canonical.hex(), tuple_['canonicalZoneWireHex'])
    check(tuple_['id'] + ':sha384', hashlib.sha384(canonical).hexdigest(), tuple_['digestHex'])
    check(tuple_['id'] + ':text-sha256', hashlib.sha256(tuple_['zoneText'].encode()).hexdigest(), tuple_['zoneTextSha256'])
    check(tuple_['id'] + ':scheme-hash', [tuple_['scheme'], tuple_['hashAlgorithm']], [1, 1])
    zone = dns.zone.from_text(tuple_['zoneText'], origin='lab.example.', relativize=False)
    digest = zone.compute_digest(dns.zonetypes.DigestHashAlgorithm.SHA384)
    check(tuple_['id'] + ':library-positive-digest', digest.digest.hex(), tuple_['digestHex'])
    zone.verify_digest(digest)
    result = subprocess.run(['openssl', 'dgst', '-sha384'], input=canonical, capture_output=True, check=True)
    check(tuple_['id'] + ':openssl-sha384', result.stdout.decode().strip().split()[-1], tuple_['digestHex'])
    observations.append({'id': tuple_['id'], 'canonicalBytes': len(canonical), 'digestHex': tuple_['digestHex'],
                         'opensslStdout': result.stdout.decode(), 'result': 'pass'})
check('zonemd-original-frozen-authenticated-digest', ztuples['zonemd-original']['digestHex'], frozen_zonemd['digestHex'])
# Published RFC8976 Appendix A.1 is a separate externally fixed oracle for collation.
published_zone = ('example. 86400 IN SOA ns1.example. admin.example. 2018031900 1800 900 604800 86400\n'
                  'example. 86400 IN NS ns1.example.\nexample. 86400 IN NS ns2.example.\n'
                  'ns1.example. 3600 IN A 203.0.113.63\nns2.example. 3600 IN AAAA 2001:db8::63\n')
published_digest = 'c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c'
check('rfc8976-appendix-A1-published-sha384', hashlib.sha384(independent.zone_input(published_zone, 'example.')).hexdigest(), published_digest)

# Preserve actual mismatch observations without putting negative expectations in tuples.
zone = dns.zone.from_text(ztuples['zonemd-unsigned-glue-mutated']['zoneText'], origin='lab.example.', relativize=False)
try:
    zone.verify_digest()
    observed = 'pass'
except Exception as error:
    observed = type(error).__name__
    observations.append({'id': 'frozen-authenticated-digest-vs-mutated-glue', 'exceptionClass': observed, 'message': str(error),
                         'originalDigestHex': ztuples['zonemd-original']['digestHex'],
                         'mutatedDigestHex': ztuples['zonemd-unsigned-glue-mutated']['digestHex']})
check('actual-mutated-frozen-digest-library-observation', observed, 'DigestVerificationFailure')

report = {'schemaVersion': 1, 'postFreeze': True, 'freezeAuthoritySha256': data['freezeAuthoritySha256'],
    'kind': 'dns19-independent-public-numeric-verification', 'fixtureSha256': hashlib.sha256(raw).hexdigest(),
    'fixtureBytes': len(raw), 'fixturePath': reference_path(FIXTURE), 'baseClock': BASE, 'result': 'pass',
    'checksCount': len(checks), 'checks': checks, 'observationsCount': len(observations), 'observations': observations,
    'counts': {key: len(data[key]) for key in ['keys', 'dnssecKeys', 'rrsets', 'signatures', 'messages', 'streams', 'updates', 'macReferenceTuples', 'zonemdReferenceTuples']},
    'code': [identity(HERE / name) for name in ['produce.py', 'verify.py', 'independent_bytes.py']],
    'safeFrozenPrimitive': identity(ROOT / reference_path(CURRENT_TOOLS / 'reference_bytes.py')),
    'runtime': {'python': platform.python_version(), 'packages': versions,
                'opensslCli': subprocess.run(['openssl', 'version'], capture_output=True, text=True, check=True).stdout.strip()},
    'command': [_current_sys.executable, '-B', str(_CurrentPath(__file__).resolve())],
    'failureCaptureDirectory': reference_path(output_root() / 'post-freeze-completion/dns19/runs'),
    'scope': 'Independent positive HMAC/digest and actual signed RR/message evidence only; no application or ACL acceptance oracle.',
    'limits': data['provenance']['limits']}
result = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
path = OUT / 'dns19-verification-v2.json'
if path.exists() and path.read_bytes() != result:
    raise RuntimeError('Preserve prior verifier output before regenerating changed evidence')
if not path.exists():
    path.write_bytes(result)
print(json.dumps({**identity(path), 'result': 'pass', 'checksCount': len(checks), 'observationsCount': len(observations), 'fixtureSha256': report['fixtureSha256']}, sort_keys=True))
