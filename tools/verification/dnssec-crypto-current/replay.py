#!/usr/bin/env python3
"""Execute the maintained current reference graph, or read-only check its seal.

No historical program is imported/executed and no source is rewritten at runtime.
Each program is a normal subprocess of this exact interpreter, with actual captures.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
from current_profile import (ROOT, TOOLS, HISTORICAL, EXPECTED_RUNTIME, identity,
                             regular_file, require_runtime, validate_bundle, verify_identity)

BASE_PRODUCERS = ['generate.py', 'generate_lifecycle.py', 'generate_profiles.py',
                  'generate_zonemd_auth.py', 'generate_records.py', 'generate_refresh.py',
                  'generate_long_profiles.py', 'generate_complete_paths.py',
                  'generate_resolution_profiles.py', 'generate_parent_negative.py',
                  'generate_role_rollovers.py', 'generate_overlap_keysets.py',
                  'generate_review_corrections.py']
ERRATA = 'post-freeze-contract-errata/'
COMPLETION = 'post-freeze-completion/'
PRODUCERS = BASE_PRODUCERS + [ERRATA + 'generate.py', ERRATA + 'correct_owner_wire.py',
                             COMPLETION + 'denial-anchor/generate.py',
                             COMPLETION + 'parent-signing/produce.py', COMPLETION + 'dns19/produce.py']
VERIFIERS = ['verify.py', 'library_check.py', 'verify_lifecycle.py', 'verify_profiles.py',
             'verify_zonemd_auth.py', 'verify_records.py', 'verify_refresh.py',
             'verify_long_profiles.py', 'verify_complete_paths.py', 'verify_resolution_profiles.py',
             'verify_parent_negative.py', 'verify_role_rollovers.py', 'verify_overlap_keysets.py',
             'verify_review_corrections.py', ERRATA + 'verify.py',
             COMPLETION + 'denial-anchor/verify.py', COMPLETION + 'parent-signing/verify.py',
             COMPLETION + 'dns19/verify.py']
FIXTURES = ['dnssec-numeric-fixtures.json', 'lifecycle-fixtures.json', 'profile-fixtures.json',
            'zonemd-auth-fixtures.json', 'record-profile-fixtures.json', 'refresh-fixtures.json',
            'long-profile-fixtures.json', 'complete-path-fixtures.json', 'resolution-profile-fixtures.json',
            'parent-negative-fixtures.json', 'role-rollover-fixtures.json', 'overlap-keysets-fixtures.json',
            'review-corrections/denial-authority-fixtures.json', ERRATA + 'publication-fixtures.json',
            ERRATA + 'resolution-fixtures.json', ERRATA + 'resolution-fixtures-owner-wire-corrected.json',
            COMPLETION + 'denial-anchor/fixtures.json', COMPLETION + 'parent-signing/parent-signing-fixtures.json',
            COMPLETION + 'dns19/dns19-fixtures.json']
REPORTS = ['independent-verification.json', 'library-observations.json', 'lifecycle-verification.json',
           'profile-verification.json', 'zonemd-auth-verification.json', 'record-profile-verification.json',
           'refresh-verification.json', 'long-profile-verification.json', 'complete-path-verification.json',
           'resolution-profile-verification.json', 'parent-negative-verification.json',
           'role-rollover-verification.json', 'overlap-keysets-verification.json',
           'review-corrections/denial-authority-verification.json', ERRATA + 'publication-verification.json',
           ERRATA + 'resolution-verification.json', COMPLETION + 'denial-anchor/verification.json',
           COMPLETION + 'parent-signing/parent-signing-verification.json', COMPLETION + 'dns19/dns19-verification-v2.json']


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(json_bytes(value))


def inventory(out):
    rows = []
    for path in sorted(out.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('Symlink in current output: ' + str(path))
        if path.is_file():
            rows.append(identity(path, out))
        elif not path.is_dir():
            raise RuntimeError('Nonregular current payload: ' + str(path))
    return rows


def snapshot(out):
    # This mutable generation ledger is finalised before the first verifier runs.
    # Verifiers only read it, and its exact identity is included in the catalog.
    names = FIXTURES + ['runtime-and-licenses.json', ERRATA + 'generation-provenance.json']
    rows = [identity(out / name, out) for name in names if (out / name).exists()]
    (out / 'GENERATED-INPUTS.json').write_bytes(json_bytes({'schemaVersion': 1,
        'kind': 'dnssec-current-pre-verification-generated-identities', 'files': rows}))
    return rows


# These fields describe runtime/source lineage, not cryptographic objects. All
# remaining fields (including every owner, TTL, signature, wire, digest and numeric
# literal) are compared recursively without normalising values or case.
TOP_LINEAGE = {'referenceTool', 'generationProvenance', 'provenance', 'baselineSha256',
               'sourceFixtureSha256', 'resolutionProfileSha256', 'baselineFixtureSha256',
               'ownerWireCorrection'}
REFERENCE_FIELDS = {'publicRdataSource', 'frozenZoneRef', 'sourcePath', 'frozenSource', 'aSelfSignatureSource'}


def public_projection(value, path=()):
    if isinstance(value, list):
        return [public_projection(item, path + (str(index),)) for index, item in enumerate(value)]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if not path and key in TOP_LINEAGE:
            continue
        if key in REFERENCE_FIELDS:
            continue
        if path and path[0] in ('references', 'rrsetReferences') and key in ('path', 'sha256'):
            continue
        if path == ('rootTrustMaterial',) and key == 'sourceSha256':
            continue
        if path == ('remoteReceiptFacts', 'separatePrimaryProof') and key == 'path':
            continue
        result[key] = public_projection(item, path + (key,))
    return result


def parity(out):
    rows = []
    for name in FIXTURES:
        current = json.loads((out / name).read_bytes())
        accepted = json.loads((HISTORICAL / name).read_bytes())
        left = public_projection(current)
        right = public_projection(accepted)
        if left != right:
            raise RuntimeError('Regenerated public cryptographic data differs from accepted reference: ' + name)
        public_bytes = json_bytes(left)
        rows.append({'fixture': identity(out / name, out), 'accepted': identity(HISTORICAL / name, ROOT),
                     'publicProjectionSha256': hashlib.sha256(public_bytes).hexdigest(),
                     'publicProjectionBytes': len(public_bytes), 'allPublicFieldsEqual': True})
    return {'kind': 'dnssec-current-public-byte-parity', 'result': 'pass', 'datasets': rows,
            'excludedTopLevelLineageFields': sorted(TOP_LINEAGE),
            'excludedReferenceOnlyFields': sorted(REFERENCE_FIELDS),
            'scope': 'Complete recursively compared fixture objects, excluding only explicit runtime and source-reference lineage.'}


def capture(out, program, phase, number):
    command = [sys.executable, '-B', str(TOOLS / program)]
    environment = dict(os.environ, AUTH_LAB_DNSSEC_CURRENT_OUT=str(out), PYTHONDONTWRITEBYTECODE='1')
    environment.pop('PYTHONPATH', None)
    environment.pop('PYTHONHOME', None)
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True)
    row = {'schemaVersion': 1, 'kind': 'dnssec-current-actual-command-capture', 'phase': phase,
           'program': program, 'command': command, 'cwd': str(ROOT), 'startedAt': start,
           'finishedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'exitCode': result.returncode,
           'stdout': result.stdout, 'stderr': result.stderr, 'programIdentity': identity(TOOLS / program, ROOT),
           'runtime': EXPECTED_RUNTIME}
    receipt = out / 'runs' / ('run-%03d.json' % number)
    write_new(receipt, row)
    if result.returncode:
        raise RuntimeError('Current reference command failed; retained ' + str(receipt) + '\n' + result.stderr)
    if program == 'verify_review_corrections.py':
        report = json.loads(result.stdout)
        write_new(out / 'review-corrections/denial-authority-verification.json', report)
    return {'program': program, 'phase': phase, 'exitCode': result.returncode, 'capture': identity(receipt, out)}


def create(out):
    profile = validate_bundle()
    runtime = require_runtime()
    out = out.absolute()
    if out.exists() or out.is_symlink() or out.resolve() != out or out == ROOT or ROOT in out.parents:
        raise RuntimeError('--out must be a nonexistent external path without symlinks')
    out.mkdir(parents=True)
    # Retained primary source bytes are inputs, not regenerated reports. Copy only
    # this source tree; all fixtures/reports below are actually generated anew.
    shutil.copytree(HISTORICAL / 'sources', out / 'sources', symlinks=False)
    code = []
    for path in sorted(TOOLS.rglob('*.py')):
        if '__pycache__' in path.parts:
            continue
        relative = path.relative_to(TOOLS)
        dest = out / 'code' / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open('xb') as stream:
            stream.write(path.read_bytes())
        code.append({'source': identity(path, ROOT), 'snapshot': identity(dest, out)})
    for name in ('profile.json', 'requirements.txt'):
        dest = out / 'inputs' / name
        dest.parent.mkdir(exist_ok=True)
        dest.write_bytes((TOOLS / name).read_bytes())
    commands = [capture(out, 'provenance.py', 'provenance', 1)]
    for program in PRODUCERS:
        commands.append(capture(out, program, 'producer', len(commands) + 1))
        snapshot(out)
    generated = snapshot(out)
    if {r['path'] for r in generated} != set(FIXTURES + ['runtime-and-licenses.json', ERRATA + 'generation-provenance.json']):
        raise RuntimeError('Producer graph did not produce every required input')
    generated_identity = identity(out / 'GENERATED-INPUTS.json', out)
    for program in VERIFIERS:
        commands.append(capture(out, program, 'verifier', len(commands) + 1))
    verify_identity(out, generated_identity)
    for row in generated:
        verify_identity(out, row)
    for name in REPORTS:
        regular_file(out, name)
    proof = parity(out)
    write_new(out / 'PUBLIC-BYTE-PARITY.json', proof)
    validate_bundle()  # Preserve original authorities before AND after execution.
    catalog = {'schemaVersion': 1, 'kind': 'current-dnssec-offline-reference-catalog',
               'result': 'pass', 'runtime': runtime, 'independentOfProduction': True,
               'profile': identity(TOOLS / 'profile.json', ROOT), 'requirements': profile['requirements'],
               'code': code, 'commands': commands,
               'producers': [row for row in commands if row['phase'] == 'producer'],
               'verifiers': [row for row in commands if row['phase'] == 'verifier'],
               'generatedInputs': generated_identity, 'fixtures': [identity(out / name, out) for name in FIXTURES],
               'reports': [identity(out / name, out) for name in REPORTS],
               'runtimeAndLicenses': identity(out / 'runtime-and-licenses.json', out),
               'publicByteParity': identity(out / 'PUBLIC-BYTE-PARITY.json', out),
               'preservation': {'originalAuthorityAndPayloadBytesUnchanged': True,
                                'authorities': profile['historical']['authorities'], 'files': profile['historical']['files']},
               'limits': ['Offline package selection, not OS-enforced network isolation',
                          'No production imports or live DNS/server interoperability',
                          'External CPython/uv/system OpenSSL/OS prerequisites; no source rebuild claimed']}
    write_new(out / 'CURRENT-CATALOG.json', catalog)
    rows = inventory(out)
    write_new(out / 'CONTENTS.json', {'schemaVersion': 1, 'kind': 'dnssec-current-output-identities',
                                    'files': rows, 'fileCount': len(rows), 'payloadBytes': sum(row['bytes'] for row in rows)})
    sums = rows + [identity(out / 'CONTENTS.json', out)]
    with (out / 'SHA256SUMS').open('x') as stream:
        stream.write(''.join(row['sha256'] + '  ' + row['path'] + '\n' for row in sorted(sums, key=lambda row: row['path'])))
    return catalog


def check(out):
    # stdlib-only, read-only: never imports a producer, crypto package or verifier.
    profile = validate_bundle()
    if out.is_symlink() or not out.is_dir():
        raise RuntimeError('Missing regular sealed output directory')
    contents = json.loads(regular_file(out, 'CONTENTS.json').read_bytes())
    if contents['schemaVersion'] != 1 or contents['kind'] != 'dnssec-current-output-identities':
        raise RuntimeError('Unsupported output manifest')
    rows = contents['files']
    names = [row['path'] for row in rows]
    if len(set(names)) != len(names) or set(names) & {'CONTENTS.json', 'SHA256SUMS'}:
        raise RuntimeError('Duplicate or recursive output identity')
    for row in rows:
        verify_identity(out, row)
    actual = inventory(out)
    if {r['path'] for r in actual} != set(names) | {'CONTENTS.json', 'SHA256SUMS'}:
        raise RuntimeError('Sealed output file set differs')
    if contents['fileCount'] != len(rows) or contents['payloadBytes'] != sum(row['bytes'] for row in rows):
        raise RuntimeError('Incorrect output manifest totals')
    expected_sums = ''.join(row['sha256'] + '  ' + row['path'] + '\n' for row in sorted(rows + [identity(out / 'CONTENTS.json', out)], key=lambda row: row['path']))
    if regular_file(out, 'SHA256SUMS').read_text() != expected_sums:
        raise RuntimeError('SHA256SUMS differs from sealed contents')
    catalog = json.loads(regular_file(out, 'CURRENT-CATALOG.json').read_bytes())
    if catalog['schemaVersion'] != 1 or catalog['kind'] != 'current-dnssec-offline-reference-catalog' or catalog['result'] != 'pass' or catalog['runtime'] != EXPECTED_RUNTIME:
        raise RuntimeError('Invalid current runtime catalog')
    if catalog['preservation'] != {'originalAuthorityAndPayloadBytesUnchanged': True,
                                  'authorities': profile['historical']['authorities'], 'files': profile['historical']['files']}:
        raise RuntimeError('Catalog does not preserve the original authorities')
    verify_identity(ROOT, catalog['profile'])
    for code in catalog['code']:
        verify_identity(ROOT, code['source'])
        verify_identity(out, code['snapshot'])
        if code['source']['sha256'] != code['snapshot']['sha256']:
            raise RuntimeError('Code snapshot differs from executed source')
    if [r['program'] for r in catalog['producers']] != PRODUCERS or [r['program'] for r in catalog['verifiers']] != VERIFIERS:
        raise RuntimeError('Incomplete producer/verifier graph')
    commands = catalog['commands']
    if [r['program'] for r in commands] != ['provenance.py'] + PRODUCERS + VERIFIERS:
        raise RuntimeError('Incomplete actual command captures')
    for command in commands:
        verify_identity(out, command['capture'])
        row = json.loads((out / command['capture']['path']).read_bytes())
        if command['exitCode'] != 0 or row['exitCode'] != 0 or row['program'] != command['program'] or row['phase'] != command['phase'] or row['runtime'] != EXPECTED_RUNTIME:
            raise RuntimeError('Unsuccessful or mismatched execution receipt')
        captured_root = pathlib.Path(row['cwd'])
        expected_program = captured_root / 'tools/verification/dnssec-crypto-current' / row['program']
        if len(row['command']) != 3 or row['command'][1:] != ['-B', str(expected_program)] or not captured_root.is_absolute() or not pathlib.Path(row['command'][0]).is_absolute():
            raise RuntimeError('Captured command differs from the maintained program')
        verify_identity(ROOT, row['programIdentity'])
    for field, names_expected in (('fixtures', FIXTURES), ('reports', REPORTS)):
        if [r['path'] for r in catalog[field]] != names_expected:
            raise RuntimeError('Incomplete ' + field + ' catalog')
        for row in catalog[field]:
            verify_identity(out, row)
    for field in ('generatedInputs', 'runtimeAndLicenses', 'publicByteParity'):
        verify_identity(out, catalog[field])
    snapshot_data = json.loads((out / catalog['generatedInputs']['path']).read_bytes())
    for row in snapshot_data['files']:
        verify_identity(out, row)
    provenance = json.loads((out / catalog['runtimeAndLicenses']['path']).read_bytes())
    if provenance['runtime'] != EXPECTED_RUNTIME or provenance['packages'] != profile['packages']:
        raise RuntimeError('Runtime/licence provenance does not match current profile')
    for license_row in provenance['licenses']:
        verify_identity(out, license_row)
    expected_parity = parity(out)
    if json.loads((out / catalog['publicByteParity']['path']).read_bytes()) != expected_parity:
        raise RuntimeError('Public byte parity proof differs')
    return catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--out', type=pathlib.Path)
    modes.add_argument('--check', type=pathlib.Path)
    args = parser.parse_args()
    catalog = create(args.out) if args.out is not None else check(args.check)
    print(json.dumps({'result': 'pass', 'runtime': catalog['runtime'],
                      'producers': len(catalog['producers']), 'verifiers': len(catalog['verifiers'])}))


if __name__ == '__main__':
    main()
