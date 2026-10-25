#!/usr/bin/env python3
"""Independent stdlib ZIP reader; verifies a relocated completed review delivery."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import zipfile

repo, delivery, output, bun = map(Path, sys.argv[1:5])
expected_source = '1b5a3350e5e2b778efb52dccb46473e197df1ec202e3cd202618540c1988f234'
expected_html = '5e13671a57cfb0d4c827b4eb6af52fc6d0d53f48c5816c8e7bcc423e54022f54'
files = ['auth-flow-studio-dnssec-source-and-review.zip', 'auth-flow-studio-dnssec.html', 'START-HERE.md', 'SHA256SUMS.txt', 'packaging-status.json']
report = {'schemaVersion': 1, 'kind': 'DNSSEC-independent-relocated-review-integrity', 'argv': sys.argv, 'startedAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'passed': False, 'commands': [], 'scope': 'Independent Python stdlib ZIP/member/hash/source/freeze checks and actual relocated build, not a second human/Astra review, owner acceptance or publication.'}
stage = None

def require(condition, message):
    if not condition:
        raise AssertionError(message)

def digest(path):
    require(stat.S_ISREG(path.lstat().st_mode), 'Regular no-symlink file: ' + str(path))
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return {'sha256': h.hexdigest(), 'bytes': path.stat().st_size}

def load(path):
    return json.loads(path.read_text())

def safe(name):
    require(isinstance(name, str) and name and not name.startswith(('/', '-')) and '\\' not in name and not any(ord(c) < 32 or ord(c) == 127 for c in name), 'Safe archive path')
    require(all(p not in ('', '.', '..') for p in name.split('/')), 'No archive path traversal')
    return PurePosixPath(name)

def command(args, cwd):
    env = {**os.environ, 'BUN_INSTALL_AUTO': 'disable', 'npm_config_offline': 'true'}
    result = subprocess.run(list(map(str, args)), cwd=cwd, env=env, capture_output=True, text=True, timeout=600)
    row = {'argv': list(map(str, args)), 'cwd': str(cwd), 'exitCode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    report['commands'].append(row)
    require(result.returncode == 0, 'Command failed: ' + repr(row['argv']))
    return row

def canonical(root):
    names = ['index.html', 'build.mjs', 'security-policy.mjs', 'package.json']
    for directory in ['assets', 'src', 'tests']:
        for parent, dirs, filenames in os.walk(root / directory, followlinks=False):
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules')]
            for d in dirs:
                require(not (Path(parent) / d).is_symlink(), 'No canonical directory symlink')
            names.extend((Path(parent) / f).relative_to(root).as_posix() for f in filenames)
    h = hashlib.sha256()
    identities = {}
    for name in sorted(names):
        path = root / name
        identities[name] = digest(path)['sha256']
        h.update(name.encode() + b'\0')
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(chunk)
        h.update(b'\0')
    return {'algorithm': 'sha256-path-nul-bytes-nul-v1', 'sha256': h.hexdigest(), 'files': identities}

try:
    require(not output.exists(), 'New independent output file required')
    require(sorted(p.name for p in delivery.iterdir()) == sorted(files), 'Exactly five delivered files')
    originals = {name: digest(delivery / name) for name in files}
    report['delivered'] = originals
    previous = delivery.with_name('corrections-02')
    previous_proof = load(repo / 'docs/verification/dnssec-review-corrections/review-relocation-02.json')
    require(previous_proof['passed'], 'Prior delivery has its original successful relocation proof')
    require(sorted(p.name for p in previous.iterdir()) == sorted(files), 'Prior delivery retains exactly five siblings')
    for name in files:
        require(digest(previous / name) == previous_proof['delivered'][name], 'Corrections02 unchanged: ' + name)
    report['priorDeliveryPreserved'] = {'directory': str(previous), 'files': previous_proof['delivered'], 'unchanged': True}
    older = Path(previous_proof['priorDeliveryPreserved']['directory'])
    older_files = previous_proof['priorDeliveryPreserved']['files']
    require(older == delivery.with_name('corrections-01'), 'Exact earlier corrections01 delivery')
    for name in files:
        require(digest(older / name) == older_files[name], 'Corrections01 unchanged: ' + name)
    report['earlierDeliveryPreserved'] = {'directory': str(older), 'files': older_files, 'unchanged': True}
    cache = Path.home() / '.cache'
    require(cache.is_dir() and not cache.is_symlink() and cache.stat().st_uid == os.getuid(), 'Owned Linux cache parent')
    require(not str(cache.resolve()).startswith('/mnt/'), 'No Windows stage')
    stage = Path(tempfile.mkdtemp(prefix='dnssec-review-relocation-', dir=cache))
    relocated = stage / 'relocated'
    relocated.mkdir(mode=0o700)
    report['stage'] = {'path': str(stage), 'ownedUid': stage.stat().st_uid, 'retained': True}
    for name in files:
        shutil.copyfile(delivery / name, relocated / name)
        require(digest(relocated / name) == originals[name], 'Exact relocated sibling bytes')
    command(['sha256sum', '-c', 'SHA256SUMS.txt'], relocated)
    packaging = load(relocated / 'packaging-status.json')
    require(packaging['status'] == 'packaging-integrity-verified-not-acceptance', 'Successful original producer record')
    archive = relocated / files[0]
    with zipfile.ZipFile(archive) as z:
        members = z.infolist()
        names = [entry.filename for entry in members]
        require(len(names) == len(set(names)), 'No duplicate ZIP members')
        for entry in members:
            safe(entry.filename)
            require(not entry.is_dir(), 'Explicit regular-file ZIP members only')
            mode = entry.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG), 'No ZIP symlink or special entry')
            require(not entry.flag_bits & 1, 'No encrypted payload')
            for parent in PurePosixPath(entry.filename).parents:
                require(str(parent) not in names, 'No file/directory prefix collision')
        contents = json.loads(z.read('CONTENTS.json'))
        payloads = contents['payloads']
        require(set(names) == {'CONTENTS.json'} | {row['member'] for row in payloads}, 'Exact declared ZIP member set')
        manifest = load(repo / 'docs/dnssec-expansion/corrections/review-package-inputs-03.json')
        selected = {'source/' + row['path'] for row in manifest['source']} | {row['member'] for row in manifest['review']}
        require(set(names) == selected | {'CONTENTS.json'}, 'Exact current explicit-manifest membership')
        require(len(names) == len(payloads) + 1 == len(selected) + 1, 'Exact complete member count')
        declared = {row['member']: row for row in payloads}
        for entry in members:
            target = relocated / entry.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha256()
            size = 0
            with z.open(entry) as source, target.open('xb') as dest:
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    h.update(chunk)
                    size += len(chunk)
                    dest.write(chunk)
            if entry.filename != 'CONTENTS.json':
                row = declared[entry.filename]
                require(h.hexdigest() == row['sha256'] and size == row['bytes'], 'Every member hash/size: ' + entry.filename)
    report['zipMembersVerified'] = len(names)
    report['allMemberHashesAndSizesVerified'] = True
    command(['sha256sum', '-c', 'review/SHA256SUMS'], relocated)
    root = relocated / 'source'
    actual = canonical(root)
    expected = load(repo / 'docs/verification/dnssec-r10-correction/candidate-inputs-01.json')['sourceIdentity']
    require(actual == expected == contents['sourceIdentity'], 'Complete actual canonical source identity')
    require(actual['sha256'] == expected_source and len(actual['files']) == 231, 'Expected corrected source')
    report['canonicalSource'] = {'sha256': actual['sha256'], 'files': 231, 'algorithm': actual['algorithm']}
    source_status = load(repo / 'docs/verification/dnssec-r10-correction/source-contract-01/status.json')
    authority = source_status['inputIdentity']['independentFiles']
    for name, sha in authority.items():
        safe(name)
        require(digest(root / name)['sha256'] == sha, 'Exact protected authority: ' + name)
    require(len(authority) == 435, 'Every protected authority input')
    freeze = load(root / 'docs/dnssec-expansion/contract-freeze.json')
    require(len(freeze['inputs']) == 354, 'All original354 frozen inputs')
    for row in freeze['inputs']:
        safe(row['path'])
        require(digest(root / row['path']) == {'sha256': row['sha256'], 'bytes': row['bytes']}, 'Original frozen bytes: ' + row['path'])
    report['protectedIndependentInputsVerified'] = 435
    report['originalFrozenInputsVerified'] = 354
    gates = load(root / 'docs/dnssec-expansion/open-gates.json')
    require(gates['releaseAccepted'] is False and gates['manualG01']['observedOutput'] is None, 'Manual/release gates remain open')
    require(len(gates['priorScopedClosures']['closed']) == 21, 'All21 scoped P6 closures preserved')
    require(len(gates['optionalDeferrals']) == 4 and len(gates['siblingOrigins']['knownKinds']) == 6, 'Deferrals/omissions preserved')
    require(gates['priorMeasuredPerformance']['ownerAcceptanceRecorded'] is False, 'No inherited performance waiver')
    for row in [gates['inheritedAuthority'], gates['priorScopedClosures']['record'], gates['priorMeasuredPerformance']['report'], gates['priorMeasuredPerformance']['dispositions'], gates['priorSourceCaptureDispositions']['record']]:
        require(digest(root / row['path']) == {'sha256': row['sha256'], 'bytes': row['bytes']}, 'Exact inherited authority bytes')
    authority_closures = load(root / gates['priorScopedClosures']['record']['path'])
    require(gates['priorScopedClosures']['closed'] == authority_closures['closed'], 'Every scoped closure entry exact')
    report['inheritedLimitsAnd21ClosuresPreserved'] = True
    recheck = load(root / 'docs/dnssec-expansion/corrections/independent-recheck-02-disposition.json')
    require(recheck['review']['sha256'] == 'f560e0e23af6c55dad5db499a49e767f302d28b99343043dce61e561a743e308', 'Exact performed Astra recheck binding')
    require(digest(root / recheck['review']['path'])['sha256'] == recheck['review']['sha256'], 'Preserved raw recheck bytes')
    require([row['id'] for row in recheck['originalClosuresPreserved']] == ['DNS-R%02d' % n for n in range(1, 10)], 'Nine DNS closures preserved separately from prior P6 scope')
    focus = recheck['sourceFocusClosure']
    require(focus['id'] == 'DNS-C04' and focus['workerAlias'] == 'DNS-R09-focus-identity' and focus['countAsOneIssue'] and focus['status'] == 'closed', 'Focus followup counted as one closed issue')
    require(len(recheck['semanticFollowups']) == 2 and all(not row['precedingRecheckCoveredThis'] for row in recheck['semanticFollowups']), 'Two semantic followups retain exact performed-review scope')
    require([row['id'] for row in recheck['requiredCorrections']] == ['DNS-R10'] and recheck['status'] == 'changes-required', 'R10 independent closure still required')
    require(gates['independentDnssecReview']['status'] == 'changes-required', 'Worker verification is not independent closure')
    report['performedReviewAndClosureBoundariesVerified'] = True
    transforms = ['apply-dnssec-contract-errata.mjs', 'apply-dnssec-completion-errata.mjs', 'apply-dnssec-receipt-errata.mjs', 'apply-dnssec-client-context-errata.mjs', 'apply-dnssec-cache-kind-errata.mjs', 'apply-dnssec-review-corrections-errata.mjs', 'apply-dnssec-mixed-path-policy-errata.mjs', 'apply-dnssec-cache-namespace-location-errata.mjs', 'freeze-dnssec-contract.mjs']
    for script in transforms:
        command([bun, 'tools/verification/' + script, '--check'], root)
    report['sealedTransformChecks'] = 8
    report['originalFreezeCommandPassed'] = True
    command([bun, '--no-install', 'build.mjs', '--source-version'], root)
    require(digest(root / 'dist/auth-flow-studio.html') == originals['auth-flow-studio-dnssec.html'], 'Actual relocated offline build byte-identical')
    require(originals['auth-flow-studio-dnssec.html']['sha256'] == expected_html, 'Exact reviewed current HTML')
    require(canonical(root) == actual, 'Relocated canonical source unchanged after build/checks')
    for name in files:
        require(digest(delivery / name) == originals[name], 'Original delivered set unchanged')
    for name in files:
        require(digest(previous / name) == previous_proof['delivered'][name], 'Corrections02 still unchanged after relocated verification: ' + name)
        require(digest(older / name) == older_files[name], 'Corrections01 still unchanged after relocated verification: ' + name)
    report['relocatedOfflineBuild'] = {'passed': True, 'sha256': expected_html, 'bytes': originals['auth-flow-studio-dnssec.html']['bytes'], 'automaticInstalls': 'disabled'}
    report['bothChecksumLayersPassed'] = True
    report['originalDeliveryUnchanged'] = True
    report['releaseAccepted'] = False
    report['publicationAuthorized'] = False
    report['passed'] = True
except BaseException as error:
    report['error'] = str(error)
    report['traceback'] = traceback.format_exc()
finally:
    if report['passed'] and stage:
        require(stage.parent == Path.home() / '.cache' and stage.name.startswith('dnssec-review-relocation-') and stage.stat().st_uid == os.getuid(), 'Only owned stage cleanup')
        shutil.rmtree(stage)
        report['stage']['retained'] = False
    report['finishedAt'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    captured = output.with_name(output.name + '.runner-input.py')
    shutil.copyfile(Path(__file__), captured)
    report['runner'] = {'path': str(captured.relative_to(repo)), **digest(captured)}
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report.get(key) for key in ['passed', 'zipMembersVerified', 'canonicalSource', 'protectedIndependentInputsVerified', 'originalFrozenInputsVerified', 'sealedTransformChecks', 'bothChecksumLayersPassed', 'relocatedOfflineBuild', 'originalDeliveryUnchanged', 'stage', 'error']}, indent=2))
    if not report['passed']:
        sys.exit(1)
