#!/usr/bin/env python3
"""Capture actual current runtime and licence bytes from hash-verified sdists."""
import hashlib
import json
import platform
import subprocess
import sys
import tarfile
from cryptography.hazmat.backends.openssl.backend import backend
from current_profile import ROOT, TOOLS, identity, output_root, require_runtime, validate_bundle

out = output_root()
runtime = require_runtime()
profile = validate_bundle()
licenses = []
for package in profile['packages']:
    archive = ROOT / package['source']['path']
    found = False
    with tarfile.open(archive, 'r:gz') as source:
        for member in source.getmembers():
            parts = __import__('pathlib').PurePosixPath(member.name).parts
            if not member.isfile() or len(parts) > 3 or not any(parts[-1].upper().startswith(prefix) for prefix in ('LICENSE', 'COPYING', 'COPYRIGHT')):
                continue
            if member.size > 1048576:
                raise RuntimeError('Unexpected licence size')
            data = source.extractfile(member).read()
            name = package['name'] + '-' + package['version'] + '-' + '-'.join(parts[1:]).replace('.', '-') + '.txt'
            dest = out / 'licenses' / name
            dest.parent.mkdir(exist_ok=True)
            with dest.open('xb') as stream:
                stream.write(data)
            licenses.append({**identity(dest, out), 'package': package['name'], 'version': package['version'],
                             'sourceArchive': package['source'], 'archiveMember': member.name})
            found = True
    if not found:
        raise RuntimeError('Source archive has no licence: ' + package['name'])
row = {'schemaVersion': 1, 'kind': 'dnssec-current-runtime-and-license-identities', 'runtime': runtime,
       'python': {'version': platform.python_version(), 'implementation': platform.python_implementation(),
                  'build': platform.python_build(), 'compiler': platform.python_compiler(), 'executable': sys.executable},
       'platform': {'system': platform.system(), 'machine': platform.machine(), 'libc': platform.libc_ver()},
       'dependencies': runtime['packages'], 'uv': subprocess.check_output(['uv', '--version'], text=True).strip(),
       'opensslCli': subprocess.check_output(['openssl', 'version'], text=True).strip(),
       'cryptographyBackend': backend.openssl_version_text(), 'licenses': licenses,
       'profile': identity(TOOLS / 'profile.json', ROOT), 'requirements': profile['requirements'],
       'packages': profile['packages'], 'command': [sys.executable, '-B', str(TOOLS / 'provenance.py')],
       'offlineScope': {'packageArtifactsBundled': True, 'licenseBytesFromVerifiedSourceArchives': True,
                        'setupEvidence': 'Bootstrap output sibling setup receipts; no install claimed by this licence capture.',
                        'notBundled': ['CPython interpreter', 'uv executable', 'system OpenSSL executable/library', 'OS runtime'],
                        'notClaimed': ['OS-enforced network isolation', 'Cross-platform offline installation',
                                       'Source archive rebuild of cryptography/Rust dependencies', 'Live DNS/server interoperability']}}
with (out / 'runtime-and-licenses.json').open('x') as stream:
    json.dump(row, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps({'runtime': runtime, 'licenses': len(licenses), 'backend': row['cryptographyBackend']}))
