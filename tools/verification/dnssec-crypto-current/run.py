#!/usr/bin/env python3
"""Validate the captured bundle or replay it in a new, external offline environment."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
PROFILE = HERE / 'profile.json'
RUNTIME = {'python': '3.14.4', 'uv': '0.12.10', 'platform': 'Linux',
           'machine': 'x86_64', 'packages': {'dnspython': '2.8.0',
           'cryptography': '50.0.0', 'cffi': '2.1.1', 'pycparser': '3.12'}}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bundle_path(name):
    require(isinstance(name, str), 'Invalid bundle path')
    rel = PurePosixPath(name)
    require(name and not rel.is_absolute() and '..' not in rel.parts and
            str(rel) == name, f'Unsafe bundle path: {name}')
    current = ROOT
    for part in rel.parts:
        current = current / part
        require(not current.is_symlink(), f'Bundle symlink: {name}')
    return current


def identity(entry):
    require(isinstance(entry, dict), 'Invalid file identity')
    name = entry.get('path')
    path = bundle_path(name)
    require(isinstance(entry.get('bytes'), int) and entry['bytes'] >= 0 and
            re.fullmatch(r'[0-9a-f]{64}', entry.get('sha256', '')),
            f'Invalid file identity: {name}')
    require(path.is_file(), f'Missing bundled file: {name}')
    data = path.read_bytes()
    require(len(data) == entry['bytes'] and hashlib.sha256(data).hexdigest() == entry['sha256'],
            f'Bundled file hash/size mismatch: {name}')
    return data


def compatible_python(specifier):
    """Evaluate the numeric Requires-Python clauses used by this exact bundle."""
    if not specifier:
        return
    current = tuple(map(int, RUNTIME['python'].split('.')))
    for clause in specifier.split(','):
        match = re.fullmatch(r'\s*(>=|<=|!=|==|>|<)\s*(\d+(?:\.\d+){0,2})\s*', clause)
        require(match is not None, f'Unsupported Requires-Python declaration: {specifier}')
        operator, version = match.groups()
        wanted = tuple(map(int, version.split('.')))
        wanted += (0,) * (3 - len(wanted))
        accepted = {'>=': current >= wanted, '<=': current <= wanted,
                    '!=': current != wanted, '==': current == wanted,
                    '>': current > wanted, '<': current < wanted}[operator]
        require(accepted, f'Incompatible Requires-Python declaration: {specifier}')


def compatible_wheel(name):
    require(name.endswith('.whl'), f'Not a wheel: {name}')
    parts = name[:-4].rsplit('-', 3)
    require(len(parts) == 4, f'Invalid wheel filename: {name}')
    _, python_tag, abi_tag, platform_tag = parts
    python_ok = False
    for tag in python_tag.split('.'):
        if tag in ('py3', 'py314', 'cp314'):
            python_ok = True
        elif re.fullmatch(r'cp3\d+', tag) and abi_tag == 'abi3':
            python_ok |= 8 <= int(tag[3:]) <= 14
    require(python_ok and abi_tag in ('none', 'abi3', 'cp314'),
            f'Incompatible CPython 3.14 wheel: {name}')
    supported = False
    libc_name, libc_version = platform.libc_ver()
    for tag in platform_tag.split('.'):
        if tag == 'any':
            supported = True
        match = re.fullmatch(r'manylinux_(\d+)_(\d+)_x86_64', tag)
        if match and libc_name == 'glibc':
            supported |= tuple(map(int, libc_version.split('.')[:2])) >= tuple(map(int, match.groups()))
        if tag in ('manylinux2014_x86_64', 'manylinux2010_x86_64', 'manylinux1_x86_64') and libc_name == 'glibc':
            supported = True
    require(supported, f'Incompatible Linux x86_64 wheel: {name}')


def check_bundle(profile_path=PROFILE):
    profile = json.loads(profile_path.read_text())
    require(profile.get('schemaVersion') == 1 and
            profile.get('kind') == 'dnssec-current-offline-crypto-profile', 'Unsupported profile schema')
    require(profile.get('runtime') == RUNTIME, 'Unsupported runtime/package pins')
    require(platform.system() == RUNTIME['platform'] and platform.machine() == RUNTIME['machine'],
            'Bundle requires Linux x86_64')
    requirements = identity(profile['requirements']).decode('utf-8')
    require(profile['requirements']['path'] == 'tools/verification/dnssec-crypto-current/requirements.txt',
            'Unexpected requirements path')
    pins = {}
    for line in requirements.replace('\\\n', ' ').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([a-zA-Z0-9_-]+)==([^\s]+)\s+--hash=sha256:([0-9a-f]{64})', line)
        require(match is not None, f'Unsupported requirement: {line}')
        name, version, digest = match.groups()
        require(name not in pins, f'Duplicate requirement: {name}')
        pins[name] = (version, digest)
    require({name: value[0] for name, value in pins.items()} == RUNTIME['packages'],
            'Requirements do not match pinned packages')
    packages = profile['packages']
    require(isinstance(packages, list) and len(packages) == len(pins), 'Incomplete package bundle')
    seen = set()
    for package in packages:
        name, version = package['name'], package['version']
        require(name in pins and name not in seen and version == pins[name][0],
                f'Unexpected package/version: {name} {version}')
        seen.add(name)
        for key in ('wheel', 'source', 'metadata'):
            identity(package[key])
        wheel = package['wheel']
        require(wheel['sha256'] == pins[name][1], f'Requirement/wheel hash disagreement: {name}')
        compatible_wheel(PurePosixPath(wheel['path']).name)
        wheel_prefix = name.replace('-', '_') + '-' + version + '-'
        require(PurePosixPath(wheel['path']).name.startswith(wheel_prefix), f'Wheel package mismatch: {name}')
        metadata = json.loads(bundle_path(package['metadata']['path']).read_text())
        require(metadata['info']['name'].lower().replace('_', '-') == name and
                metadata['info']['version'] == version, f'Upstream metadata package mismatch: {name}')
        compatible_python(metadata['info'].get('requires_python'))
        for kind, package_type in (('wheel', 'bdist_wheel'), ('source', 'sdist')):
            artifact = package[kind]
            matches = [row for row in metadata['urls']
                       if row.get('filename') == PurePosixPath(artifact['path']).name]
            require(len(matches) == 1, f'Artifact absent/ambiguous in upstream metadata: {artifact["path"]}')
            row = matches[0]
            compatible_python(row.get('requires_python'))
            require(row.get('digests', {}).get('sha256') == artifact['sha256'] and
                    row.get('size') == artifact['bytes'] and row.get('url') == artifact['url'] and
                    row.get('packagetype') == package_type and not row.get('yanked', False),
                    f'Artifact/upstream metadata disagreement: {artifact["path"]}')
    historical = profile['historical']
    require(historical['authorities'] and historical['files'], 'Missing frozen preservation inventory')
    preserved = {}
    for entry in historical['authorities'] + historical['files']:
        identity(entry)
        value = (entry['sha256'], entry['bytes'])
        require(entry['path'] not in preserved or preserved[entry['path']] == value,
                f'Conflicting historical identity: {entry["path"]}')
        preserved[entry['path']] = value

    def check_refs(value):
        if isinstance(value, dict):
            if all(key in value for key in ('path', 'sha256', 'bytes')):
                require(preserved.get(value['path']) == (value['sha256'], value['bytes']),
                        f'Historical authority reference missing/mismatched: {value["path"]}')
            for child in value.values():
                check_refs(child)
        elif isinstance(value, list):
            for child in value:
                check_refs(child)

    freeze_name = 'docs/dnssec-expansion/contract-freeze.json'
    required = {freeze_name, 'docs/dnssec-expansion/numeric/FINAL-CONTENTS.json'}
    require(required.issubset({row['path'] for row in historical['authorities']}),
            'Missing original freeze/final historical authorities')
    # Earlier inventories are immutable snapshots, not live inventories.
    # Preserve their bytes; enforce membership against the original freeze.
    freeze = json.loads(bundle_path(freeze_name).read_text())
    require(isinstance(freeze.get('inputs'), list) and freeze['inputs'],
            'Missing original freeze inputs')
    check_refs(freeze['inputs'])
    return profile


def capture(out, label, argv, env):
    record = {'argv': list(map(str, argv)), 'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        result = subprocess.run(record['argv'], cwd=ROOT, env=env, capture_output=True, text=True)
        record.update(exitCode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except OSError as error:
        record.update(exitCode=127, stdout='', stderr=str(error))
    record['finishedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with (out / f'{label}.json').open('x') as handle:
        json.dump(record, handle, indent=2)
        handle.write('\n')
    require(record['exitCode'] == 0, f'{label} failed (exit {record["exitCode"]}); see {out / (label + ".json")}')
    return record


def bootstrap(out, profile):
    out = out.absolute()
    require(not out.exists() and not out.is_symlink(), f'Output already exists: {out}')
    resolved = out.resolve()
    require(not resolved.is_relative_to(ROOT), 'Output must be external to the repository')
    require(platform.python_version() == RUNTIME['python'] and platform.python_implementation() == 'CPython',
            'Bootstrap requires CPython 3.14.4')
    out.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(('UV_', 'PIP_')) or key in ('PYTHONPATH', 'PYTHONHOME', 'VIRTUAL_ENV'):
            del env[key]
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', UV_OFFLINE='1', UV_NO_CONFIG='1', UV_PYTHON_DOWNLOADS='never', UV_CACHE_DIR=str(out / 'uv-cache'))
    uv = shutil.which('uv') or 'uv'
    version = capture(out, 'setup-uv-version', [uv, '--version'], env)
    require(version['stdout'].split()[:2] == ['uv', RUNTIME['uv']], 'Bootstrap requires uv 0.12.10')
    venv = out / 'venv'
    capture(out, 'setup-venv', [uv, '--offline', 'venv', '--python', sys.executable, str(venv)], env)
    python = venv / 'bin/python'
    argv = [uv, '--offline', 'pip', 'install', '--python', str(python), '--no-index', '--require-hashes', '--only-binary', ':all:']
    for directory in sorted({str(bundle_path(package['wheel']['path']).parent) for package in profile['packages']}):
        argv.extend(['--find-links', directory])
    argv.extend(['-r', str(bundle_path(profile['requirements']['path']))])
    capture(out, 'setup-install', argv, env)
    replay = HERE / 'replay.py'
    capture(out, 'replay', [python, '-B', replay, '--out', out / 'reference'], env)
    capture(out, 'seal-check', [python, '-B', replay, '--check', out / 'reference'], env)
    check_bundle()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='Read-only validation of the bundled profile and frozen history')
    mode.add_argument('--out', type=Path, help='New external output directory (never reused)')
    args = parser.parse_args()
    try:
        profile = check_bundle()
        if args.out is not None:
            bootstrap(args.out, profile)
        print('DNSSEC current offline bundle verified' if args.check else f'DNSSEC current replay verified: {args.out}')
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f'DNSSEC current verification failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
