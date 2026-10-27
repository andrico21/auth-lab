#!/usr/bin/env python3
"""Shared paths, strict runtime requirements and immutable current input identities.

This module is stdlib-only so bundle/seal checks work without installed packages.
"""
import hashlib
import importlib.metadata
import json
import os
import pathlib
import platform
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[3]
TOOLS = pathlib.Path(__file__).resolve().parent
HISTORICAL_TOOLS = ROOT / 'tools/verification/dnssec-crypto'
HISTORICAL = ROOT / 'docs/dnssec-expansion/numeric'
EXPECTED_RUNTIME = {'python': '3.14.4', 'uv': '0.12.10', 'platform': 'Linux', 'machine': 'x86_64',
                    'packages': {'dnspython': '2.8.0', 'cryptography': '50.0.0', 'cffi': '2.1.1', 'pycparser': '3.12'}}


def load_profile():
    profile = json.loads((TOOLS / 'profile.json').read_text())
    if profile.get('schemaVersion') != 1 or profile.get('kind') != 'dnssec-current-offline-crypto-profile':
        raise RuntimeError('Unsupported current profile')
    if profile['runtime'] != EXPECTED_RUNTIME:
        raise RuntimeError('Current profile runtime differs from maintained implementation')
    return profile


def safe_relative(value):
    path = pathlib.PurePosixPath(value)
    if not value or path.is_absolute() or '..' in path.parts or str(path) != value:
        raise RuntimeError('Unsafe identity path: ' + str(value))
    return path


def regular_file(base, name):
    path = base
    for part in safe_relative(name).parts:
        path = path / part
        if path.is_symlink():
            raise RuntimeError('Symlink in identity path: ' + str(path))
    if not path.is_file():
        raise RuntimeError('Missing regular payload: ' + str(path))
    return path


def identity(path, base=None):
    data = path.read_bytes()
    return {'path': str(path.relative_to(base)) if base is not None else reference_path(path),
            'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def verify_identity(base, row):
    path = regular_file(base, row['path'])
    actual = identity(path, base)
    if actual != {key: row[key] for key in ('path', 'bytes', 'sha256')}:
        raise RuntimeError('Payload identity mismatch: ' + row['path'])
    return path


def validate_bundle():
    profile = load_profile()
    verify_identity(ROOT, profile['requirements'])
    if {p['name']: p['version'] for p in profile['packages']} != EXPECTED_RUNTIME['packages']:
        raise RuntimeError('Package profile does not match current runtime')
    for package in profile['packages']:
        for kind in ('wheel', 'source', 'metadata'):
            verify_identity(ROOT, package[kind])
        metadata = json.loads((ROOT / package['metadata']['path']).read_text())
        if metadata['info']['version'] != package['version']:
            raise RuntimeError('PyPI metadata version mismatch: ' + package['name'])
        for kind in ('wheel', 'source'):
            row = package[kind]
            candidates = [entry for entry in metadata['urls'] if entry['filename'] == pathlib.PurePosixPath(row['path']).name]
            if len(candidates) != 1 or candidates[0]['digests']['sha256'] != row['sha256'] or candidates[0]['size'] != row['bytes'] or candidates[0]['url'] != row['url']:
                raise RuntimeError('Artifact is not bound to captured PyPI metadata: ' + row['path'])
    for row in profile['historical']['authorities'] + profile['historical']['files']:
        verify_identity(ROOT, row)
    freeze_path = ROOT / 'docs/dnssec-expansion/contract-freeze.json'
    freeze_bytes = freeze_path.read_bytes()
    if hashlib.sha256(freeze_bytes).hexdigest() != 'b8ee8034a613e70c78a1f007b30a7d20b9d18e80ea84f9472bd2117e6044ad19':
        raise RuntimeError('Original freeze authority changed')
    for row in json.loads(freeze_bytes)['inputs']:
        verify_identity(ROOT, row)
    return profile


def require_runtime():
    if not __debug__:
        raise RuntimeError('Python optimization disables mathematical assertions')
    observed = {'python': platform.python_version(), 'uv': subprocess.check_output(['uv', '--version'], text=True).strip().split()[1],
                'platform': platform.system(), 'machine': platform.machine(),
                'packages': {name: importlib.metadata.version(name) for name in EXPECTED_RUNTIME['packages']}}
    if observed != EXPECTED_RUNTIME:
        raise RuntimeError('Unsupported current runtime: ' + repr(observed))
    return observed


def output_root():
    value = os.environ.get('AUTH_LAB_DNSSEC_CURRENT_OUT')
    if not value:
        raise RuntimeError('AUTH_LAB_DNSSEC_CURRENT_OUT must name the fresh external output')
    path = pathlib.Path(value).absolute()
    if path.is_symlink() or path.resolve() != path:
        raise RuntimeError('Current output must not traverse symlinks')
    if path == ROOT or ROOT in path.parents:
        raise RuntimeError('Generation inside repository is forbidden')
    if not path.is_dir():
        raise RuntimeError('Replay must create the output directory first')
    return path


def reference_path(path):
    # Provenance paths are relative to the repository cwd, including external
    # execution inputs. Sealed CONTENTS identities instead use output-relative paths.
    return os.path.relpath(path, ROOT)


def generated_hash(name):
    out = output_root()
    rows = json.loads((out / 'GENERATED-INPUTS.json').read_text())['files']
    matches = [row for row in rows if row['path'] == name]
    if len(matches) != 1:
        raise RuntimeError('Input is absent from pre-verification snapshot: ' + name)
    verify_identity(out, matches[0])
    return matches[0]['sha256']
