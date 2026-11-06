"""Resolve preserved requirement bytes without creating install manifests."""
from pathlib import PurePosixPath
import json

LEGACY_REQUIREMENTS = 'tools/verification/dnssec-crypto/requirements.txt'


def _archive_descriptor(before):
    name = before['path']
    if not isinstance(name, str) or not name.endswith('.input') or name == before['originalPath']:
        raise ValueError('Historical requirements snapshot must be a distinct inert .input file')
    path = PurePosixPath(name)
    if path.is_absolute() or 'requirements' in path.name.lower() or any(part in ('', '.', '..') for part in name.split('/')):
        raise ValueError('Unsafe historical requirements snapshot path')
    return {key: before[key] for key in ('path', 'bytes', 'sha256')}


def historical_descriptor(row, historical):
    if row['path'] != LEGACY_REQUIREMENTS:
        return row
    before = historical.get('requirementsBefore')
    if not isinstance(before, dict) or set(before) != {'originalPath', 'path', 'bytes', 'sha256'}:
        raise ValueError('Missing exact historical requirements snapshot')
    if before['originalPath'] != row['path'] or any(before[key] != row[key] for key in ('bytes', 'sha256')):
        raise ValueError('Historical requirements snapshot differs from frozen identity')
    return _archive_descriptor(before)


def reference_requirements_descriptor(historical, read_identity):
    before = historical.get('referenceRequirementsBefore')
    if not isinstance(before, dict) or set(before) != {'originalPath', 'path', 'bytes', 'sha256', 'contents'}:
        raise ValueError('Missing exact previous reference requirements snapshot')
    descriptor = _archive_descriptor(before)
    prefix = PurePosixPath(before['contents']['path']).parent
    name = str(PurePosixPath(before['originalPath']).relative_to(prefix))
    contents = json.loads(read_identity(before['contents']))
    matches = [row for row in contents['files'] if row['path'] == name]
    if len(matches) != 1 or any(matches[0][key] != before[key] for key in ('bytes', 'sha256')):
        raise ValueError('Archived reference requirements differ from original seal')
    return descriptor
