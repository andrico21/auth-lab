"""Resolve the original manifest only for historical identity checks."""
from pathlib import PurePosixPath

LEGACY_REQUIREMENTS = 'tools/verification/dnssec-crypto/requirements.txt'


def historical_descriptor(row, historical):
    if row['path'] != LEGACY_REQUIREMENTS:
        return row
    before = historical.get('requirementsBefore')
    if not isinstance(before, dict) or set(before) != {'originalPath', 'path', 'bytes', 'sha256'}:
        raise ValueError('Missing exact historical requirements snapshot')
    if before['originalPath'] != row['path'] or any(before[key] != row[key] for key in ('bytes', 'sha256')):
        raise ValueError('Historical requirements snapshot differs from frozen identity')
    name = before['path']
    if not isinstance(name, str) or not name.endswith('.input.txt') or name == row['path']:
        raise ValueError('Historical requirements snapshot must be an inert .input.txt file')
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ('', '.', '..') for part in name.split('/')):
        raise ValueError('Unsafe historical requirements snapshot path')
    return {key: before[key] for key in ('path', 'bytes', 'sha256')}
