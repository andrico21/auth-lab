#!/usr/bin/env python3
"""Deterministic ZIP creation and independent, checked extraction (stdlib only)."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile


def safe(name):
    if not isinstance(name, str) or not name or '\\' in name or ':' in name or any(ord(c) < 32 for c in name):
        raise ValueError('Unsafe archive name: ' + repr(name))
    p = PurePosixPath(name)
    if p.is_absolute() or any(c in ('', '.', '..', '.git') for c in name.split('/')):
        raise ValueError('Unsafe archive name: ' + name)
    return name


def digest(data):
    return hashlib.sha256(data).hexdigest()


mode, descriptor_file, archive, destination = sys.argv[1:]
descriptor = json.loads(Path(descriptor_file).read_text())
entries = descriptor['entries']
expected = {safe(e['path']): e for e in entries}
if len(expected) != len(entries) or len({n.casefold() for n in expected}) != len(expected):
    raise ValueError('Duplicate or case-fold-colliding archive members')
if mode == 'create':
    with open(archive, 'xb') as output:
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=True) as z:
            for name in sorted(expected):
                e = expected[name]
                source = Path(destination) / name
                if not stat.S_ISREG(source.lstat().st_mode):
                    raise ValueError('Nonregular staged member: ' + name)
                data = source.read_bytes()
                if len(data) != e['bytes'] or digest(data) != e['sha256']:
                    raise ValueError('Staged member changed: ' + name)
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
elif mode == 'extract':
    target = Path(destination)
    target.mkdir(exist_ok=False)
    with zipfile.ZipFile(archive) as z:
        names = [safe(i.filename) for i in z.infolist()]
        if len(names) != len(set(names)) or len({n.casefold() for n in names}) != len(names) or set(names) != set(expected):
            raise ValueError('Archive inventory differs')
        for info in z.infolist():
            name = safe(info.filename)
            if not stat.S_ISREG(info.external_attr >> 16) or info.is_dir():
                raise ValueError('Nonregular ZIP member: ' + name)
            data = z.read(info)
            e = expected[name]
            if len(data) != e['bytes'] or digest(data) != e['sha256']:
                raise ValueError('Extracted member differs: ' + name)
            output = target / name
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open('xb') as f:
                f.write(data)
            os.chmod(output, 0o644)
else:
    raise ValueError('Unknown operation')
print(json.dumps({'operation': mode, 'members': len(expected), 'passed': True}))
