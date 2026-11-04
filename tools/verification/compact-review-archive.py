#!/usr/bin/env python3
"""Deterministic ZIP/current-data TAR+XZ creation and checked extraction."""
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
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

def regular(filename, directory=False):
    filename = Path(os.path.abspath(filename))
    current = Path(filename.anchor)
    for index, part in enumerate(filename.parts[1:]):
        current = current / part
        mode = current.lstat().st_mode
        expected = stat.S_ISDIR if index < len(filename.parts) - 2 or directory else stat.S_ISREG
        if stat.S_ISLNK(mode) or not expected(mode):
            raise ValueError('Unsafe filesystem path: ' + str(current))
    return filename


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
elif mode == 'create-xz':
    regular(Path(archive).parent, directory=True)
    with lzma.open(archive, 'xb', format=lzma.FORMAT_XZ, check=lzma.CHECK_SHA256, filters=[{'id': lzma.FILTER_LZMA2, 'preset': 9, 'dict_size': 128 * 1024 * 1024}]) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
            for name in sorted(expected, key=lambda name: (expected[name]['bytes'], PurePosixPath(name).name, name)):
                e = expected[name]
                source = regular(e.get('source', Path(destination) / name))
                data = source.read_bytes()
                if len(data) != e['bytes'] or digest(data) != e['sha256']:
                    raise ValueError('Current data member changed: ' + name)
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                info.uid = info.gid = info.mtime = 0
                tar.addfile(info, io.BytesIO(data))
elif mode == 'extract-xz':
    target = regular(destination, directory=True)
    seen = set()
    with lzma.open(regular(archive), 'rb') as compressed:
        with tarfile.open(fileobj=compressed, mode='r|', ignore_zeros=True) as tar:
            for info in tar:
                name = safe(info.name)
                if name not in expected or name in seen or not info.isfile() or info.pax_headers:
                    raise ValueError('Unexpected, duplicate or nonregular current data member: ' + name)
                e = expected[name]
                if info.size != e['bytes']:
                    raise ValueError('Current data member size differs: ' + name)
                with tar.extractfile(info) as source:
                    data = source.read()
                if len(data) != e['bytes'] or digest(data) != e['sha256']:
                    raise ValueError('Decoded current data member differs: ' + name)
                output = target / name
                parent = target
                for component in PurePosixPath(name).parts[:-1]:
                    parent = parent / component
                    try:
                        parent.mkdir()
                    except FileExistsError:
                        pass
                    regular(parent, directory=True)
                with output.open('xb') as f:
                    f.write(data)
                if digest(output.read_bytes()) != e['sha256']:
                    raise ValueError('Written current data member differs: ' + name)
                seen.add(name)
        while compressed.read(65536):
            pass
    if seen != set(expected):
        raise ValueError('Current data archive inventory differs')
else:
    raise ValueError('Unknown operation')
print(json.dumps({'operation': mode, 'members': len(expected), 'passed': True}))
