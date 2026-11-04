#!/usr/bin/env python3
"""Reconstruct exact reviewer snapshots from checked current inputs and overlays."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe(name):
    if not isinstance(name, str) or not name or '\\' in name or ':' in name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError('Unsafe snapshot member: ' + repr(name))
    if PurePosixPath(name).is_absolute() or any(p in ('', '.', '..', '.git') for p in name.split('/')):
        raise ValueError('Unsafe snapshot member: ' + name)
    return name


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


def checked(data, identity, label):
    if len(data) != identity['bytes'] or digest(data) != identity['sha256']:
        raise ValueError('Snapshot byte identity mismatch: ' + label)


def restore_strings(data, entry):
    value = json.loads(data)
    for patch in entry['jsonStringPatches']:
        pointer = patch['pointer']
        if not isinstance(pointer, list) or not pointer or not all(type(p) in (str, int) for p in pointer):
            raise ValueError('Invalid JSON pointer')
        parent = value
        for part in pointer[:-1]:
            if isinstance(parent, list) and (type(part) is not int or part < 0 or part >= len(parent)):
                raise ValueError('Invalid JSON array position')
            parent = parent[part]
        part = pointer[-1]
        if isinstance(parent, list) and (type(part) is not int or part < 0 or part >= len(parent)):
            raise ValueError('Invalid JSON array position')
        if not isinstance(patch['expectedCurrent'], str) or not isinstance(patch['restoreBefore'], str) or parent[part] != patch['expectedCurrent']:
            raise ValueError('Historical string patch precondition failed')
        parent[part] = patch['restoreBefore']
    encoding = entry['serialization']
    if encoding['ensureASCII'] is not False or encoding['preserveObjectMemberOrder'] is not True or encoding.get('indent') not in (None, 2):
        raise ValueError('Unsupported exact JSON serialization')
    separators = tuple(encoding['separators'])
    if separators not in ((',', ':'), (',', ': ')) or type(encoding['trailingLF']) is not bool:
        raise ValueError('Unsupported exact JSON serialization')
    text = json.dumps(value, ensure_ascii=False, indent=encoding.get('indent'), separators=separators)
    return (text + ('\n' if encoding['trailingLF'] else '')).encode('utf8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('overlays', 'recipe', 'out', 'receipt'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    producer = regular(__file__)
    roots = {'current': producer.parents[3], 'overlay': regular(args.overlays, directory=True)}
    recipe_file = regular(args.recipe)
    out = regular(Path(args.out).parent, directory=True) / Path(args.out).name
    receipt_file = regular(Path(args.receipt).parent, directory=True) / Path(args.receipt).name
    for destination in (out, receipt_file):
        if any(destination == root or destination.is_relative_to(root) for root in roots.values()):
            raise ValueError('Output must be outside current source and overlays')
    if receipt_file == out or receipt_file.is_relative_to(out) or out.is_relative_to(receipt_file):
        raise ValueError('Output and receipt must be disjoint')
    with receipt_file.open('x', encoding='utf8') as receipt_stream:
        report = {'schemaVersion': 1, 'kind': 'localization-exact-review-snapshot-reconstruction',
                  'status': 'running', 'approval': False, 'waiver': False,
                  'argv': sys.argv, 'python': sys.version, 'sourceRoot': str(roots['current']),
                  'producer': {'path': str(producer), 'sha256': digest(producer.read_bytes())},
                  'recipe': {'path': str(recipe_file), 'sha256': digest(recipe_file.read_bytes())},
                  'out': str(out), 'files': [], 'errors': [],
                  'qualification': 'Exact snapshot byte restoration only; no functional, language, human or release acceptance.'}
        try:
            recipe = json.loads(recipe_file.read_bytes())
            if recipe['schemaVersion'] != 1 or recipe['kind'] != 'localization-exact-review-snapshots' or not isinstance(recipe['entries'], list) or not recipe['entries']:
                raise ValueError('Invalid snapshot recipe')
            names = [safe(entry['path']) for entry in recipe['entries']]
            if len(set(name.casefold() for name in names)) != len(names):
                raise ValueError('Duplicate or case-fold-colliding snapshot member')
            out.mkdir(mode=0o700)
            inputs = []
            for entry in recipe['entries']:
                root = roots[entry['from']]
                source = regular(root / safe(entry['inputPath']))
                data = source.read_bytes()
                checked(data, entry['input'], entry['inputPath'])
                inputs.append((source, entry['input']))
                restored = restore_strings(data, entry) if 'jsonStringPatches' in entry else data
                checked(restored, entry['output'], entry['path'])
                target = out / entry['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as output:
                    output.write(restored)
                checked(target.read_bytes(), entry['output'], entry['path'])
                report['files'].append({'path': entry['path'], **entry['output']})
            for source, identity in inputs:
                checked(regular(source).read_bytes(), identity, str(source))
            report['status'] = 'passed'
            report['inputBytesUnchanged'] = True
            report['everyWrittenByteChecked'] = True
        except Exception as error:
            report['status'] = 'failed'
            report['errors'].append(type(error).__name__ + ': ' + str(error))
        json.dump(report, receipt_stream, ensure_ascii=False, indent=2)
        receipt_stream.write('\n')
    print(json.dumps({'status': report['status'], 'files': len(report['files']), 'errors': report['errors'], 'receipt': str(receipt_file)}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
