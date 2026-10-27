#!/usr/bin/env python3
"""Compare isolated installed libpam dispatch with source-only expectations.

No /etc writes, real account authentication, host services, password hooks,
resource-limit changes, compiler or development headers are used. Only exact
pam_debug/pam_permit/pam_deny fixtures are admitted. This intentionally probes
cached dispatch even after a prior failure; it never launches any service.

Run from any directory:
  python3 tools/verification/compare-pam-native.py --output /tmp/pam-native.json
Installed package observations are NOT the upstream reference source build.
"""
import argparse
import ctypes
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

REFERENCE_PIN = '584ef2275254016ee68126f90dab6df3604124b9'
ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / 'docs' / 'pam-foundations'
ALLOWED_MODULES = {'pam_debug.so', 'pam_permit.so', 'pam_deny.so'}
LINE = re.compile(r'^(auth|account|password|session)\s+(\[[^\]]+\]|required|requisite|sufficient|optional|include|substack)\s+(\S+)(?:\s+.*)?$')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_record(path):
    real = path.resolve(strict=True)
    data = real.read_bytes()
    return {'requestedPath': str(path), 'resolvedPath': str(real), 'sha256': sha256(data), 'bytes': len(data)}


def package_versions():
    command = ['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\n', 'libpam0g', 'libpam-modules', 'libpam-runtime']
    try:
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        return {'command': command, 'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    except OSError as error:
        return {'command': command, 'unavailable': str(error)}


def compare():
    report = {'retrieved': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'referenceSourcePin': REFERENCE_PIN,
              'evidence': 'Installed Linux-PAM deterministic dispatch comparison only; not source-pin build, distro-default, RFC, Windows, macOS, release or G01 conformance.',
              'packages': package_versions(), 'fixtures': [], 'results': [], 'unavailable': [],
              'excludedScope': ['pam_unix/real-account proof', 'SSSD/provider authority', 'real conversation prompts', 'password token changes', 'pam_limits/real resource mutations', 'host login/sudo/sshd', 'production application launch/admission', 'native coverage of all110 symbolic cases']}
    expected_path = DOCS / 'native-expectations.json'
    configuration_path = DOCS / 'configurations.json'
    expectations_bytes = expected_path.read_bytes()
    manifest_bytes = configuration_path.read_bytes()
    expected = json.loads(expectations_bytes)
    if expected['referencePin'] != REFERENCE_PIN:
        raise ValueError('Native expectations reference pin mismatch')
    report['independentExpectations'] = {'path': str(expected_path.relative_to(ROOT)), 'sha256': sha256(expectations_bytes), 'authorship': expected['authorship']}
    report['configurationManifest'] = {'path': str(configuration_path.relative_to(ROOT)), 'sha256': sha256(manifest_bytes)}
    manifest = {row['id']: row for row in json.loads(manifest_bytes)}
    libraries = [Path('/usr/lib/x86_64-linux-gnu/libpam.so.0'), Path('/lib/x86_64-linux-gnu/libpam.so.0')]
    library = next((path for path in libraries if path.is_file()), None)
    if library is None:
        report['unavailable'].append('Installed x86_64 libpam.so.0 not found at declared Linux paths')
        return report, 2
    report['library'] = file_record(library)
    lib = ctypes.CDLL(report['library']['resolvedPath'])
    if not hasattr(lib, 'pam_start_confdir'):
        report['unavailable'].append('Installed library lacks pam_start_confdir; no fallback to /etc configuration is permitted')
        return report, 2
    report['modules'] = []
    for name in sorted(ALLOWED_MODULES | {'pam_limits.so'}):
        candidates = [Path('/usr/lib/x86_64-linux-gnu/security') / name, Path('/lib/x86_64-linux-gnu/security') / name]
        module = next((path for path in candidates if path.is_file()), None)
        if module is None:
            report['unavailable'].append('Installed module not found: ' + name)
        else:
            report['modules'].append({'name': name, **file_record(module), 'eligibleForExecution': name in ALLOWED_MODULES})
    available_modules = {module['name'] for module in report['modules']}
    if not ALLOWED_MODULES <= available_modules:
        return report, 2

    class Message(ctypes.Structure):
        _fields_ = [('style', ctypes.c_int), ('text', ctypes.c_char_p)]

    class Response(ctypes.Structure):
        _fields_ = [('text', ctypes.c_void_p), ('returncode', ctypes.c_int)]

    Callback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(Message)), ctypes.POINTER(ctypes.POINTER(Response)), ctypes.c_void_p)

    class Conversation(ctypes.Structure):
        _fields_ = [('callback', Callback), ('data', ctypes.c_void_p)]

    libc = ctypes.CDLL(None)
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.calloc.restype = ctypes.c_void_p
    current_service = None
    report['conversations'] = []

    @Callback
    def conversation_callback(count, messages, responses, data):
        responses[0] = ctypes.POINTER(Response)()
        if count <= 0 or count > 64:
            return 19
        observed = [{'style': messages[index].contents.style, 'text': (messages[index].contents.text or b'').decode(errors='replace')} for index in range(count)]
        report['conversations'].append({'service': current_service, 'messages': observed, 'policy': 'Informational/debug messages only; credential prompts are refused'})
        if any(message['style'] not in (3, 4) for message in observed):
            return 19
        memory = libc.calloc(count, ctypes.sizeof(Response))
        if not memory:
            return 5
        # Successful conversation responses are allocated by libc and ownership
        # passes to PAM, which frees them. Informational entries contain NULL.
        responses[0] = ctypes.cast(memory, ctypes.POINTER(Response))
        return 0

    lib.pam_start_confdir.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(Conversation), ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.pam_start_confdir.restype = ctypes.c_int
    lib.pam_strerror.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.pam_strerror.restype = ctypes.c_char_p
    for name in ['pam_authenticate', 'pam_setcred', 'pam_acct_mgmt', 'pam_open_session', 'pam_close_session', 'pam_end']:
        getattr(lib, name).argtypes = [ctypes.c_void_p, ctypes.c_int]
        getattr(lib, name).restype = ctypes.c_int
    inverse_statuses = {number: name for name, number in expected['statusABI'].items()}
    prepared = {}
    visiting = set()

    def prepare(service):
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]*', service):
            raise ValueError('Unsafe fixture service identifier: ' + service)
        if service in prepared:
            return
        if service in visiting:
            raise ValueError('Recursive include/substack fixture: ' + service)
        visiting.add(service)
        row = manifest[service]
        path = ROOT / row['snapshot']
        if path.is_symlink() or path.parent != DOCS / 'configs':
            raise ValueError('Fixture must be a physical file in the authored configs directory')
        data = path.read_bytes()
        if sha256(data) != row['sha256']:
            raise ValueError('Fixture checksum mismatch: ' + service)
        for line_number, line in enumerate(data.decode().splitlines(), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            match = LINE.fullmatch(line)
            if not match:
                raise ValueError('Unsupported fixture syntax: ' + service + ':' + str(line_number))
            _, control, module = match.groups()
            if control in {'include', 'substack'}:
                prepare(module)
            elif module not in ALLOWED_MODULES:
                raise ValueError('Refusing nondeterministic or real-account module: ' + module)
        visiting.remove(service)
        prepared[service] = data
        report['fixtures'].append({'service': service, 'source': str(path.relative_to(ROOT)), 'sha256': sha256(data), 'bytes': len(data)})

    for vector in expected['vectors']:
        prepare(vector['service'])
    passed = failed = 0
    with tempfile.TemporaryDirectory(prefix='afs-pam-native-') as directory:
        report['temporaryConfiguration'] = {'isolation': 'Private temporary directory passed to pam_start_confdir; never /etc/pam.d', 'removedAtExit': True}
        for service, data in prepared.items():
            destination = Path(directory) / service
            with destination.open('xb') as stream:
                stream.write(data)
        for vector in expected['vectors']:
            handle = ctypes.c_void_p()
            # pam_debug emits informational pam_info messages. They get empty
            # responses; this helper refuses every credential-input prompt.
            current_service = vector['service']
            conversation = Conversation(conversation_callback, None)
            status = lib.pam_start_confdir(vector['service'].encode(), b'afs-dispatch-fixture', ctypes.byref(conversation), directory.encode(), ctypes.byref(handle))
            start = {'service': vector['service'], 'api': 'pam_start_confdir', 'flags': 0, 'actual': status, 'actualName': inverse_statuses.get(status), 'expected': 'PAM_SUCCESS', 'matches': status == 0}
            report['results'].append(start)
            passed += int(start['matches'])
            failed += int(not start['matches'])
            if status:
                report['unavailable'].append('Cannot initialize isolated service: ' + vector['service'])
                continue
            try:
                for call in vector['calls']:
                    status = getattr(lib, call['api'])(handle, call['flags'])
                    matches = status == expected['statusABI'][call['expected']]
                    record = {'service': vector['service'], 'api': call['api'], 'flags': call['flags'], 'actual': status, 'actualName': inverse_statuses.get(status), 'message': lib.pam_strerror(handle, status).decode(), 'expected': call['expected'], 'matches': matches}
                    report['results'].append(record)
                    passed += int(matches)
                    failed += int(not matches)
            finally:
                ended = lib.pam_end(handle, status)
                matches = ended == expected['statusABI'][vector['expectedEnd']]
                report['results'].append({'service': vector['service'], 'api': 'pam_end', 'actual': ended, 'actualName': inverse_statuses.get(ended), 'expected': vector['expectedEnd'], 'matches': matches})
                passed += int(matches)
                failed += int(not matches)
    report['summary'] = {'services': len(expected['vectors']), 'physicalFixtures': len(prepared), 'matchedCalls': passed, 'mismatchedCalls': failed, 'scope': 'Only actual calls above; no inferred native acceptance of symbolic cases'}
    return report, 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Create a new JSON report; refuses to overwrite existing evidence')
    args = parser.parse_args()
    try:
        report, status = compare()
    except Exception as error:
        report, status = {'referenceSourcePin': REFERENCE_PIN, 'error': type(error).__name__ + ': ' + str(error), 'nativeAccepted': False}, 2
    text = json.dumps(report, indent=2) + '\n'
    if args.output:
        with args.output.open('x', encoding='utf-8') as stream:
            stream.write(text)
    sys.stdout.write(text)
    return status


if __name__ == '__main__':
    raise SystemExit(main())
