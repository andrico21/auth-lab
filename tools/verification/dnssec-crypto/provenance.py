#!/usr/bin/env python3
"""Capture runtime identities and exact bundled license bytes from pinned source archives."""
import hashlib
import importlib.metadata
import json
import pathlib
import platform
import subprocess
import sys
import tarfile
from cryptography.hazmat.backends.openssl.backend import backend
ROOT=pathlib.Path(__file__).resolve().parents[3]
OUT=ROOT/'docs/dnssec-expansion/numeric'
licenses=[]
for package,version in [('dnspython','2.8.0'),('cryptography','46.0.3'),('cffi','2.1.1'),('pycparser','3.12')]:
    archive=OUT/f'dependencies/{package}-{version}.tar.gz'
    with tarfile.open(archive,'r:gz') as source:
        for member in source.getmembers():
            parts=pathlib.PurePosixPath(member.name).parts
            if not member.isfile() or len(parts)>3 or not any(parts[-1].upper().startswith(prefix) for prefix in ['LICENSE','COPYING','COPYRIGHT']):
                continue
            if member.size>1048576:
                raise ValueError('Unexpected license size')
            data=source.extractfile(member).read()
            dest=OUT/'licenses'/(package+'-'+version+'-'+'-'.join(parts[1:]).replace('.','-')+'.txt')
            dest.parent.mkdir(exist_ok=True)
            if dest.exists() and dest.read_bytes()!=data:
                raise RuntimeError('Immutable license identity changed')
            if not dest.exists():
                dest.write_bytes(data)
            licenses.append({'package':package,'version':version,'sourceArchive':str(archive.relative_to(OUT)),'archiveMember':member.name,
              'path':str(dest.relative_to(OUT)),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    if not any(item['package']==package for item in licenses):
        raise RuntimeError('Missing source license '+package)
versions={name:importlib.metadata.version(name) for name in ['dnspython','cryptography','cffi','pycparser']}
row={'schemaVersion':1,'kind':'dnssec-reference-runtime-and-license-identities','producer':'tools/verification/dnssec-crypto/provenance.py',
 'python':{'version':platform.python_version(),'implementation':platform.python_implementation(),'build':platform.python_build(),'compiler':platform.python_compiler()},
 'platform':{'system':platform.system(),'machine':platform.machine(),'libc':platform.libc_ver()},'dependencies':versions,
 'uv':subprocess.check_output(['uv','--version'],text=True).strip(),'opensslCli':subprocess.check_output(['openssl','version'],text=True).strip(),
 'cryptographyBackend':backend.openssl_version_text(),'licenses':licenses,
 'offlineScope':{'dependencyWheelsBundled':True,'dependencySourceArchivesBundled':True,'licenseBytesBundled':True,
 'freshVenvNoIndexInstallExecuted':'runs/run-010.json','freshVenvGenerationExecuted':['runs/run-011.json','runs/run-013.json','runs/run-014.json'],
 'freshVenvVerificationExecuted':['runs/run-012.json','runs/run-015.json','runs/run-016.json'],
 'platform':'Linux x86_64 CPython3.14, cryptography abi3 manylinux2.34 and cffi cp314 manylinux2.17 wheels',
 'notBundled':['CPython interpreter','uv executable','system OpenSSL executable/library','OS runtime'],
 'notClaimed':['Cross-platform offline installation','source archive rebuild of cryptography/Rust dependencies','live DNS or server interoperability']}}
raw=(json.dumps(row,indent=2,sort_keys=True)+'\n').encode()
path=OUT/'runtime-and-licenses.json'
if path.exists() and path.read_bytes()!=raw:
    raise RuntimeError('Runtime identity changed; retain prior capture')
if not path.exists():
    path.write_bytes(raw)
print(json.dumps({'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(raw).hexdigest(),'licenseFiles':len(licenses),'versions':versions,'backend':row['cryptographyBackend']},indent=2))
