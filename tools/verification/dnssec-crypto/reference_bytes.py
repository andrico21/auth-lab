#!/usr/bin/env python3
"""Independent limited-fixture byte primitives. No DNS library or generator imports.
Only verification consumes this module; it does not produce expected fixture bytes.
"""
import base64
import hashlib
import ipaddress
import json
import pathlib
import shlex
import struct
import subprocess
import tempfile
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

ROOT=pathlib.Path(__file__).resolve().parents[3]
HERE=pathlib.Path(__file__).resolve().parent
OUT=ROOT/'docs/dnssec-expansion/numeric'
TYPES={'A':1,'NS':2,'CNAME':5,'SOA':6,'MX':15,'TXT':16,'AAAA':28,'DNAME':39,'DS':43,'RRSIG':46,'NSEC':47,'DNSKEY':48,'NSEC3':50,'NSEC3PARAM':51,'CDS':59,'CDNSKEY':60,'CSYNC':62,'ZONEMD':63,'DSYNC':66,'NXNAME':128}
RESULTS=[]

def check(identity,actual,expected):
    if actual!=expected:
        raise AssertionError({'id':identity,'expected':expected,'actual':actual})
    RESULTS.append({'id':identity,'result':'pass'})

def name_wire(name,fold=True):
    if name=='.':
        return b'\0'
    if not name.endswith('.'):
        raise ValueError('Only fully qualified literal fixture names are supported')
    # Only literal ASCII and RFC1035 decimal escapes are needed by these fixtures.
    import re
    labels=[re.sub(rb'\\([0-9]{3})',lambda m:bytes([int(m[1])]),label) for label in name[:-1].encode('ascii').split(b'.')]
    if any(not label or len(label)>63 for label in labels):
        raise ValueError(name)
    return b''.join(bytes([len(label)])+(label.lower() if fold else label) for label in labels)+b'\0'

def bitmap(names):
    windows={}
    for name in names:
        code=int(name[4:]) if name.startswith('TYPE') else TYPES[name]
        window=code//256
        offset=code%256
        data=windows.setdefault(window,bytearray(32))
        data[offset//8]|=128>>(offset%8)
    return b''.join(bytes([window,len(data.rstrip(b'\0'))])+data.rstrip(b'\0') for window,data in sorted(windows.items()))

def rdata(typ,text):
    p=text.split() if typ=='NSEC' else shlex.split(text)
    if typ in ['A','AAAA']:
        return ipaddress.ip_address(text).packed
    if typ in ['DNSKEY','CDNSKEY']:
        return struct.pack('!HBB',*map(int,p[:3]))+base64.b64decode(''.join(p[3:]))
    if typ in ['DS','CDS']:
        return struct.pack('!HBB',*map(int,p[:3]))+bytes.fromhex(''.join(p[3:]))
    if typ=='ZONEMD':
        return struct.pack('!IBB',*map(int,p[:3]))+bytes.fromhex(''.join(p[3:]))
    if typ in ['NS','CNAME','DNAME']:
        return name_wire(p[0])
    if typ=='MX':
        return struct.pack('!H',int(p[0]))+name_wire(p[1])
    if typ=='TXT':
        return b''.join(bytes([len(s.encode('ascii'))])+s.encode('ascii') for s in p)
    if typ=='SOA':
        return name_wire(p[0])+name_wire(p[1])+struct.pack('!IIIII',*map(int,p[2:]))
    if typ=='NSEC':
        # RFC6840 5.1: NSEC next name is NOT folded.
        return name_wire(p[0],fold=False)+bitmap(p[1:])
    if typ=='NSEC3':
        salt=bytes.fromhex(p[3]) if p[3]!='-' else b''
        next_hash=base64.b32hexdecode(p[4]+'='*((-len(p[4]))%8))
        return struct.pack('!BBHB',int(p[0]),int(p[1]),int(p[2]),len(salt))+salt+bytes([len(next_hash)])+next_hash+bitmap(p[5:])
    if typ=='CSYNC':
        return struct.pack('!IH',int(p[0]),int(p[1]))+bitmap(p[2:])
    if typ=='DSYNC':
        return struct.pack('!HBH',TYPES[p[0]],int(p[1]),int(p[2]))+name_wire(p[3],fold=False)
    raise ValueError('Unsupported reference fixture type '+typ)

def canonical(rr,sig):
    owner=rr['owner']
    labels=owner.rstrip('.').split('.') if owner!='.' else []
    if len(labels)>sig['labels']:
        owner='*.'+'.'.join(labels[-sig['labels']:])+'.'
    prefix=struct.pack('!HBBIIIH',sig['typeCovered'],sig['algorithm'],sig['labels'],sig['originalTtl'],sig['expiration'],sig['inception'],sig['keyTag'])+name_wire(sig['signer'])
    records=sorted(set(rdata(rr['type'],r) for r in rr['records']))
    body=b''.join(name_wire(owner)+struct.pack('!HHIH',TYPES[rr['type']],1,sig['originalTtl'],len(data))+data for data in records)
    return prefix+body

def public_key(key):
    data=bytes.fromhex(key['publicKeyHex'])
    if key['algorithm']==13:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),b'\x04'+data)
    if key['algorithm']==15:
        return ed25519.Ed25519PublicKey.from_public_bytes(data)
    raise ValueError('Unsupported fixture signature algorithm')

def signature_der(key,raw):
    return utils.encode_dss_signature(int.from_bytes(raw[:32],'big'),int.from_bytes(raw[32:],'big')) if key['algorithm']==13 else raw

def valid(key,signature,data):
    try:
        public=public_key(key)
        if key['algorithm']==13:
            public.verify(signature_der(key,signature),data,ec.ECDSA(hashes.SHA256()))
        else:
            public.verify(signature,data)
        return True
    except InvalidSignature:
        return False

def openssl_check(identity,key,signature,data,scratch):
    (scratch/'public.pem').write_text(key['publicKeyPem'])
    (scratch/'signature.bin').write_bytes(signature_der(key,signature))
    (scratch/'input.bin').write_bytes(data)
    argv=['openssl','pkeyutl','-verify','-pubin','-inkey',str(scratch/'public.pem'),'-rawin','-in',str(scratch/'input.bin'),'-sigfile',str(scratch/'signature.bin')]
    if key['algorithm']==13:
        argv+=['-digest','sha256']
    result=subprocess.run(argv,text=True,capture_output=True)
    if result.returncode:
        raise RuntimeError({'id':identity,'argv':argv,'exitCode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
    return {'id':identity,'argv':[a.replace(str(scratch),'<scratch>') for a in argv],'exitCode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}

def key_tag(raw):
    total=sum(byte*(256 if index%2==0 else 1) for index,byte in enumerate(raw))
    return (total+(total>>16))&65535

def nsec3(name,iterations,salt):
    data=hashlib.sha1(name_wire(name)+salt).digest()
    initial=data.hex()
    trace=[initial]
    for _ in range(iterations):
        data=hashlib.sha1(data+salt).digest()
        trace.append(data.hex())
    return {'initialHashHex':initial,'hashHex':data.hex(),'hashBase32hex':base64.b32hexencode(data).decode().rstrip('='),'trace':trace}

def serial_order(a,b):
    d=(a-b)&0xffffffff
    return None if d==0x80000000 else (0 if d==0 else (1 if d<0x80000000 else -1))

def time_state(now,inception,expiration):
    duration=(expiration-inception)&0xffffffff
    if duration>=0x80000000:
        return 'undefined-serial-order'
    after=serial_order(now,inception)
    before=serial_order(now,expiration)
    if after is None or before is None:
        return 'undefined-serial-order'
    if after<0:
        return 'not-yet-valid'
    if before>0:
        return 'expired'
    return 'valid'

# Minimal independent DNS-message reader only for the captured MX occurrence vectors.
def wire_name(raw,offset,visited=None):
    visited=set() if visited is None else visited
    if offset in visited:
        raise ValueError('Compression cycle')
    visited.add(offset)
    labels=[]
    while True:
        length=raw[offset]
        offset+=1
        if length==0:
            return '.'.join(labels)+'.',offset
        if length&0xc0==0xc0:
            pointer=((length&63)<<8)|raw[offset]
            suffix,_=wire_name(raw,pointer,visited)
            return '.'.join(labels)+('.' if labels else '')+suffix,offset+1
        if length>63:
            raise ValueError('Invalid label')
        labels.append(raw[offset:offset+length].decode('ascii'))
        offset+=length

def read_mx_message(raw):
    _,_,qd,an,ns,ar=struct.unpack('!HHHHHH',raw[:12])
    offset=12
    for _ in range(qd):
        _,offset=wire_name(raw,offset)
        offset+=4
    records=[]
    owners=[]
    for _ in range(an):
        owner,offset=wire_name(raw,offset)
        typ,cls,ttl,size=struct.unpack('!HHIH',raw[offset:offset+10])
        offset+=10
        if (typ,cls)!=(15,1):
            raise ValueError('Expected IN MX')
        pref=struct.unpack('!H',raw[offset:offset+2])[0]
        exchange,_=wire_name(raw,offset+2)
        records.append(str(pref)+' '+exchange)
        owners.append(owner)
        offset+=size
    if ns or ar or len(set(owners))!=1 or offset!=len(raw):
        raise ValueError('Unexpected message structure')
    return {'owner':owners[0],'ttl':ttl,'type':'MX','records':records}
