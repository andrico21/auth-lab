"""Offline fixture derivation only, not the Bun validator or an authentication API.
Prints deterministic JSON. Uses independent Python integer point arithmetic and
Python/OpenSSL hashes/AES/DER serialization, never the JavaScript implementation.
Official scalars come from RFC 9382/9383; the certificate is RFC 7517 Appendix B.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parent
load = lambda name: json.loads((ROOT / 'fixtures' / name).read_text())
P = int('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff', 16)
Q = int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16)
B = int('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b', 16)
G = (int('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 16), int('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 16))

def decode(s):
    raw = bytes.fromhex(s)
    if raw[0] == 4:
        return int.from_bytes(raw[1:33], 'big'), int.from_bytes(raw[33:], 'big')
    x = int.from_bytes(raw[1:], 'big')
    y = pow((x*x*x - 3*x + B) % P, (P+1)//4, P)
    if y % 2 != raw[0] % 2:
        y = P - y
    return x, y

M = decode('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f')
N = decode('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49')

def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1+y2) % P == 0:
        return None
    slope = ((3*x1*x1-3) * pow(2*y1, -1, P) if a == b else (y2-y1) * pow(x2-x1, -1, P)) % P
    x3 = (slope*slope-x1-x2) % P
    return x3, (slope*(x1-x3)-y1) % P

def mul(n, a):
    result = None
    n %= Q
    while n:
        if n & 1:
            result = add(result, a)
        a = add(a, a)
        n >>= 1
    return result

def sub(a, b):
    return add(a, (b[0], -b[1] % P))

def enc(p):
    return b'\x04' + p[0].to_bytes(32, 'big') + p[1].to_bytes(32, 'big')

def frame(*items):
    return b''.join(len(v).to_bytes(8, 'little')+v for v in items)

def hkdf(ikm, info, size):
    prk = hmac.digest(bytes(32), ikm, 'sha256')
    out, block = b'', b''
    for counter in range(1, (size+31)//32+1):
        block = hmac.digest(prk, block+info.encode()+bytes([counter]), 'sha256')
        out += block
    return out[:size]

def balanced(f, mismatch=False, identity=None):
    w, x, y = (int(f[k],16) for k in ['w','x','y'])
    wa, wb = w+int(mismatch), w
    pa, pb = add(mul(x,G),mul(wa,M)), add(mul(y,G),mul(wb,N))
    result = {}
    for role, k, scalar in [('A',mul(x,sub(pb,mul(wa,N))),wa),('B',mul(y,sub(pa,mul(wb,M))),wb)]:
        binding = identity if role == 'A' and identity is not None else f['B']
        tt = frame(f['A'].encode(), binding.encode(), enc(pa), enc(pb), enc(k), scalar.to_bytes(32,'big'))
        digest = hashlib.sha256(tt).digest()
        kc = hkdf(digest[16:], 'ConfirmationKeys', 32)
        result[role] = {'K':enc(k).hex(), 'TT':tt.hex(), 'Ke':digest[:16].hex(), 'Ka':digest[16:].hex(), 'KcA':kc[:16].hex(), 'KcB':kc[16:].hex(), 'cA':hmac.digest(kc[:16],tt,'sha256').hex(), 'cB':hmac.digest(kc[16:],tt,'sha256').hex()}
    return result

def augmented(f, mismatch=False, context=None):
    w0, w1, x, y = (int(f[k],16) for k in ['w0','w1','x','y'])
    wp, wv, wp1 = w0+int(mismatch), w0, w1+int(mismatch)
    xp, yv = add(mul(x,G),mul(wp,M)), add(mul(y,G),mul(wv,N))
    base = sub(yv,mul(wp,N))
    values = [('P',mul(x,base),mul(wp1,base),wp), ('V',mul(y,sub(xp,mul(wv,M))),mul(y,decode(f['L'])),wv)]
    result = {}
    for role, z, v, scalar in values:
        binding = context if role == 'P' and context is not None else f['context']
        tt = frame(binding.encode(), f['idProver'].encode(), f['idVerifier'].encode(),enc(M),enc(N),enc(xp),enc(yv),enc(z),enc(v),scalar.to_bytes(32,'big'))
        main = hashlib.sha256(tt).digest()
        kc = hkdf(main,'ConfirmationKeys',64)
        result[role] = {'Z':enc(z).hex(),'V':enc(v).hex(),'TT':tt.hex(),'K_main':main.hex(),'K_confirmP':kc[:32].hex(),'K_confirmV':kc[32:].hex(),'confirmP':hmac.digest(kc[:32],enc(yv),'sha256').hex(),'confirmV':hmac.digest(kc[32:],enc(xp),'sha256').hex(),'K_shared':hkdf(main,'SharedKey',32).hex()}
    return result

def nfold(data, size):
    import math
    bits = len(data)*8
    length = math.lcm(bits,size*8)
    rotations = []
    value = int.from_bytes(data,'big')
    mask = (1 << bits)-1
    shift = 13 % bits
    for i in range(length//bits):
        rotations.append(value.to_bytes(len(data),'big'))
        value = ((value >> shift) | (value << (bits-shift))) & mask
    expanded = b''.join(rotations)
    total = sum(int.from_bytes(expanded[i:i+size],'big') for i in range(0,len(expanded),size))
    mask = (1 << (size*8))-1
    while total > mask:
        total = (total & mask) + (total >> (size*8))
    return total.to_bytes(size,'big')

def dk(key, constant):
    block = nfold(constant,16)
    encryptor = Cipher(algorithms.AES(key),modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()

def kerberos_factor(f, key=None):
    key = bytes.fromhex(f["K'[1]"]) if key is None else key
    clear = bytes(range(16)) + bytes.fromhex('3005a003020101')
    ke = dk(key,(65).to_bytes(4,'big')+b'\xaa')
    ki = dk(key,(65).to_bytes(4,'big')+b'\x55')
    encryptor = Cipher(algorithms.AES(ke),modes.CBC(bytes(16))).encryptor()
    cbc = encryptor.update(clear+bytes(32-len(clear)))+encryptor.finalize()
    return {'confounder':bytes(range(16)).hex(),'plaintext':'3005a003020101','usage':65,'protectedFactor':(cbc[16:]+cbc[:len(clear)-16]+hmac.digest(ki,clear,'sha1')[:12]).hex()}

EP = (1 << 255)-19
EQ = (1 << 252)+27742317777372353535851937790883648493
ED = -121665 * pow(121666, -1, EP) % EP

def eddecode(s):
    raw = int.from_bytes(bytes.fromhex(s), 'little')
    sign, y = raw >> 255, raw & ((1 << 255)-1)
    x2 = (y*y-1) * pow(ED*y*y+1, -1, EP) % EP
    x = pow(x2, (EP+3)//8, EP)
    if x*x % EP != x2:
        x = x * pow(2, (EP-1)//4, EP) % EP
    if x % 2 != sign:
        x = EP-x
    return x, y

def edadd(a, b):
    x, y = a
    z, t = b
    common = ED*x*z*y*t % EP
    return ((x*t+y*z)*pow(1+common,-1,EP) % EP,
            (y*t+x*z)*pow(1-common,-1,EP) % EP)

def edmul(n, point):
    result = (0, 1)
    n %= EQ
    while n:
        if n & 1:
            result = edadd(result, point)
        point = edadd(point, point)
        n >>= 1
    return result

def edsub(a, b):
    return edadd(a, (-b[0] % EP, b[1]))

def edenc(point):
    return (point[1] | ((point[0] % 2) << 255)).to_bytes(32, 'little')

def prfplus(key, pepper, size):
    out = b''
    for counter in range(1, (size+15)//16+1):
        block = hashlib.sha1(bytes([counter])+pepper).digest()[:16]
        cipher = Cipher(algorithms.AES(dk(key,b'prf')),modes.ECB()).encryptor()
        out += cipher.update(block)+cipher.finalize()
    return out[:size]

def kerb_negative(f, wrong_password=False, wrong_body=False):
    key = dk(hashlib.pbkdf2_hmac('sha1',f['password'].encode(),f['salt'].encode(),f['iterations'],16),b'kerberos')
    client_key = dk(hashlib.pbkdf2_hmac('sha1',(f['password']+('!' if wrong_password else '')).encode(),f['salt'].encode(),f['iterations'],16),b'kerberos')
    pepper = b'SPAKEsecret'+(1).to_bytes(4,'big')
    w, cw = prfplus(key,pepper,32), prfplus(client_key,pepper,32)
    wn, cwn = int.from_bytes(w,'little') % EQ, int.from_bytes(cw,'little') % EQ
    g = eddecode('5866666666666666666666666666666666666666666666666666666666666666')
    m = eddecode('d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf')
    n = eddecode('d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab')
    x, y = (int.from_bytes(bytes.fromhex(f[k]),'little') for k in ['x','y'])
    t, s = edadd(edmul(x,g),edmul(wn,m)), edadd(edmul(y,g),edmul(cwn,n))
    kk, ck = edmul(x,edsub(s,edmul(wn,n))), edmul(y,edsub(t,edmul(cwn,m)))
    challenge = bytes.fromhex('a1363034a003020101a1220420')+edenc(t)+bytes.fromhex('a20930073005a003020101')
    thash = hashlib.sha256(hashlib.sha256(bytes(32)+bytes.fromhex(f['SPAKESupport'])+challenge).digest()+edenc(s)).digest()
    result = {}
    for role, basekey, wbytes, shared in [('KDC',key,w,kk),('client',client_key,cw,ck)]:
        body = bytes.fromhex(f['KDC-REQ-BODY'])
        if wrong_body and role == 'client':
            body = body[:-1]+bytes([body[-1]^1])
        keys = []
        for i in range(4):
            digest = hashlib.sha256(b'SPAKEkey'+(1).to_bytes(4,'big')+(17).to_bytes(4,'big')+wbytes+edenc(shared)+thash+body+i.to_bytes(4,'big')+b'\x01').digest()[:16]
            left, right = prfplus(basekey,b'SPAKE',16), prfplus(digest,b'keyderiv',16)
            keys.append(bytes(a^b for a,b in zip(left,right)))
        result[role] = {'K':edenc(shared).hex(),'keys':[key.hex() for key in keys],'protectedFactor':kerberos_factor(f,keys[1])['protectedFactor']}
    return result

def credssp(f):
    cert_der = base64.b64decode(f['certificateBase64'])
    cert = x509.load_der_x509_certificate(cert_der)
    pub = cert.public_key()
    subject = pub.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.PKCS1)
    spki = pub.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    nonce = bytes.fromhex(f['nonceHex'])
    c = b'CredSSP Client-To-Server Binding Hash\0'
    s = b'CredSSP Server-To-Client Binding Hash\0'
    digest = lambda magic, n=nonce, key=subject: hashlib.sha256(magic+n+key).hexdigest()
    return {'id':f['id'],'nonce':nonce.hex(),'subjectPublicKey':subject.hex(),'spki':spki.hex(),'certificate':cert_der.hex(),'clientToServer':digest(c),'serverToClient':digest(s),'missingNul':digest(c[:-1]),'wrongNonce':digest(c,bytes([nonce[0]^1])+nonce[1:]),'spkiSubstitution':digest(c,key=spki),'certificateSubstitution':digest(c,key=cert_der),'thumbprintSubstitution':digest(c,key=hashlib.sha256(cert_der).digest())}

b, a, k = load('rfc9382.json'), load('rfc9383.json'), load('rfc9588.json')
result = {'derivation':{'generator':'derive-synthetic.py','python':'3 stdlib integer arithmetic/hashlib/hmac; cryptography OpenSSL serialization/AES','cryptographyVersion':cryptography.__version__,'inputPolicy':'Fixed published example inputs and exact controlled deltas; no randomness, secrets, sockets or password input API'},'rfc9382':{'passwordMismatch':balanced(b,True),'transcriptMismatch':balanced(b,identity='client-altered')},'rfc9383':{'passwordMismatch':augmented(a,True),'transcriptMismatch':augmented(a,context=a['context']+' altered')},'kerberos':kerberos_factor(k),'credssp':credssp(load('credssp-public-input.json'))}
result['derivation']['inputSha256'] = {name:hashlib.sha256((ROOT / 'fixtures' / name).read_bytes()).hexdigest() for name in ['rfc9382.json','rfc9383.json','rfc9588.json','credssp-public-input.json']}
result['derivation']['transcriptBindings'] = {'rfc9382':{'A.B':'client-altered','B.B':b['B'],'firstConfirmation':'A.cA -> B.cA expectation'},'rfc9383':{'P.Context':a['context']+' altered','V.Context':a['context'],'firstConfirmation':'V.confirmV -> P.confirmV expectation'}}
result['kerberos']['passwordMismatch'] = kerb_negative(k, wrong_password=True)
result['kerberos']['transcriptMismatch'] = kerb_negative(k, wrong_body=True)
print(json.dumps(result,indent=2))
