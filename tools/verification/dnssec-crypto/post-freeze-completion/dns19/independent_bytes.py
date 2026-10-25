#!/usr/bin/env python3
"""Limited independent DNS19 reader/collator. No dns or producer imports."""
import base64
import datetime
import hashlib
import hmac
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
import reference_bytes as ref


def timestamp(text):
    if len(text) == 14:
        return int(datetime.datetime.strptime(text, '%Y%m%d%H%M%S').replace(tzinfo=datetime.timezone.utc).timestamp())
    return int(text)


def rdata_text(typ, text):
    if typ != 'RRSIG':
        return ref.rdata(typ, text)
    p = text.split()
    return (struct.pack('!HBBIIIH', ref.TYPES[p[0]], int(p[1]), int(p[2]), int(p[3]),
                        timestamp(p[4]), timestamp(p[5]), int(p[6]))
            + ref.name_wire(p[7]) + base64.b64decode(''.join(p[8:])))


def text_records(text):
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        owner, ttl, cls, typ, rtext = line.split(None, 4)
        if cls != 'IN':
            raise ValueError('Only complete explicit IN fixture records supported')
        rows.append((owner.lower(), int(ttl), 1, ref.TYPES[typ], rdata_text(typ, rtext)))
    return rows


def canonical_record(record):
    owner, ttl, cls, typ, raw = record
    return ref.name_wire(owner) + struct.pack('!HHIH', typ, cls, ttl, len(raw)) + raw


def zone_input(text, origin='lab.example.'):
    records = set(text_records(text))
    rows = []
    for record in records:
        owner, _, _, typ, raw = record
        if owner == origin and (typ == 63 or (typ == 46 and struct.unpack('!H', raw[:2])[0] == 63)):
            continue
        order = (tuple(reversed(owner.rstrip('.').encode().split(b'.'))), typ, raw)
        rows.append((order, canonical_record(record)))
    return b''.join(raw for _, raw in sorted(rows))


def wire_name(raw, offset, fold=True):
    name, end = ref.wire_name(raw, offset)
    return name.lower() if fold else name, end


def expanded_rdata(raw, offset, size, typ):
    """Expand only name-bearing types used by these fixtures; preserve NSEC next case."""
    end = offset + size
    if size == 0:
        return b''
    if typ in [2, 5]:
        name, pos = wire_name(raw, offset)
        assert pos == end
        return ref.name_wire(name)
    if typ == 15:
        name, pos = wire_name(raw, offset + 2)
        assert pos == end
        return raw[offset:offset + 2] + ref.name_wire(name)
    if typ == 6:
        ns, pos = wire_name(raw, offset)
        mailbox, pos = wire_name(raw, pos)
        assert pos + 20 == end
        return ref.name_wire(ns) + ref.name_wire(mailbox) + raw[pos:end]
    if typ == 46:
        signer, pos = wire_name(raw, offset + 18)
        return raw[offset:offset + 18] + ref.name_wire(signer) + raw[pos:end]
    if typ == 47:
        name, pos = wire_name(raw, offset, fold=False)
        return ref.name_wire(name, fold=False) + raw[pos:end]
    return raw[offset:end]


def read_message(raw):
    mid, flags, qd, an, ns, ar = struct.unpack('!6H', raw[:12])
    pos = 12
    questions = []
    for _ in range(qd):
        owner, pos = wire_name(raw, pos)
        typ, cls = struct.unpack('!HH', raw[pos:pos + 4])
        pos += 4
        questions.append((owner, typ, cls))
    sections = []
    tsig = None
    for section, count in enumerate([an, ns, ar]):
        rows = []
        for index in range(count):
            start = pos
            owner, pos = wire_name(raw, pos)
            typ, cls, ttl, size = struct.unpack('!HHIH', raw[pos:pos + 10])
            pos += 10
            rstart = pos
            end = pos + size
            if typ == 250:
                assert section == 2 and index == count - 1 and tsig is None
                algorithm, cursor = wire_name(raw, pos)
                time_signed = int.from_bytes(raw[cursor:cursor + 6], 'big')
                fudge, macsize = struct.unpack('!HH', raw[cursor + 6:cursor + 10])
                cursor += 10
                mac = raw[cursor:cursor + macsize]
                cursor += macsize
                original, error, otherlen = struct.unpack('!HHH', raw[cursor:cursor + 6])
                cursor += 6
                other = raw[cursor:cursor + otherlen]
                assert cursor + otherlen == end
                tsig = {'owner': owner, 'algorithm': algorithm, 'timeSigned': time_signed, 'fudge': fudge,
                        'mac': mac, 'originalId': original, 'error': error, 'other': other,
                        'start': start, 'rdata': raw[rstart:end], 'class': cls, 'ttl': ttl}
            else:
                rows.append((owner, ttl, cls, typ, expanded_rdata(raw, pos, size, typ)))
            pos = end
        sections.append(rows)
    assert pos == len(raw)
    if tsig:
        unsigned = raw[:10] + struct.pack('!H', ar - 1) + raw[12:tsig['start']]
        unsigned = struct.pack('!H', tsig['originalId']) + unsigned[2:]
    else:
        unsigned = raw
    return {'id': mid, 'flags': flags, 'questions': questions, 'answer': sections[0], 'authority': sections[1],
            'additional': sections[2], 'tsig': tsig, 'unsigned': unsigned}


def mac_input(message, request_mac=b'', prior_mac=b''):
    tsig = message['tsig']
    timers = tsig['timeSigned'].to_bytes(6, 'big') + struct.pack('!H', tsig['fudge'])
    if prior_mac:
        return struct.pack('!H', len(prior_mac)) + prior_mac + message['unsigned'] + timers
    prefix = struct.pack('!H', len(request_mac)) + request_mac if request_mac else b''
    variables = (ref.name_wire(tsig['owner']) + struct.pack('!HI', 255, 0)
                 + ref.name_wire(tsig['algorithm']) + timers
                 + struct.pack('!HH', tsig['error'], len(tsig['other'])) + tsig['other'])
    return prefix + message['unsigned'] + variables


def hmac_secret(keyname):
    return hashlib.sha256(('auth-lab-dns19-postfreeze-tsig:' + keyname).encode()).digest()


def hmac_sha256(keyname, raw):
    return hmac.new(hmac_secret(keyname), raw, hashlib.sha256).digest()


def soa_serial(record):
    assert record[3] == 6
    raw = record[4]
    _, pos = wire_name(raw, 0)
    _, pos = wire_name(raw, pos)
    return struct.unpack('!I', raw[pos:pos + 4])[0]


def apply_transfer(stream, messages):
    """Apply decoded received RRs, never copy resultZoneText into candidate holdings."""
    received = []
    for mid in stream['responseMessageIds']:
        received += messages[mid]['answer']
    assert received[0][3] == 6 and received[-1] == received[0]
    if stream['kind'] != 'ixfr':
        candidate = set(received[:-1])
        return candidate, {'mode': 'complete-zone-replacement', 'receivedRecords': len(received),
                           'resultRecords': len(candidate), 'serial': soa_serial(received[0])}
    holdings = set(text_records(stream['baseZoneText']))
    assert received[1][3] == 6
    assert soa_serial(received[1]) < soa_serial(received[0])
    # One concrete delta is supplied here. Old SOA opens deletion section;
    # new SOA opens addition section; final current SOA closes the sequence.
    new_soa_index = next(index for index in range(2, len(received) - 1) if received[index][3] == 6)
    deleted = received[1:new_soa_index]
    added = received[new_soa_index:-1]
    for record in deleted:
        if record not in holdings:
            raise ValueError('IXFR attempts to delete an absent concrete RR')
        holdings.remove(record)
    for record in added:
        if record in holdings:
            raise ValueError('IXFR attempts to add an already-present concrete RR')
        holdings.add(record)
    return holdings, {'mode': 'actual-delete-add-application', 'baseRecords': len(text_records(stream['baseZoneText'])),
                      'deletedRecords': len(deleted), 'addedRecords': len(added), 'resultRecords': len(holdings),
                      'oldSerial': soa_serial(received[1]), 'serial': soa_serial(received[0]),
                      'deletedRecordWireHex': [canonical_record(r).hex() for r in deleted],
                      'addedRecordWireHex': [canonical_record(r).hex() for r in added]}
