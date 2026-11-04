"""Bind separately captured licence bytes to their upstream Git blob and tree."""
import hashlib
import json


def validate_license_binding(license_row, data, tree_data):
    blob = hashlib.sha1(b'blob %d\0' % len(data))
    blob.update(data)
    if blob.hexdigest() != license_row['upstreamBlob']:
        raise ValueError('Upstream license blob mismatch')
    tree = json.loads(tree_data)
    if tree.get('sha') != license_row['upstreamTree'] or not any(
            entry.get('path') == 'LICENSE' and entry.get('type') == 'blob'
            and entry.get('sha') == license_row['upstreamBlob'] for entry in tree.get('tree', [])):
        raise ValueError('Upstream license tree mismatch')
