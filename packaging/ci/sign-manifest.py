#!/usr/bin/env python3
"""Sign the exact bounded native-package manifest; private keys stay in env."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

parser = argparse.ArgumentParser()
parser.add_argument('artifact', type=Path)
parser.add_argument('--platform', required=True)
parser.add_argument('--kind', choices=['deb', 'rpm', 'msi', 'pkg'], required=True)
parser.add_argument('--version', required=True)
parser.add_argument('--sequence', required=True, type=int)
args = parser.parse_args()
manifest = {'schema': 1, 'key_id': os.environ.get('LARISKA_RELEASE_KEY_ID', 'lariska-local-2026-10'),
            'version': args.version, 'platform': args.platform, 'package_kind': args.kind,
            'size_bytes': args.artifact.stat().st_size, 'sha256': hashlib.sha256(args.artifact.read_bytes()).hexdigest(),
            'expires_at': int(time.time()) + 30 * 86400, 'sequence': args.sequence}
key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(os.environ['LARISKA_RELEASE_ED25519_KEY']))
canonical = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
signed = {'manifest': manifest, 'signature': key.sign(canonical).hex()}
args.artifact.with_suffix(args.artifact.suffix + '.manifest.json').write_text(json.dumps(signed, sort_keys=True, separators=(',', ':')) + '\n')
args.artifact.with_suffix(args.artifact.suffix + '.sha256').write_text(f"{manifest['sha256']}  {args.artifact.name}\n")
