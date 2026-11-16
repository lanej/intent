#!/usr/bin/env python3
"""Check tagged SDK assets against their committed source and digest manifest."""
import hashlib
import json
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parents[1] / 'native'
manifest = json.loads((root / 'assets/manifest.json').read_text())
assert manifest['source_sha256'] == hashlib.sha256(b''.join(path.read_bytes() for path in sorted([*root.glob('*.swift'), root / 'Info.plist', *(root / 'Resources').glob('*')]))).hexdigest(), 'Rebuild embedded native assets after changing their source'
assert set(manifest['assets']) == {'darwin-arm64.zip', 'darwin-amd64.zip'}
for name, digest in manifest['assets'].items():
    asset = root / 'assets' / name
    assert digest == hashlib.sha256(asset.read_bytes()).hexdigest(), f'Asset digest mismatch: {name}'
    with zipfile.ZipFile(asset) as archive:
        names = set(archive.namelist())
        assert names == {'Intent.app/Contents/Info.plist', 'Intent.app/Contents/MacOS/Intent', 'Intent.app/Contents/_CodeSignature/CodeResources'} | {'Intent.app/Contents/Resources/' + path.name for path in (root / 'Resources').glob('*')}, names
        for path in (root / 'Resources').glob('*'):
            assert archive.read('Intent.app/Contents/Resources/' + path.name) == path.read_bytes()
        assert (archive.getinfo('Intent.app/Contents/MacOS/Intent').external_attr >> 16) & 0o111
        assert archive.read('Intent.app/Contents/Info.plist') == (root / 'Info.plist').read_bytes()
print('Embedded helper source and assets agree')
