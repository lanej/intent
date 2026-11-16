#!/usr/bin/env python3
"""Build signed SDK assets on macOS; consumers only need the tagged module."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

root = Path(__file__).resolve().parents[1]
source = root / 'native'
manifest = {'source_sha256': hashlib.sha256(b''.join(path.read_bytes() for path in sorted([*source.glob('*.swift'), source / 'Info.plist', *(source / 'Resources').glob('*')]))).hexdigest(), 'assets': {}}
for arch in ('arm64', 'amd64'):
    build = source / 'build' / arch
    if build.exists():
        shutil.rmtree(build)
    app = build / 'Intent.app'
    exe = app / 'Contents/MacOS/Intent'
    exe.parent.mkdir(parents=True)
    target = ('arm64' if arch == 'arm64' else 'x86_64') + '-apple-macos13.0'
    subprocess.run(['swiftc', '-O', '-target', target, '-o', str(exe), *[str(path) for path in sorted(source.glob('*.swift'))], '-framework', 'AppKit', '-framework', 'LocalAuthentication', '-framework', 'Security'], check=True)
    shutil.copyfile(source / 'Info.plist', app / 'Contents/Info.plist')
    shutil.copytree(source / 'Resources', app / 'Contents/Resources')
    subprocess.run(['codesign', '--force', '--sign', '-', str(app)], check=True)
    subprocess.run(['codesign', '--verify', '--strict', str(app)], check=True)
    asset = source / 'assets' / f'darwin-{arch}.zip'
    with zipfile.ZipFile(asset, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(app.rglob('*')):
            if path.is_file():
                info = zipfile.ZipInfo(path.relative_to(build).as_posix(), (2026, 1, 1, 0, 0, 0))
                info.external_attr = (0o100755 if path == exe else 0o100644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, path.read_bytes())
    manifest['assets'][asset.name] = hashlib.sha256(asset.read_bytes()).hexdigest()
(source / 'assets/manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
