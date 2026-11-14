#!/usr/bin/env python3
"""Build self-contained CLI archives; the Go module already embeds native assets."""
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

root = Path(__file__).resolve().parents[1]
subprocess.run(['python3', str(root / 'scripts/check-assets.py')], check=True)
out = root / 'dist'
out.mkdir(exist_ok=True)
checksums = []
for system in ('darwin', 'linux'):
    for arch in ('arm64', 'amd64'):
        with tempfile.TemporaryDirectory(prefix='intent-release-') as temporary:
            binary = Path(temporary) / 'intent'
            subprocess.run(['go', 'build', '-trimpath', '-o', str(binary), './cmd/intent'], cwd=root, env={**os.environ, 'CGO_ENABLED': '0', 'GOOS': system, 'GOARCH': arch}, check=True)
            archive = out / f'intent_{system}_{arch}.tar.gz'
            with tarfile.open(archive, 'w:gz') as package:
                package.add(binary, arcname='intent')
                package.add(root / 'LICENSE', arcname='LICENSE')
                package.add(root / 'README.md', arcname='README.md')
            checksums.append(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name)
(out / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n')
