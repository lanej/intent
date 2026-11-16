#!/usr/bin/env python3
"""Capture and check the production card without evaluating authentication."""
import argparse
import json
from pathlib import Path
import shutil
import plistlib
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output-dir', type=Path, help='retain PNGs for visual review')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='intent-card-') as temporary:
    stage = Path(temporary)
    app = stage / 'CardCapture.app'
    executable = app / 'Contents/MacOS/CardCapture'
    executable.parent.mkdir(parents=True)
    shutil.copytree(root / 'native/Resources', app / 'Contents/Resources')
    info = plistlib.loads((root / 'native/Info.plist').read_bytes())
    info['CFBundleExecutable'] = 'CardCapture'
    info['CFBundleIdentifier'] = 'dev.joshlane.intent.card-capture'
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
    subprocess.run(['swiftc', '-O', '-o', str(executable), str(root / 'native/Card.swift'), str(root / 'native/tests/CardCapture.swift'), '-framework', 'AppKit', '-framework', 'LocalAuthentication'], check=True)
    subprocess.run(['codesign', '--force', '--sign', '-', str(app)], check=True)
    gate_check = stage / 'approval-gate-check'
    subprocess.run(['swiftc', '-o', str(gate_check), str(root / 'native/ApprovalGate.swift'), str(root / 'native/tests/ApprovalGateCheck.swift')], check=True)
    subprocess.run([str(gate_check)], check=True)
    output = args.output_dir or stage
    output.mkdir(parents=True, exist_ok=True)
    fixture = json.loads((root / 'native/tests/credentials.json').read_text())
    for name, flags in [('light', []), ('dark', ['--dark']), ('plaintext', []), ('bounded', ['--bounded', '--details'])]:
        review = json.loads(json.dumps(fixture))
        if name == 'plaintext':
            review['card']['notice_title'] = 'Plaintext file'
            review['card']['notice'] = 'Render /tmp/test.env as plaintext. The file is readable by this user and removed on lease expiry.'
        if name == 'bounded':
            review['card']['credentials'] = [{'name': f'{i:03d}_' + 'long credential name ' * 6, 'variable': f'KEY_{i:03d}'} for i in range(64)]
            review['details'] = ('Long destination /sample/ ' * 32 + '\n') * 64
        source = stage / (name + '.json')
        source.write_text(json.dumps(review))
        subprocess.run([str(executable), str(source), str(output / (name + '.png')), *flags], check=True)
