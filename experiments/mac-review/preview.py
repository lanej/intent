#!/usr/bin/env python3
"""Build and run the isolated Mac review prototype; no production helper is used."""
import argparse
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, help='Render ten native variants as PNGs and exit')
    parser.add_argument('--build-only', action='store_true')
    args = parser.parse_args()
    if platform.system() != 'Darwin':
        parser.error('The preview requires macOS and Xcode Command Line Tools')
    output = ROOT / '.build/mac-review-preview'
    output.parent.mkdir(exist_ok=True)
    subprocess.run(['xcrun', 'swiftc', '-swift-version', '5', str(ROOT / 'main.swift'),
                    '-target', f'{platform.machine()}-apple-macosx13.0',
                    '-framework', 'AppKit', '-o', str(output)], check=True)
    if args.build_only:
        print(output)
        return
    command = [str(output), str(ROOT)]
    if args.capture:
        command.extend(['--capture', str(args.capture.resolve())])
    subprocess.run(command, check=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
