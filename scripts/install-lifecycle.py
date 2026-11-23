#!/usr/bin/env python3
"""Publish a verified owner build immutably, then select it atomically."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def private_directory(path):
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if path.is_symlink() or not path.is_dir() or info.st_uid != os.getuid():
        raise ValueError('preserve unexpected installation directory: ' + str(path))
    path.chmod(0o700)


def regular_owned(path):
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_uid != os.getuid():
        raise ValueError('preserve unexpected executable or manifest: ' + str(path))
    return info


def native_old_image(path, tool):
    result = subprocess.run(['go', 'version', '-m', str(path)], capture_output=True, text=True)
    module = 'github.com/lanej/' + tool + '/cmd/' + tool
    return result.returncode == 0 and any(line.split() == ['path', module] for line in result.stdout.splitlines())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool', choices=('intent', 'keylease'), required=True)
    parser.add_argument('--source-bin', type=Path, required=True)
    parser.add_argument('--prefix', type=Path, required=True)
    options = parser.parse_args()
    tool = options.tool
    source = options.source_bin / tool
    manifest = options.source_bin / (tool + '.build.json')
    regular_owned(source)
    regular_owned(manifest)
    record = json.loads(manifest.read_text())
    sha = digest(source)
    if record.get('sha256') != sha or not isinstance(record.get('expected_identity'), str) or not record['expected_identity'].startswith('build:'):
        raise ValueError('selected build identity and byte receipt differ')
    base = options.prefix / 'libexec' / tool
    private_directory(base)
    lock_path = base / '.install.lock'
    if lock_path.is_symlink():
        raise ValueError('preserve unexpected installation lock')
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        releases = base / 'releases'
        private_directory(releases)
        release = releases / sha
        if release.exists() or release.is_symlink():
            regular_owned(release / tool)
            regular_owned(release / (tool + '.build.json'))
            if release.is_symlink() or digest(release / tool) != sha or json.loads((release / (tool + '.build.json')).read_text()) != record:
                raise ValueError('preserve changed immutable release')
        else:
            with tempfile.TemporaryDirectory(prefix='.install-', dir=releases) as temporary:
                stage = Path(temporary)
                shutil.copyfile(source, stage / tool)
                if digest(stage / tool) != sha or json.loads(manifest.read_text()) != record:
                    raise ValueError('build changed while staging; preserve selected installation')
                (stage / tool).chmod(0o500)
                manifest_target = stage / (tool + '.build.json')
                manifest_target.write_text(json.dumps(record) + '\n')
                manifest_target.chmod(0o400)
                for path in (stage / tool, manifest_target):
                    with path.open('rb') as stream:
                        os.fsync(stream.fileno())
                # Rename the completed private release; the temporary context
                # removes only its original, now absent, staging pathname.
                stage.rename(release)
        (release / tool).chmod(0o500)
        (release / (tool + '.build.json')).chmod(0o400)
        release.chmod(0o500)
        selected = options.prefix / 'bin' / tool
        selected.parent.mkdir(parents=True, exist_ok=True)
        original = selected.lstat() if selected.exists() or selected.is_symlink() else None
        if original is not None and not selected.is_symlink():
            regular_owned(selected)
            if not native_old_image(selected, tool):
                raise ValueError('preserve unmanaged executable: ' + str(selected))
            previous_sha = digest(selected)
            previous = releases / ('previous-' + previous_sha)
            if not previous.exists():
                private_directory(previous)
                shutil.copyfile(selected, previous / tool)
                if digest(previous / tool) != previous_sha:
                    raise ValueError('previous executable changed during preservation')
                (previous / tool).chmod(0o500)
                previous.chmod(0o500)
            elif previous.is_symlink() or digest(previous / tool) != previous_sha:
                raise ValueError('preserve changed prior release')
            if selected.lstat() != original or digest(selected) != previous_sha:
                raise ValueError('selected executable changed during preservation')
        link = selected.parent / ('.' + tool + '-install-' + uuid.uuid4().hex)
        try:
            link.symlink_to(release / tool)
            # The native installer serializes its own updates and retains the
            # original regular file's bytes before replacing its selected name.
            link.replace(selected)
        finally:
            link.unlink(missing_ok=True)
    print(json.dumps({'installed_binary': str(selected), 'release': str(release), **record}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
