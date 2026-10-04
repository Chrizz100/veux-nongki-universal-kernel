#!/usr/bin/env python3
"""Install an authenticated VEUX payload without reverting unknown repo changes."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile


MANIFEST = 'INSTALL_MANIFEST.json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def install(archive_path, root, expected_sha):
    root = Path(root).resolve()
    data = Path(archive_path).read_bytes()
    if sha(data) != expected_sha:
        raise ValueError('ZIP checksum mismatch')
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or archive.testzip() is not None:
            raise ValueError('duplicate ZIP member or invalid CRC')
        manifest = json.loads(archive.read(MANIFEST))
        if manifest.get('schema') != 1 or not isinstance(manifest.get('files'), dict):
            raise ValueError('invalid installation manifest')
        if set(names) != set(manifest['files']) | {MANIFEST}:
            raise ValueError('unexpected ZIP members')
        plans = []
        for name, record in manifest['files'].items():
            relative = PurePosixPath(name)
            if (not name or relative.is_absolute() or '..' in relative.parts or
                    relative.as_posix() != name or '\\' in name or
                    relative.parts[0] not in {'common', 'docs'} or
                    'sweet' in name.lower()):
                raise ValueError('invalid target path: ' + name)
            member = archive.getinfo(name)
            mode = member.external_attr >> 16
            if member.is_dir() or stat.S_ISLNK(mode):
                raise ValueError('payload must contain regular files: ' + name)
            target = root.joinpath(*relative.parts)
            if (target.is_symlink() or not target.resolve().is_relative_to(root) or
                    any(p.is_symlink() for p in target.parents if p != root)):
                raise ValueError('linked target path: ' + name)
            content = archive.read(name)
            after = record['after_sha256']
            if sha(content) != after or record['mode'] not in (0o644, 0o755):
                raise ValueError('invalid payload identity: ' + name)
            if target.exists() and not target.is_file():
                raise ValueError('target is not a regular file: ' + name)
            current = sha(target.read_bytes()) if target.is_file() else None
            if current == after:
                continue
            if current != record['before_sha256']:
                raise ValueError('repo file changed; refusing overwrite: ' + name)
            plans.append((target, content, record['mode']))
        # Validation of every file must finish before the first write.
        for target, content, mode in plans:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(mode)
    return len(plans)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    try:
        count = install(args.archive, args.root, args.sha256)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        parser.exit(1, 'BLOCKED: ' + str(exc) + '\n')
    print('VEUX_INSTALL=PASS; changed_files=' + str(count))


if __name__ == '__main__':
    main()
