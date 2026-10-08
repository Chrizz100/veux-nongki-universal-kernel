#!/usr/bin/env python3
"""Build and package the VEUX external RMNET pair against this exact kernel.

No historic config/symbol CRC lock. No force load, vendor overlay, property write,
module hiding or kernel source changes. Runtime is supplied by the same AK3.
"""
from __future__ import annotations
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import shutil
import struct
import subprocess
import zipfile

KERNEL = '5.4.274'
PAIR = {'rmnet_offload': 'offload', 'rmnet_shs': 'shs'}
ASSETS = Path(__file__).resolve().parents[1] / 'runtime/veux-rmnet'
FORMAT = 'veux-rmnet-v1'


def require(condition, message):
    if not condition:
        raise ValueError('RMNET: ' + message)


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else Path(value).read_bytes()).hexdigest()



def requested(targets, label):
    names = targets.get('rmnet_required', [KERNEL] if targets.get('candidate_manual_build') is True else [])
    require(isinstance(names, list) and all(isinstance(x, str) for x in names)
            and len(names) == len(set(names)) and set(names) <= {KERNEL},
            'invalid per-build RMNET policy')
    require(not targets.get('candidate_manual_build') or KERNEL in names,
            'candidate build lacks required RMNET integration')
    return label in names


def regular(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'missing/linked file: ' + str(path))
    return path


class Elf64:
    """Bounds-checked little-endian ELF64 reader for module evidence only."""
    def __init__(self, data):
        self.data = data
        require(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01', 'not ELF64 LE')
        header = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
        self.type, self.machine = header[:2]
        shoff, entsize, count, names_index = header[5], header[10], header[11], header[12]
        require(entsize == 64 and 0 < count < 65535 and names_index < count,
                'unsupported ELF section table')
        self.slice(shoff, count * entsize)
        self.headers = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + n * entsize)
                        for n in range(count)]
        names = self.section_data(self.headers[names_index])
        self.sections = {}
        for h in self.headers:
            name = self.cstring(names, h[0])
            if not name:
                continue
            require(name not in self.sections, 'duplicate ELF section: ' + name)
            self.sections[name] = h

    def slice(self, offset, size):
        require(0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset,
                'ELF range outside file')
        return self.data[offset:offset + size]

    @staticmethod
    def cstring(data, offset):
        require(0 <= offset < len(data), 'ELF string offset invalid')
        end = data.find(b'\0', offset)
        require(end >= 0, 'unterminated ELF string')
        return data[offset:end].decode('ascii')

    def section_data(self, h):
        require(h[1] != 8, 'NOBITS is not file data')
        return self.slice(h[4], h[5])

    def section(self, name):
        require(name in self.sections, 'missing ELF section: ' + name)
        return self.section_data(self.sections[name])

    def symbols(self):
        h = self.sections.get('.symtab')
        require(h is not None and h[9] == 24 and h[5] % 24 == 0, 'invalid ELF symbol table')
        require(h[6] < len(self.headers), 'bad ELF string-table index')
        strings = self.section_data(self.headers[h[6]])
        data = self.section_data(h)
        for pos in range(0, len(data), 24):
            name, info, other, index, value, size = struct.unpack_from('<IBBHQQ', data, pos)
            yield self.cstring(strings, name), info >> 4, info & 15, index, value, size


def exports_from(data):
    result = {}
    for line in data.decode('ascii').splitlines():
        fields = line.split()
        require(len(fields) >= 4 and fields[2] == 'vmlinux', 'non-kernel export in Module.symvers')
        name, value = fields[1], int(fields[0], 16)
        require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) and name not in result
                and 0 <= value <= 0xffffffff, 'invalid/duplicate export')
        result[name] = value
    require('module_layout' in result, 'module_layout export missing')
    return result


def versions_from(data):
    require(data and len(data) % 64 == 0, 'malformed AArch64 __versions')
    result = {}
    for pos in range(0, len(data), 64):
        value = struct.unpack_from('<Q', data, pos)[0]
        raw = data[pos + 8:pos + 64]
        require(b'\0' in raw, 'unterminated CRC symbol')
        name, padding = raw.split(b'\0', 1)
        name = name.decode('ascii')
        require(not any(padding) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name)
                and name not in result and value <= 0xffffffff, 'invalid/duplicate CRC symbol')
        result[name] = value
    return result


def inspect_module(path, exports, release, name):
    data = regular(path).read_bytes()
    elf = Elf64(data)
    require(elf.machine == 183 and elf.type == 1, 'not AArch64 relocatable module')
    info = {}
    for field in elf.section('.modinfo').split(b'\0'):
        if b'=' in field:
            key, value = field.decode('ascii').split('=', 1)
            info.setdefault(key, []).append(value)
    require(info.get('name') == [name] and name in PAIR, 'module identity mismatch')
    require(info.get('depends') == [''], 'unsupported external dependency')
    magic = release + ' SMP preempt mod_unload modversions aarch64'
    require(info.get('vermagic') == [magic], 'vermagic mismatch')
    versions = versions_from(elf.section('__versions'))
    require(versions.get('module_layout') == exports['module_layout'], 'module_layout CRC mismatch')
    mismatches = [key for key, value in versions.items() if exports.get(key) != value]
    require(not mismatches, 'symbol CRC mismatches: ' + ','.join(mismatches))
    symbols = list(elf.symbols())
    imports = {n for n, binding, _, section, _, _ in symbols if n and section == 0 and binding != 2}
    require(imports <= versions.keys(), 'strong imports without version proof: ' + str(sorted(imports - versions.keys())))
    functions = {n for n, _, kind, section, _, _ in symbols if kind == 2 and section != 0}
    require({'init_module', 'cleanup_module', '__cfi_check'} <= functions, 'init/exit/CFI missing')
    note = elf.section('.note.gnu.build-id')
    require(len(note) >= 20 and note[12:16] == b'GNU\0', 'module build-id note invalid')
    return {'name': name, 'sha256': digest(data), 'bytes': len(data), 'vermagic': magic,
            'checked_crcs': len(versions), 'strong_imports': len(imports),
            'depends': [], 'cfi': True, 'init': True, 'exit': True,
            'note_sha256': digest(note)}


def note_from_kernel(image, system_map):
    """Extract the exact __start_notes..__stop_notes bytes from uncompressed Image."""
    addresses = {}
    for line in system_map.decode('ascii').splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in {'_text', '_stext', '__start_notes', '__stop_notes'}:
            require(parts[2] not in addresses, 'duplicate kernel note symbol')
            addresses[parts[2]] = int(parts[0], 16)
    require({'_text', '__start_notes', '__stop_notes'} <= addresses.keys(), 'kernel note symbols missing')
    start = addresses['__start_notes'] - addresses['_text']
    stop = addresses['__stop_notes'] - addresses['_text']
    require(0 <= start < stop <= len(image) and stop - start < 65536, 'kernel note range invalid')
    notes = image[start:stop]
    require(b'GNU\0' in notes, 'kernel build-id not present in notes')
    return notes


def build_modules(state, work, image, result, jobs):
    import veux_update_engine as e
    require(result.get('kernel') == KERNEL and result.get('compile') is True, 'requires compiled 5.4.274')
    work, image = Path(work), regular(image)
    out, src = work / 'build', Path(state['source'])
    config = regular(out / '.config').read_bytes()
    symvers = regular(out / 'Module.symvers').read_bytes()
    exports = exports_from(symvers)
    required = ['CONFIG_MODULES=y', 'CONFIG_MODULE_UNLOAD=y', 'CONFIG_MODVERSIONS=y',
                'CONFIG_CFI_CLANG=y', 'CONFIG_THINLTO=y', 'CONFIG_STACKPROTECTOR_STRONG=y',
                '# CONFIG_MODULE_FORCE_LOAD is not set', '# CONFIG_MODULE_FORCE_UNLOAD is not set']
    require(all(s in config.decode().splitlines() for s in required), 'module/security config incomplete')
    require(digest(config) == result['config_audit']['actual_config_sha256'], 'config belongs to another build')
    require(digest(image) == result['image_sha256'], 'compiled Image changed')
    notes = note_from_kernel(image.read_bytes(), regular(out / 'System.map').read_bytes())
    vmlinux = Elf64(regular(out / 'vmlinux').read_bytes())
    require(vmlinux.section('.notes') == notes, 'Image/vmlinux note mismatch')
    payload = work / 'rmnet-payload'
    payload.mkdir()
    values = dict(v.split('=', 1) for v in state['variables'])
    require('O' in values and jobs > 0, 'missing build variables')
    values['O'] = str(out)
    env = dict(os.environ, **state['env'])
    env.pop('VEUX_CAPTURE', None)
    env['PATH'] = os.pathsep.join(p for p in env['PATH'].split(os.pathsep)
                                  if p != str(work / 'source-temp/bin'))
    base = ['/usr/bin/make', '-C', str(src), *[f'{k}={v}' for k, v in values.items()]]
    e.run([*base, f'-j{jobs}', 'modules_prepare'], env=env, log=work / 'rmnet-prepare.log')
    require((out / '.config').read_bytes() == config and (out / 'Module.symvers').read_bytes() == symvers,
            'modules_prepare changed kernel evidence')
    modules = {}
    for name, folder in PAIR.items():
        source = src / 'techpack/datarmnet-ext' / folder
        require(source.is_dir() and not source.is_symlink(), 'module source directory unavailable')
        inputs = {p.name: digest(p) for p in source.iterdir() if p.is_file() and
                  (p.suffix in ('.c', '.h') or p.name in ('Kbuild', 'Makefile')) and not p.name.endswith('.mod.c')}
        require(inputs and 'Kbuild' in inputs, 'no module input inventory')
        logfile = work / (name + '-compile.log')
        e.run([*base, f'-j{jobs}', 'M=' + str(source),
               'RMNET_CORE_INC_DIR=' + str(src / 'techpack/datarmnet/core'),
               'KBUILD_EXTRA_SYMBOLS=', 'modules'], env=env, log=logfile, timeout=1800)
        text = logfile.read_text(errors='replace')
        require(not re.search(r'\bwarning:|fatal error:|\berror:|undefined reference', text),
                'module compiler diagnostics require review: ' + name)
        require((out / '.config').read_bytes() == config and (out / 'Module.symvers').read_bytes() == symvers
                and digest(image) == result['image_sha256'], 'module build changed base kernel evidence')
        require(all(digest(source / n) == h for n, h in inputs.items()), 'module sources changed while building')
        protected = []
        for n in inputs:
            if n.endswith('.c'):
                command = regular(source / ('.' + Path(n).stem + '.o.cmd')).read_text()
                require(all(flag in command for flag in ('-fsanitize=cfi', '-flto=thin', '-fstack-protector-strong')),
                        'compiler protection missing: ' + n)
                protected.append(n)
        require(protected, 'no protected translation units')
        module = regular(source / (name + '.ko'))
        row = inspect_module(module, exports, result['kernelrelease'], name)
        row.update(source_files_sha256=inputs, protected_units=sorted(protected))
        shutil.copy2(module, payload / (name + '.ko'))
        modules[name] = row
    proof = {'format': FORMAT, 'kernel': KERNEL, 'kernelrelease': result['kernelrelease'],
             'image_sha256': result['image_sha256'], 'kernel_notes_sha256': digest(notes),
             'config_sha256': digest(config), 'symvers_sha256': digest(symvers),
             'modules': modules, 'build': True, 'module_abi': True,
             'installed_on_device': False, 'device': False, 'installation': 'AnyKernel3-data-boot-completed'}
    (work / 'RMNET.json').write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n')
    result['rmnet'] = proof
    print('RMNET_PAIR_BUILD=PASS; SAME_BUILD_ABI=PASS; DEVICE_PASS=NO', flush=True)
    return proof


def write_zip(path, members):
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, (data, mode) in sorted(members.items()):
            rel = PurePosixPath(name)
            require(not rel.is_absolute() and '..' not in rel.parts and rel.as_posix() == name and '\\' not in name,
                    'unsafe package path')
            info = zipfile.ZipInfo(name, (2024, 12, 5, 14, 48, 0))
            info.create_system = 3
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)


def augment_package(result, work, public):
    work, public = Path(work), Path(public)
    proof = result.get('rmnet')
    verify_proof(result)
    package = regular(public / result['package_file'])
    require(digest(package) == result['package_sha256'], 'base package digest mismatch')
    with zipfile.ZipFile(package) as z:
        require(z.testzip() is None and len(z.namelist()) == len(set(z.namelist())), 'invalid base archive')
        members = {i.filename: (z.read(i), (i.external_attr >> 16) & 0o777) for i in z.infolist()}
    require(members['Image'][0] and digest(members['Image'][0]) == proof['image_sha256'], 'package Image mismatch')
    script = members['anykernel.sh'][0].decode()
    require(script.count('dump_boot;') == 1 and script.count('write_boot;') == 1
            and 'do.modules=0' in script, 'unsupported AK3 installation layout')
    require(not any(n.startswith('rmnet/') for n in members), 'package is already augmented')
    # Stage data before the boot write. It is selected only by the NEXT boot's
    # exact kernel notes, never enabled for the running old kernel during install.
    script = script.replace('write_boot;',
        'sh "$AKHOME/rmnet/install.sh" "$AKHOME/rmnet" || abort "RMNET data installation failed; boot unchanged";\nwrite_boot;', 1)
    members['anykernel.sh'] = (script.encode(), 0o755)
    for name in PAIR:
        blob = regular(work / 'rmnet-payload' / (name + '.ko')).read_bytes()
        require(digest(blob) == proof['modules'][name]['sha256'], 'module payload changed')
        members['rmnet/' + name + '.ko'] = (blob, 0o600)
    for name in ('launcher.sh', 'runtime.sh', 'install.sh'):
        members['rmnet/' + name] = (regular(ASSETS / name).read_bytes(), 0o700)
    manifest = {
        'FORMAT': FORMAT,
        'KERNEL_RELEASE': proof['kernelrelease'],
        'KERNEL_NOTES_SHA256': proof['kernel_notes_sha256'],
        'OFFLOAD_NOTE_SHA256': proof['modules']['rmnet_offload']['note_sha256'],
        'SHS_NOTE_SHA256': proof['modules']['rmnet_shs']['note_sha256'],
    }
    members['rmnet/identity.txt'] = (''.join(k + '=' + v + '\n' for k, v in manifest.items()).encode(), 0o600)
    sums = ''.join(digest(data) + '  ' + name.removeprefix('rmnet/') + '\n'
                   for name, (data, _) in sorted(members.items()) if name.startswith('rmnet/'))
    members['rmnet/SHA256SUMS'] = (sums.encode(), 0o600)
    target_name = result['package_file'].removesuffix('_AnyKernel.zip') + '_AnyKernel_RMNET.zip'
    destination = public / target_name
    require(destination != package and not destination.exists(), 'RMNET package destination exists')
    write_zip(destination, members)
    second = work / 'rmnet-repeat.zip'
    write_zip(second, members)
    require(digest(second) == digest(destination), 'non-deterministic RMNET package')
    with zipfile.ZipFile(destination) as z:
        require(z.testzip() is None and z.read('Image') == members['Image'][0], 'RMNET package integrity failure')
    package.unlink()
    result.update(package_file=target_name, package_sha256=digest(destination))
    proof['package'] = True
    (public / 'RMNET-INSTALLATION.txt').write_text(
        'RMNET ist nur mit dem AnyKernel_RMNET.zip vollstaendig installiert.\n'
        'Das separate boot.img enthaelt nur den Kernel und ersetzt diese Installation nicht.\n'
        'Kernelbegleitende Dateien: /data/adb/veux-rmnet/<Build-Identitaet> und '\
        '/data/adb/boot-completed.d/50-veux-rmnet.sh. Kein zusaetzliches Manager-Modul.\n'
        'Kein Vendor-Overlay, keine Vendor-Schreibzugriffe. Bestehende ROM-Ladeversuche bleiben bestehen.\n'
        'Aktivierung erst nach Android-Bootabschluss, nur beim passenden Kernel; SafeMode bleibt wirksam.\n'
        'Dynamische ROM-Properties werden nur gelesen, niemals ueberschrieben.\n'
        'CI-/Hosttests sind kein Geraete- oder Mobilfunkdaten-PASS.\n')
    (work / 'RMNET.json').write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n')
    verify_package(result, public)
    print('RMNET_PACKAGE=PASS; VENDOR_WRITES=NO; DEVICE_PASS=NO', flush=True)


def verify_proof(row):
    proof = row.get('rmnet')
    require(row.get('kernel') == KERNEL and isinstance(proof, dict) and proof.get('format') == FORMAT and proof.get('kernel') == KERNEL,
            'module build proof missing')
    require(proof.get('image_sha256') == row.get('image_sha256') and
            proof.get('kernelrelease') == row.get('kernelrelease'), 'module proof belongs to another kernel')
    require(proof.get('config_sha256') == row.get('config_audit', {}).get('actual_config_sha256'),
            'module proof belongs to another config')
    require(proof.get('build') is True and proof.get('module_abi') is True and
            proof.get('device') is False and proof.get('installed_on_device') is False, 'invalid module proof states')
    for key in ('symvers_sha256', 'kernel_notes_sha256', 'config_sha256', 'image_sha256'):
        require(isinstance(proof.get(key), str) and re.fullmatch(r'[0-9a-f]{64}', proof[key]), 'invalid proof digest: ' + key)
    require(set(proof.get('modules', {})) == set(PAIR), 'incomplete module pair')
    for name, module in proof['modules'].items():
        require(module.get('name') == name and module.get('depends') == []
                and type(module.get('checked_crcs')) is int and module['checked_crcs'] > 0
                and all(module.get(key) is True for key in ('cfi', 'init', 'exit')), 'invalid module evidence')
        for key in ('sha256', 'note_sha256'):
            require(isinstance(module.get(key), str) and re.fullmatch(r'[0-9a-f]{64}', module[key]), 'invalid module digest')


def verify_package(row, public):
    verify_proof(row)
    proof = row['rmnet']
    require(proof.get('package') is True, 'module package was not validated')
    package = regular(Path(public) / row['package_file'])
    require(digest(package) == row['package_sha256'], 'module package digest mismatch')
    with zipfile.ZipFile(package) as z:
        require(z.testzip() is None and len(z.namelist()) == len(set(z.namelist())), 'corrupt module package')
        require(digest(z.read('Image')) == proof['image_sha256'], 'wrong packaged kernel')
        for name in PAIR:
            require(digest(z.read('rmnet/' + name + '.ko')) == proof['modules'][name]['sha256'], 'wrong packaged module')
        for name in ('launcher.sh', 'runtime.sh', 'install.sh'):
            require(z.read('rmnet/' + name) == regular(ASSETS / name).read_bytes(), 'runtime script mismatch')
        identity = {}
        for line in z.read('rmnet/identity.txt').decode('ascii').splitlines():
            key, value = line.split('=', 1)
            require(key not in identity, 'duplicate identity field')
            identity[key] = value
        require(identity == {
            'FORMAT': FORMAT, 'KERNEL_RELEASE': proof['kernelrelease'],
            'KERNEL_NOTES_SHA256': proof['kernel_notes_sha256'],
            'OFFLOAD_NOTE_SHA256': proof['modules']['rmnet_offload']['note_sha256'],
            'SHS_NOTE_SHA256': proof['modules']['rmnet_shs']['note_sha256'],
        }, 'package identity differs from this build')
        script = z.read('anykernel.sh').decode()
        expected_command = 'sh "$AKHOME/rmnet/install.sh" "$AKHOME/rmnet" || abort '
        require(script.count(expected_command) == 1 and script.count('write_boot;') == 1
                and script.index(expected_command) < script.index('write_boot;'),
                'missing or late companion installation')
        expected_members = {'rmnet/' + name for name in (
            'launcher.sh', 'runtime.sh', 'install.sh', 'identity.txt', 'SHA256SUMS',
            'rmnet_offload.ko', 'rmnet_shs.ko')}
        require({n for n in z.namelist() if n.startswith('rmnet/')} == expected_members,
                'unexpected or missing companion files')
        for item in z.infolist():
            rel = PurePosixPath(item.filename)
            require(not rel.is_absolute() and '..' not in rel.parts and
                    '\\' not in item.filename and rel.as_posix() == item.filename,
                    'unsafe package member')
            mode = item.external_attr >> 16
            require(not stat.S_ISLNK(mode), 'linked package member')
        checks = z.read('rmnet/SHA256SUMS').decode().splitlines()
        names = set()
        for line in checks:
            expected, name = line.split('  ', 1)
            require(PurePosixPath(name).name == name and name not in names, 'invalid payload checksum entry')
            require(digest(z.read('rmnet/' + name)) == expected, 'payload checksum mismatch')
            names.add(name)
        require(names == set(PAIR_name + '.ko' for PAIR_name in PAIR) |
                {'launcher.sh', 'runtime.sh', 'install.sh', 'identity.txt'}, 'incomplete payload checksums')
