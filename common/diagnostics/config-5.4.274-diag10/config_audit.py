#!/usr/bin/env python3
"""Restore captured ROM requirements and verify the actual compiled configuration."""
from contextlib import contextmanager
import difflib
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import zlib
import veux_update_engine as e
import vintf_kernel as vintf

HERE = Path(__file__).resolve().parent
KEYS = ('IKCONFIG', 'IKCONFIG_PROC', 'LTO', 'LTO_CLANG', 'THINLTO',
        'CFI_CLANG', 'CFI_CLANG_SHADOW', 'CFI_PERMISSIVE')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def options(data):
    result = {}
    for line in data.decode().splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1)
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            key, value = line[2:-11], 'n'
        else:
            continue
        e.require(key not in result, 'duplicate config option: ' + key)
        result[key] = value
    return result


def extract(image):
    """Require exactly one complete, CRC-checked IKCONFIG gzip member."""
    matches = []
    pos = 0
    while True:
        pos = image.find(b'IKCFG_ST', pos)
        if pos < 0:
            break
        pos += 8
        if image[pos:pos+3] != b'\x1f\x8b\x08':
            continue
        try:
            stream = zlib.decompressobj(31)
            data = stream.decompress(image[pos:], 2*1024*1024)
            if stream.eof and stream.unused_data.startswith(b'IKCFG_ED'):
                matches.append(data)
        except zlib.error:
            continue
    e.require(len(matches) == 1, 'require one valid embedded kernel config')
    return matches[0]


def apply_sched_debug(src):
    manifest = json.loads((HERE/'sched-debug-manifest.json').read_text())
    path = e.inside(src/manifest['path'], src)
    e.require(path.is_file() and not path.is_symlink(), 'invalid scheduler debug source')
    before = path.read_bytes()
    e.require(sha(before) == manifest['before_sha256'], 'scheduler debug baseline drift')
    e.require(e.digest(HERE/'sched-debug-pm.patch') == manifest['patch_sha256'],
              'scheduler debug patch drift')
    old = b'#define   PM(F, M) __PS(#F, p->F & (M))'
    new = b'#define   PM(F, M) SEQ_printf(m, "%-45s:%21Ld\\n", #F, (long long)(p->F & (M)))'
    e.require(before.count(old) == 1, 'scheduler PM macro changed')
    after = before.replace(old, new)
    e.require(sha(after) == manifest['after_sha256'], 'scheduler debug postimage drift')
    path.write_bytes(after)
    return manifest


def apply(src):
    manifest = json.loads((HERE/'manifest.json').read_text())
    path = e.inside(src/manifest['path'], src)
    e.require(path.is_file() and not path.is_symlink(), 'invalid kernel Makefile')
    before = path.read_bytes()
    e.require(sha(before) == manifest['before_sha256'], 'kernel Makefile baseline drift')
    old = b'$(obj)/config_data.gz: arch/arm64/configs/stock_defconfig FORCE'
    new = b'$(obj)/config_data.gz: $(KCONFIG_CONFIG) FORCE'
    e.require(before.count(old) == 1, 'IKCONFIG rule changed')
    after = before.replace(old, new)
    e.require(sha(after) == manifest['after_sha256'], 'kernel Makefile postimage drift')
    path.write_bytes(after)
    manifest['scheduler_patch'] = apply_sched_debug(src)
    return manifest


def verify_build(src, out, image, expected_config, reports, manifest):
    actual = (out/'.config').read_bytes()
    e.require(actual == expected_config, 'configuration changed during compile')
    embedded = extract(image.read_bytes())
    (reports/'embedded.config').write_bytes(embedded)
    e.require(embedded == actual, 'Image embedded config differs from actual build config')
    compressed = gzip.decompress((out/'kernel/config_data.gz').read_bytes())
    e.require(compressed == actual, 'config_data.gz differs from actual build config')
    e.require(e.digest(src/manifest['path']) == manifest['after_sha256'], 'IKCONFIG rule changed during compile')
    sched = manifest['scheduler_patch']
    e.require(e.digest(src/sched['path']) == sched['after_sha256'], 'scheduler debug source changed during compile')
    values = options(actual)
    baseline = (HERE/'diag09-actual.config').read_bytes()
    vintf_report = vintf.require_compatible(actual, baseline)
    auto_data = (out/'include/config/auto.conf').read_bytes()
    (reports/'auto.conf').write_bytes(auto_data)
    auto = options(auto_data)
    e.require(all(values.get('CONFIG_'+k, 'n') == auto.get('CONFIG_'+k, 'n') for k in KEYS),
              'generated build options disagree with .config')
    e.require(values.get('CONFIG_IKCONFIG') == 'y' and values.get('CONFIG_IKCONFIG_PROC') == 'y',
              'kernel config interface must remain enabled')
    commands = {}
    # A normal core translation unit provides evidence independent of the
    # embedded text. Do not infer runtime CFI protection from text markers.
    for rel in ('kernel/.fork.o.cmd', 'kernel/.configs.o.cmd', 'kernel/.cfi.o.cmd'):
        path = out/rel
        if path.is_file():
            text = path.read_text()
            (reports/path.name.lstrip('.')).write_text(text)
            commands[rel] = {'sha256': e.digest(path),
                'cfi_flag': bool(re.search(r'-fsanitize=[^\s;]*\bcfi\b', text)),
                'lto_flag': bool(re.search(r'(?<!\S)-flto(?:=\S+)?(?:\s|$)', text))}
    core = commands.get('kernel/.fork.o.cmd')
    e.require(core is not None, 'core compile command missing for CFI audit')
    configured_cfi = values.get('CONFIG_CFI_CLANG', 'n') == 'y'
    e.require(core['cfi_flag'] == configured_cfi, 'CFI option and core compiler flag disagree')
    vintf.compiler_evidence((out/'kernel/.fork.o.cmd').read_text(),
                            (out/'System.map').read_text())
    stock = (src/'arch/arm64/configs/stock_defconfig').read_bytes()
    (reports/'stock-to-actual.diff').write_text(''.join(difflib.unified_diff(
        stock.decode().splitlines(True), actual.decode().splitlines(True),
        fromfile='previously-embedded-stock_defconfig', tofile='actual-build.config')))
    report = {'id': 'ConfigDiag10', 'status': 'PASS',
        'actual_config_sha256': sha(actual), 'embedded_config_sha256': sha(embedded),
        'image_sha256': e.digest(image), 'source_patch': manifest,
        'configuration_unchanged_during_compile': True,
        'vintf_kernel': vintf_report,
        'stack_protector': 'strong-configured-and-core-instrumented',
        'options': {k: values.get('CONFIG_'+k, 'n') for k in KEYS},
        'core_compile_commands': commands,
        'cfi': 'configured-and-core-instrumented' if configured_cfi else 'disabled',
        'cfi_runtime_test': 'not-performed', 'device': False}
    e.write_json(reports/'CONFIG-AUDIT.json', report)
    print('CONFIG_DIAG10=PASS; embedded=actual; CFI='+report['cfi'], flush=True)
    return report


@contextmanager
def compiler_audit(reports):
    original_compile, original_run = e.compile_kernel, e.run
    reports.mkdir(parents=True, exist_ok=False)

    def compile_checked(label, state, targets, work, jobs):
        e.require(label == '5.4.274', 'unreviewed config diagnostic lineage')
        src, out = Path(state['source']), work/'build'
        values = dict(v.split('=', 1) for v in state['variables'])
        old_config = e.inside((src/values['O']).resolve(), work)/'.config'
        old_hash = e.digest(old_config)
        manifest = apply(src)
        e.require(e.digest(old_config) == old_hash, 'patch changed input configuration')
        e.write_json(reports/'SOURCE-PATCH.json', manifest)
        snapshot = []

        def observe(argv, *args, **kwargs):
            if kwargs.get('log') == work/'configure.log':
                e.require('olddefconfig' in [str(x) for x in argv], 'unexpected configure operation')
                original_run(vintf.configure_argv(src, out), cwd=src, env=kwargs.get('env'))
                configured = original_run(argv, *args, **kwargs)
                config = (out/'.config').read_bytes()
                report = vintf.evaluate(config)
                e.write_json(reports/'VINTF-PREBUILD.json', report)
                report = vintf.require_compatible(config, (HERE/'diag09-actual.config').read_bytes())
                e.write_json(reports/'VINTF-PREBUILD.json', report)
                print('VINTF_KERNEL_PREBUILD=PASS; 261 captured ROM requirements', flush=True)
                return configured
            if kwargs.get('log') == work/'compile.log':
                e.require(not snapshot, 'duplicate compile invocation')
                config = (out/'.config').read_bytes()
                snapshot.append(config)
                (reports/'actual-build.config').write_bytes(config)
            return original_run(argv, *args, **kwargs)

        try:
            e.run = observe
            image, result = original_compile(label, state, targets, work, jobs)
            e.require(len(snapshot) == 1, 'actual build config was not captured')
            report = verify_build(src, out, image, snapshot[0], reports, manifest)
            result['config_audit'] = report
            e.write_json(work/'build-result.json', result)
            return image, result
        finally:
            e.run = original_run
            # Preserve real options and partial evidence even on failed builds.
            if (out/'.config').is_file():
                shutil.copy2(out/'.config', reports/'final-build.config')

    try:
        e.compile_kernel = compile_checked
        yield
    finally:
        e.compile_kernel, e.run = original_compile, original_run
