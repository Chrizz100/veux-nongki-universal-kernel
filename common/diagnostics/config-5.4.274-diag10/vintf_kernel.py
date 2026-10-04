#!/usr/bin/env python3
"""Check the captured ROM's kernel requirements; this is not a HAL/AVB check."""
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import veux_update_engine as e

HERE = Path(__file__).resolve().parent
REQUIRED_ENABLE = ('AUDIT', 'CRYPTO_GCM', 'MODULES', 'MODULE_UNLOAD',
    'MODVERSIONS', 'PROFILING', 'SCHED_DEBUG', 'STACKPROTECTOR',
    'STACKPROTECTOR_STRONG', 'STRICT_MODULE_RWX', 'CFI_CLANG')
# SCHED_DEBUG depends on DEBUG_KERNEL in the pinned kernel source.
DEPENDENCY_ENABLE = ('DEBUG_KERNEL',)
REQUIRED_DISABLE = ('CFI_PERMISSIVE', 'MODULE_FORCE_LOAD', 'MODULE_FORCE_UNLOAD')


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


def integer(value):
    value = value.strip()
    return int(value, 16 if value.lower().startswith('0x') else 10)


def matches(actual, kind, expected):
    if kind == 'tristate':
        e.require(expected in ('y', 'm', 'n'), 'invalid tristate requirement')
        return actual == expected
    if kind == 'string':
        return actual == '"' + expected + '"'
    if kind in ('int', 'range'):
        try:
            if kind == 'int':
                return integer(actual) == integer(expected)
            lo, hi = expected.split('-', 1)
            return integer(lo) <= integer(actual) <= integer(hi)
        except ValueError:
            return False
    raise e.Blocked('unsupported VINTF value type: ' + kind)


def row(config, values):
    key, value = config.findtext('key'), config.find('value')
    e.require(key is not None and value is not None, 'incomplete kernel requirement')
    kind, expected = value.get('type'), value.text or ''
    actual = values.get(key, 'n')
    return {'key': key, 'type': kind, 'required': expected, 'actual': actual,
            'match': matches(actual, kind, expected)}


def evaluate(data, matrix=None, kernel='5.4.274'):
    values = options(data)
    matrix = matrix or HERE/'rom-kernel-requirements.xml'
    root = ET.parse(matrix).getroot()
    e.require(root.tag == 'compatibility-matrix' and root.get('type') == 'framework'
              and root.get('level') == '5', 'unexpected ROM matrix identity')
    e.require(values.get('CONFIG_ARM64') == 'y', 'ARM64 configuration required')
    version = tuple(map(int, kernel.split('.')))
    checks, applied, skipped = [], 0, 0
    for group in root.findall('kernel'):
        minimum = tuple(map(int, group.get('version').split('.')))
        e.require(group.get('level') == '5', 'unexpected kernel FCM level')
        if minimum[:2] != version[:2] or minimum > version:
            continue
        conditions = group.find('conditions')
        if conditions is not None and not all(row(c, values)['match'] for c in conditions.findall('config')):
            skipped += 1
            continue
        applied += 1
        checks.extend(row(c, values) for c in group.findall('config'))
    e.require(applied > 0 and checks, 'no matching kernel requirements')
    failures = [c for c in checks if not c['match']]
    return {'scope': 'captured ROM kernel requirements only', 'kernel': kernel,
        'matrix_level': 5, 'kernel_level': 5, 'matrix_sha256': e.digest(matrix),
        'groups_applied': applied, 'groups_skipped': skipped,
        'requirements': len(checks), 'passed': len(checks)-len(failures),
        'failures': failures, 'status': 'FAIL' if failures else 'PASS',
        'device': False}


def require_compatible(data, baseline):
    report = evaluate(data)
    values, previous = options(data), options(baseline)
    e.require(report['requirements'] == 261, 'ROM condition selection changed')
    e.require(not report['failures'], 'ROM kernel requirements unmet: ' +
              ', '.join(x['key'] for x in report['failures']))
    for key in REQUIRED_ENABLE + DEPENDENCY_ENABLE + ('LTO_CLANG', 'THINLTO', 'IKCONFIG', 'IKCONFIG_PROC', 'KSU', 'KSU_SUSFS', 'NOMOUNT'):
        e.require(values.get('CONFIG_'+key) == 'y', 'required option missing: '+key)
    for key in REQUIRED_DISABLE:
        e.require(values.get('CONFIG_'+key, 'n') == 'n', 'unsafe diagnostic option: '+key)
    lost = [key for key, value in previous.items()
            if value == 'y' and values.get(key, 'n') != 'y']
    e.require(not lost, 'existing built-in option dropped: ' + ', '.join(lost))
    modules = [key for key, value in values.items() if value == 'm']
    e.require(not modules, 'AK3 does not ship new loadable driver modules: '+', '.join(modules))
    report['changes_from_diag09'] = {
        key: {'before': previous.get(key, 'n'), 'after': values.get(key, 'n')}
        for key in sorted(previous.keys() | values.keys())
        if previous.get(key, 'n') != values.get(key, 'n')}
    return report


def compiler_evidence(command, symbols):
    e.require(re.search(r'-fsanitize=[^\s;]*\bcfi\b', command) is not None,
              'CFI compiler instrumentation missing')
    e.require('-fsanitize-cfi-cross-dso' in command, 'module-aware CFI missing')
    e.require('-fsanitize-recover=cfi' not in command, 'permissive CFI flags found')
    stack_flags = re.findall(r'(?<!\S)-f(?:no-)?stack-protector(?:-strong|-all)?(?=\s|$)', command)
    e.require(stack_flags and stack_flags[-1] == '-fstack-protector-strong',
              'strong stack protector compiler flag missing or overridden')
    for name in ('__cfi_check', '__stack_chk_fail'):
        e.require(re.search(r'(?m)^\S+\s+\S\s+'+re.escape(name)+r'$', symbols),
                  'compiled protection symbol missing: '+name)


def configure_argv(src, out):
    argv = [src/'scripts/config', '--file', out/'.config']
    for key in REQUIRED_ENABLE + DEPENDENCY_ENABLE:
        argv.extend(['--enable', key])
    for key in REQUIRED_DISABLE:
        argv.extend(['--disable', key])
    return argv
