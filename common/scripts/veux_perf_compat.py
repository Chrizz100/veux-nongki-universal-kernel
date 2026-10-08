#!/usr/bin/env python3
"""Restore the existing MSM CPU-limit interface in 5.4.274 candidates.

No scheduler substitution, dummy nodes, vendor writes, frequency-policy tuning,
forced modules or changes to the historic ConfigDiag10 assets. Build-local
source/config changes are audited against the same resulting Image.
"""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import zlib

KERNEL = '5.4.274'
FORMAT = 'veux-msm-cpu-limits-v1'
DRIVER = 'drivers/soc/qcom/msm_performance.c'
INCLUDE = '#include <linux/sched/core_ctl.h>'
GUARDED = '#ifdef CONFIG_MSM_PERFORMANCE_QGKI\n' + INCLUDE + '\n#endif'
INTERFACES = ['cpu_min_freq', 'cpu_max_freq']


def require(ok, reason):
    if not ok:
        raise ValueError('MSM CPU limits: ' + reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'missing/linked input: ' + str(path))
    return path


def options(data):
    values = {}
    for line in data.decode('utf-8').splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, val = line.split('=', 1)
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            key, val = line[2:-11], 'n'
        else:
            continue
        require(key not in values, 'duplicate configuration key: ' + key)
        values[key] = val
    return values


def requested(targets, label):
    require(isinstance(targets, dict), 'invalid targets')
    candidate = targets.get('candidate_manual_build') is True
    names = targets.get('performance_required', [KERNEL] if candidate else [])
    require(isinstance(names, list) and all(isinstance(x, str) for x in names)
            and len(set(names)) == len(names) and set(names) <= {KERNEL},
            'invalid per-build performance policy')
    require(not candidate or KERNEL in names, 'candidate omitted CPU-limit repair')
    return label in names


def source_patch(src):
    path = regular(Path(src) / DRIVER)
    before = path.read_bytes()
    text = before.decode('utf-8')
    require(text.count(INCLUDE) == 1, 'core_ctl include missing or ambiguous')
    # The included header only belongs to the QGKI implementation. The source
    # tree no longer supplies that header. Keep its reference in the matching
    # conditional branch, rather than fabricating a replacement header.
    if GUARDED not in text:
        lines = text.splitlines(keepends=True)
        hits = [i for i, line in enumerate(lines) if line.strip() == INCLUDE]
        require(len(hits) == 1, 'include is not a standalone directive')
        i = hits[0]
        # Do not accidentally close or alter an existing conditional branch.
        depth = 0
        for line in lines[:i]:
            if re.match(r'^\s*#\s*(if|ifdef|ifndef)\b', line):
                depth += 1
            elif re.match(r'^\s*#\s*endif\b', line):
                depth -= 1
        require(depth == 0, 'include already in an unreviewed conditional')
        lines[i] = GUARDED + '\n'
        text = ''.join(lines)
    require(text.count(GUARDED) == 1, 'guard is not unique')
    for name in INTERFACES:
        require(re.search(r'module_param_cb\s*\(\s*' + name +
                          r'\s*,\s*&param_ops_' + name + r'\s*,\s*NULL\s*,\s*0644\s*\)', text),
                'original CPU-limit callback/permissions changed: ' + name)
        for fn in ('set_' + name, 'get_' + name):
            require(re.search(r'\b' + fn + r'\s*\(', text), 'callback missing: ' + fn)
    for token in ('freq_qos_add_request', 'freq_qos_update_request',
                  'late_initcall(msm_performance_init)'):
        require(token in text, 'original implementation missing: ' + token)
    after = text.encode('utf-8')
    if after != before:
        path.write_bytes(after)
    return {'path': DRIVER, 'before_sha256': digest(before),
            'after_sha256': digest(after), 'change': 'QGKI-only core_ctl include guard'}


def check_config(data):
    values = options(data)
    for name in ('MSM_PERFORMANCE', 'CPU_FREQ', 'SYSFS', 'SMP',
                 'IKCONFIG', 'IKCONFIG_PROC', 'CFI_CLANG', 'THINLTO',
                 'STACKPROTECTOR_STRONG', 'MODULES', 'MODULE_UNLOAD', 'MODVERSIONS'):
        require(values.get('CONFIG_' + name) == 'y', 'required option: ' + name)
    for name in ('MSM_PERFORMANCE_QGKI', 'QTI_PLH', 'CFI_PERMISSIVE',
                 'MODULE_FORCE_LOAD', 'MODULE_FORCE_UNLOAD'):
        require(values.get('CONFIG_' + name, 'n') == 'n', 'unexpected enabled option: ' + name)
    return values


def command_proof(text):
    # Only the actual command assignment counts, never a dependency filename.
    commands = [line for line in text.splitlines() if re.match(r'^cmd_.*\s*:=', line)]
    require(len(commands) == 1, 'missing/ambiguous driver command assignment')
    cmd = commands[0]
    require('msm_performance.c' in cmd, 'command is not the performance driver')
    require(re.search(r'(?<!\S)-fsanitize=[^\s;]*\bcfi\b', cmd), 'driver CFI missing')
    require('-fsanitize-cfi-cross-dso' in cmd, 'driver cross-DSO CFI missing')
    require('-flto=thin' in cmd, 'driver ThinLTO missing')
    require('-fsanitize-recover=cfi' not in cmd and '-fno-sanitize=cfi' not in cmd,
            'driver CFI overridden')
    flags = re.findall(r'(?<!\S)-f(?:no-)?stack-protector(?:-strong|-all)?(?=\s|$)', cmd)
    require(flags and flags[-1] == '-fstack-protector-strong', 'driver stack protection missing')
    return digest(text.encode('utf-8'))


@contextmanager
def compiler_scope(audit, state, targets, work):
    """Extend only the live configure operation; restore all hooks on exit."""
    if not requested(targets, KERNEL):
        yield None
        return
    import veux_update_engine as e
    work, src = Path(work), Path(state['source'])
    proof = {'source_patch': source_patch(src), 'precompile': False}
    vintf = audit.vintf
    original_configure, original_run = vintf.configure_argv, e.run
    seen = []

    def configure(src_arg, out_arg):
        require(Path(src_arg) == src and Path(out_arg) == work / 'build', 'wrong configuration directory')
        before = options(regular(Path(out_arg) / '.config').read_bytes())
        require(before.get('CONFIG_MSM_PERFORMANCE_QGKI', 'n') == 'n'
                and before.get('CONFIG_QTI_PLH', 'n') == 'n',
                'do not disable an existing QGKI/PLH implementation')
        argv = list(original_configure(src_arg, out_arg))
        require(len(argv) >= 3 and str(argv[0]) == str(src / 'scripts/config')
                and argv[1] == '--file' and Path(argv[2]) == Path(out_arg) / '.config',
                'unrecognized base configuration command')
        # Existing settings and their original enable/disable operations remain.
        return argv + ['--enable', 'MSM_PERFORMANCE', '--disable', 'MSM_PERFORMANCE_QGKI',
                       '--disable', 'QTI_PLH']

    def run(argv, *args, **kwargs):
        is_configure = kwargs.get('log') == work / 'configure.log'
        if not is_configure:
            return original_run(argv, *args, **kwargs)
        require(not seen, 'duplicate configuration operation')
        names = [str(x) for x in argv]
        require(names.count('olddefconfig') == 1, 'unrecognized olddefconfig invocation')
        response = original_run(argv, *args, **kwargs)
        out = work / 'build'
        config = regular(out / '.config').read_bytes()
        check_config(config)
        early = [str(x) if str(x) != 'olddefconfig' else 'drivers/soc/qcom/msm_performance.o'
                 for x in argv]
        opts = dict(kwargs)
        opts['log'] = work / 'performance-precompile.log'
        opts['timeout'] = 600
        original_run(early, *args, **opts)
        log_text = regular(opts['log']).read_text(errors='replace')
        require(not re.search(r'\bwarning:|fatal error:|\berror:|undefined reference', log_text),
                'targeted driver diagnostics require review')
        require(regular(out / '.config').read_bytes() == config, 'precompile changed configuration')
        regular(out / 'drivers/soc/qcom/msm_performance.o')
        command = regular(out / 'drivers/soc/qcom/.msm_performance.o.cmd').read_text()
        command_proof(command)
        require(digest(regular(src / DRIVER).read_bytes()) == proof['source_patch']['after_sha256'],
                'performance source changed during precompile')
        seen.append(True)
        proof.update(precompile=True, precompile_config_sha256=digest(config),
                     precompile_command_sha256=digest(command.encode('utf-8')))
        print('MSM_CPU_LIMITS_TARGETED_COMPILE=PASS; FULL_KERNEL_BUILD=NEXT', flush=True)
        return response

    try:
        vintf.configure_argv = configure
        e.run = run
        yield proof
        require(len(seen) == 1 and proof['precompile'] is True, 'targeted driver precompile not executed')
    finally:
        vintf.configure_argv = original_configure
        e.run = original_run


def embedded_config(image):
    found, pos = [], 0
    while True:
        pos = image.find(b'IKCFG_ST', pos)
        if pos < 0:
            break
        pos += 8
        if image[pos:pos + 3] != b'\x1f\x8b\x08':
            continue
        try:
            stream = zlib.decompressobj(31)
            data = stream.decompress(image[pos:], 2 * 1024 * 1024)
            if stream.eof and stream.unused_data.startswith(b'IKCFG_ED'):
                found.append(data)
        except zlib.error:
            continue
    require(len(found) == 1, 'missing/ambiguous embedded configuration')
    return found[0]


def verify_build(state, work, image, result, pending):
    require(isinstance(pending, dict) and pending.get('precompile') is True, 'missing precompile proof')
    work, image = Path(work), regular(image)
    src, out = Path(state['source']), work / 'build'
    config = regular(out / '.config').read_bytes()
    values = check_config(config)
    require(digest(config) == pending['precompile_config_sha256'], 'config changed since precompile')
    require(embedded_config(image.read_bytes()) == config, 'embedded config differs')
    require(result.get('compile') is True and result.get('kernel') == KERNEL, 'not a compiled 5.4.274 result')
    require(digest(image.read_bytes()) == result.get('image_sha256'), 'result image mismatch')
    require(result.get('config_audit', {}).get('actual_config_sha256') == digest(config),
            'ConfigDiag10 does not describe this configuration')
    generated = options(regular(out / 'include/config/auto.conf').read_bytes())
    for name in ('MSM_PERFORMANCE', 'MSM_PERFORMANCE_QGKI', 'QTI_PLH', 'CFI_CLANG', 'THINLTO'):
        key = 'CONFIG_' + name
        require(generated.get(key, 'n') == values.get(key, 'n'), 'generated config disagrees: ' + name)
    source_hash = digest(regular(src / DRIVER).read_bytes())
    require(source_hash == pending['source_patch']['after_sha256'], 'built driver source changed')
    command = regular(out / 'drivers/soc/qcom/.msm_performance.o.cmd').read_text()
    command_hash = command_proof(command)
    obj = regular(out / 'drivers/soc/qcom/msm_performance.o').read_bytes()
    require(len(obj) > 0, 'empty driver object')
    symbols = regular(out / 'System.map').read_text()
    present = []
    for name in ('msm_performance_init', 'set_cpu_min_freq', 'get_cpu_min_freq',
                 'set_cpu_max_freq', 'get_cpu_max_freq'):
        require(re.search(r'(?m)^\S+\s+[tT]\s+' + re.escape(name) + r'(?:\.[^\s]+)?$', symbols),
                'linked driver function missing: ' + name)
        present.append(name)
    data = image.read_bytes()
    for name in INTERFACES:
        # Built-in module parameters retain the module prefix in the Image.
        require(('msm_performance.' + name + '\0').encode() in data,
                'built-in parameter name missing from Image: ' + name)
    proof = dict(pending, format=FORMAT, kernel=KERNEL, build=True, device=False,
                 image_sha256=digest(data), config_sha256=digest(config),
                 command_sha256=command_hash, object_sha256=digest(obj),
                 linked_symbols=present, interfaces=list(INTERFACES),
                 mode='built-in-cpu-limits-only', qgki_enabled=False,
                 source_after_sha256=source_hash,
                 unchanged=['scheduler', 'devfreq', 'frequency-tuning-values', 'vendor-files', 'security-policy'])
    result['performance_compat'] = proof
    verify_result(result)
    directory = work / 'config-reports'
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'PERFORMANCE.json').write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n')
    (directory / 'msm_performance.o.cmd').write_text(command)
    print('MSM_CPU_LIMITS_BUILTIN_AND_IMAGE=PASS; DEVICE_PASS=NO', flush=True)
    return proof


def verify_result(row):
    require(isinstance(row, dict), 'invalid result')
    p = row.get('performance_compat')
    require(isinstance(p, dict) and p.get('format') == FORMAT and p.get('kernel') == KERNEL,
            'required CPU-limit proof missing')
    require(row.get('kernel') == KERNEL and row.get('compile') is True
            and p.get('build') is True and p.get('precompile') is True and p.get('device') is False,
            'invalid compile/device claim')
    require(p.get('image_sha256') == row.get('image_sha256')
            and p.get('config_sha256') == row.get('config_audit', {}).get('actual_config_sha256')
            and p.get('precompile_config_sha256') == p.get('config_sha256'), 'same-build proof mismatch')
    require(p.get('mode') == 'built-in-cpu-limits-only' and p.get('qgki_enabled') is False
            and p.get('interfaces') == INTERFACES, 'unexpected interface mode')
    for key in ('config_sha256', 'image_sha256', 'command_sha256', 'object_sha256', 'source_after_sha256'):
        require(isinstance(p.get(key), str) and re.fullmatch(r'[0-9a-f]{64}', p[key]), 'invalid digest: ' + key)
    require(p.get('linked_symbols') == ['msm_performance_init', 'set_cpu_min_freq', 'get_cpu_min_freq',
                                      'set_cpu_max_freq', 'get_cpu_max_freq'], 'incomplete linked symbols')
