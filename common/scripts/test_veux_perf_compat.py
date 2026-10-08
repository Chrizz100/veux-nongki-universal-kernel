#!/usr/bin/env python3
"""Host tests for the CPU-limit integration, with explicitly simulated kernel IO."""
from contextlib import contextmanager
import copy
import gzip
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import veux_perf_compat as p

# Minimal C source shape for the include migration (not a fake kernel build).
SOURCE = '''// source-shape fixture only
#include <linux/sched/core_ctl.h>
static int set_cpu_min_freq(void) { return freq_qos_add_request(); }
static int get_cpu_min_freq(void) { return 0; }
static int set_cpu_max_freq(void) { return freq_qos_update_request(); }
static int get_cpu_max_freq(void) { return 0; }
module_param_cb(cpu_min_freq, &param_ops_cpu_min_freq, NULL, 0644);
module_param_cb(cpu_max_freq, &param_ops_cpu_max_freq, NULL, 0644);
late_initcall(msm_performance_init);
'''
ENABLED = ('MSM_PERFORMANCE', 'CPU_FREQ', 'SYSFS', 'SMP', 'IKCONFIG', 'IKCONFIG_PROC',
           'CFI_CLANG', 'THINLTO', 'STACKPROTECTOR_STRONG', 'MODULES', 'MODULE_UNLOAD', 'MODVERSIONS')
DISABLED = ('MSM_PERFORMANCE_QGKI', 'QTI_PLH', 'CFI_PERMISSIVE', 'MODULE_FORCE_LOAD', 'MODULE_FORCE_UNLOAD')
CONFIG = (''.join('CONFIG_' + x + '=y\n' for x in ENABLED) +
          ''.join('# CONFIG_' + x + ' is not set\n' for x in DISABLED)).encode()
COMMAND = ('cmd_drivers/soc/qcom/msm_performance.o := clang -fsanitize=cfi '
           '-fsanitize-cfi-cross-dso -flto=thin -fstack-protector-strong '
           '-c drivers/soc/qcom/msm_performance.c\n')
SYMBOLS = ['msm_performance_init', 'set_cpu_min_freq', 'get_cpu_min_freq',
           'set_cpu_max_freq', 'get_cpu_max_freq']


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())


def fixture(folder):
    work = Path(folder)
    src, out = work / 'src', work / 'build'
    put(src / p.DRIVER, SOURCE)
    source = p.source_patch(src)
    put(out / '.config', CONFIG)
    put(out / 'include/config/auto.conf', CONFIG)
    put(out / 'drivers/soc/qcom/msm_performance.o', b'test object, not compiled kernel code')
    put(out / 'drivers/soc/qcom/.msm_performance.o.cmd', COMMAND)
    put(out / 'System.map', ''.join(f'ffffff0000{i:06x} t {n}.llvm.123\n' for i, n in enumerate(SYMBOLS)))
    data = (b'IKCFG_ST' + gzip.compress(CONFIG, mtime=0) + b'IKCFG_ED' +
            b'msm_performance.cpu_min_freq\0msm_performance.cpu_max_freq\0')
    image = out / 'Image'
    put(image, data)
    row = {'kernel': p.KERNEL, 'compile': True, 'image_sha256': p.digest(data),
           'config_audit': {'actual_config_sha256': p.digest(CONFIG)}}
    pending = {'precompile': True, 'precompile_config_sha256': p.digest(CONFIG), 'source_patch': source}
    return work, {'source': str(src)}, image, row, pending


class SourceTests(unittest.TestCase):
    def test_include_guard_first_and_repeat(self):
        with tempfile.TemporaryDirectory() as folder:
            src = Path(folder); put(src / p.DRIVER, SOURCE)
            p.source_patch(src); before = (src / p.DRIVER).read_bytes()
            p.source_patch(src)
            self.assertEqual(before, (src / p.DRIVER).read_bytes())
            self.assertEqual(before.decode().replace(p.GUARDED, p.INCLUDE), SOURCE)

    def test_missing_or_duplicate_include_rejected_without_write(self):
        for text in (SOURCE.replace(p.INCLUDE, ''), SOURCE + p.INCLUDE + '\n'):
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / p.DRIVER; put(path, text)
                with self.assertRaises(ValueError): p.source_patch(Path(folder))
                self.assertEqual(path.read_text(), text)

    def test_unexpected_conditional_rejected(self):
        text = SOURCE.replace(p.INCLUDE, '#ifdef OTHER\n' + p.INCLUDE + '\n#endif')
        with tempfile.TemporaryDirectory() as folder:
            put(Path(folder) / p.DRIVER, text)
            with self.assertRaises(ValueError): p.source_patch(Path(folder))

    def test_callbacks_permissions_and_qos_not_dummy_nodes(self):
        for token in ('0644', 'freq_qos_add_request', 'set_cpu_max_freq',
                      'late_initcall(msm_performance_init)'):
            with tempfile.TemporaryDirectory() as folder:
                put(Path(folder) / p.DRIVER, SOURCE.replace(token, 'removed'))
                with self.assertRaises(ValueError): p.source_patch(Path(folder))

    def test_guard_preprocessor_no_missing_header_when_qgki_disabled(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'guard.c'; put(path, p.GUARDED + '\nint intact;\n')
            good = subprocess.run(['cc', '-E', '-P', '-nostdinc', str(path)], capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertIn('int intact;', good.stdout)
            bad = subprocess.run(['cc', '-E', '-P', '-nostdinc', '-DCONFIG_MSM_PERFORMANCE_QGKI=1', str(path)],
                                 capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn('core_ctl.h', bad.stderr)

    def test_symlink_source_is_not_modified(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); outside=root/'outside.c'; put(outside,SOURCE)
            path=root/'src'/p.DRIVER; path.parent.mkdir(parents=True); path.symlink_to(outside)
            with self.assertRaises(ValueError): p.source_patch(root/'src')
            self.assertEqual(outside.read_text(),SOURCE)


class PolicyTests(unittest.TestCase):
    def test_candidate_only_274(self):
        target={'candidate_manual_build':True}
        self.assertTrue(p.requested(target,p.KERNEL))
        for label in ('5.4.292','5.4.293','5.4.300','5.4.301','5.4.302'):
            self.assertFalse(p.requested(target,label))
        self.assertFalse(p.requested({},p.KERNEL))

    def test_candidate_cannot_omit_repair(self):
        with self.assertRaises(ValueError): p.requested({'candidate_manual_build':True,'performance_required':[]},p.KERNEL)

    def test_invalid_policy(self):
        for value in ('5.4.274',[p.KERNEL,p.KERNEL],['5.4.302'],None,[{}]):
            with self.assertRaises(ValueError): p.requested({'performance_required':value},p.KERNEL)

    def test_required_settings(self):
        for name in ENABLED:
            with self.assertRaises(ValueError): p.check_config(CONFIG.replace(('CONFIG_'+name+'=y').encode(),('# CONFIG_'+name+' is not set').encode()))
        for name in DISABLED:
            with self.assertRaises(ValueError): p.check_config(CONFIG.replace(('# CONFIG_'+name+' is not set').encode(),('CONFIG_'+name+'=y').encode()))

    def test_duplicate_config_rejected(self):
        with self.assertRaises(ValueError): p.options(CONFIG+b'CONFIG_MSM_PERFORMANCE=y\n')

    def test_non_candidate_scope_needs_no_fixture_source(self):
        with p.compiler_scope(None, {}, {}, Path('/unused')) as proof:
            self.assertIsNone(proof)

    def test_compiler_flags_checked_only_in_command(self):
        self.assertEqual(len(p.command_proof(COMMAND)),64)
        for text in (COMMAND.replace('-fsanitize=cfi',''), COMMAND.replace('-flto=thin',''),
                     COMMAND.replace('-fsanitize-cfi-cross-dso',''), COMMAND+'\n'+COMMAND,
                     COMMAND.replace(' -c ', ' -fno-stack-protector -c ')):
            with self.assertRaises(ValueError): p.command_proof(text)


class BuildTests(unittest.TestCase):
    def test_complete_simulated_build_and_verifier(self):
        with tempfile.TemporaryDirectory() as folder:
            args=fixture(folder); proof=p.verify_build(args[1],args[0],*args[2:]);p.verify_result(args[3])
            self.assertFalse(proof['device'])
            self.assertTrue((args[0]/'config-reports/PERFORMANCE.json').is_file())

    def test_missing_object_or_command_rejected(self):
        for name in ('msm_performance.o','.msm_performance.o.cmd'):
            with tempfile.TemporaryDirectory() as folder:
                a=fixture(folder);(a[0]/'build/drivers/soc/qcom'/name).unlink()
                with self.assertRaises(ValueError):p.verify_build(a[1],a[0],*a[2:])

    def test_linked_function_required(self):
        for symbol in SYMBOLS:
            with tempfile.TemporaryDirectory() as folder:
                a=fixture(folder);s=a[0]/'build/System.map';s.write_text(s.read_text().replace(symbol,'absent'))
                with self.assertRaises(ValueError):p.verify_build(a[1],a[0],*a[2:])

    def test_parameter_name_required(self):
        with tempfile.TemporaryDirectory() as folder:
            a=fixture(folder);a[2].write_bytes(a[2].read_bytes().replace(b'msm_performance.cpu_max_freq',b'not_the_real_parameter'))
            a[3]['image_sha256']=p.digest(a[2].read_bytes())
            with self.assertRaises(ValueError):p.verify_build(a[1],a[0],*a[2:])

    def test_source_and_config_drift_rejected(self):
        for choice in ('source','config','generated'):
            with tempfile.TemporaryDirectory() as folder:
                a=fixture(folder)
                path={'source':Path(a[1]['source'])/p.DRIVER,'config':a[0]/'build/.config',
                      'generated':a[0]/'build/include/config/auto.conf'}[choice]
                data=path.read_bytes()
                path.write_bytes(data+b'\n// drift\n' if choice=='source' else data.replace(b'CONFIG_MSM_PERFORMANCE=y',b'CONFIG_MSM_PERFORMANCE=m'))
                with self.assertRaises(ValueError):p.verify_build(a[1],a[0],*a[2:])

    def test_wrong_embedded_configuration_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            a=fixture(folder);a[2].write_bytes(b'IKCFG_ST'+gzip.compress(CONFIG+b'# other\n')+b'IKCFG_ED')
            a[3]['image_sha256']=p.digest(a[2].read_bytes())
            with self.assertRaises(ValueError):p.verify_build(a[1],a[0],*a[2:])

    def test_report_cannot_be_reused_or_claim_device_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            a=fixture(folder);p.verify_build(a[1],a[0],*a[2:]);row=a[3]
            for key,val in [('device',True),('precompile',False),('mode','full-QGKI'),
                            ('config_sha256','0'*64),('image_sha256','0'*64),('linked_symbols',[])]:
                bad=copy.deepcopy(row);bad['performance_compat'][key]=val
                with self.assertRaises(ValueError):p.verify_result(bad)
            bad=copy.deepcopy(row);del bad['performance_compat']
            with self.assertRaises(ValueError):p.verify_result(bad)

    def test_embedded_duplicate_and_invalid_gzip_rejected(self):
        cfg=b'IKCFG_ST'+gzip.compress(CONFIG,mtime=0)+b'IKCFG_ED'
        for data in (cfg+cfg,b'IKCFG_ST\x1f\x8b\x08broken',b'none'):
            with self.assertRaises(ValueError):p.embedded_config(data)


class ScopeTests(unittest.TestCase):
    def exercise(self, problem=None):
        with tempfile.TemporaryDirectory() as folder:
            work=Path(folder);src=work/'src';out=work/'build'
            put(src/p.DRIVER,SOURCE)
            base=CONFIG.replace(b'CONFIG_MSM_PERFORMANCE=y',b'# CONFIG_MSM_PERFORMANCE is not set')
            if problem=='qgki':base=base.replace(b'# CONFIG_MSM_PERFORMANCE_QGKI is not set',b'CONFIG_MSM_PERFORMANCE_QGKI=y')
            put(out/'.config',base)
            seen=[]
            def original_configure(s,o):return [s/'scripts/config','--file',o/'.config','--enable','AUDIT']
            def fake_run(argv,*args,**kwargs):
                names=[str(x) for x in argv];seen.append(names)
                if '--enable' in names:
                    data=(out/'.config').read_bytes()
                    (out/'.config').write_bytes(data.replace(b'# CONFIG_MSM_PERFORMANCE is not set',b'CONFIG_MSM_PERFORMANCE=y'))
                if 'msm_performance.o' in names[-1]:
                    if problem=='compile':raise RuntimeError('simulated compiler rejection')
                    put(out/'drivers/soc/qcom/msm_performance.o',b'object')
                    put(out/'drivers/soc/qcom/.msm_performance.o.cmd',COMMAND)
                    put(kwargs['log'],'warning: real new warning' if problem=='warning' else 'target build passed\n')
                    if problem=='drift':put(out/'.config',CONFIG+b'# drift\n')
                return 'base return'
            engine=types.SimpleNamespace(run=fake_run)
            vintf=types.SimpleNamespace(configure_argv=original_configure)
            audit=types.SimpleNamespace(vintf=vintf)
            target={'candidate_manual_build':True}
            with patch.dict(sys.modules,{'veux_update_engine':engine}):
                try:
                    with p.compiler_scope(audit,{'source':str(src)},target,work) as pending:
                        if problem=='body':raise RuntimeError('simulated body failure')
                        engine.run(vintf.configure_argv(src,out))
                        ret=engine.run(['/usr/bin/make','-C',str(src),'O='+str(out),'olddefconfig'],log=work/'configure.log')
                        self.assertEqual(ret,'base return')
                        if problem=='duplicate':engine.run(['make','olddefconfig'],log=work/'configure.log')
                        self.assertTrue(pending['precompile'])
                finally:
                    self.assertIs(engine.run,fake_run)
                    self.assertIs(vintf.configure_argv,original_configure)
            self.assertTrue(any(n[-1]=='drivers/soc/qcom/msm_performance.o' for n in seen))
            self.assertIn('--enable',seen[0])
            self.assertIn('AUDIT',seen[0])
            self.assertNotIn('CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE',str(seen))

    def test_scope_runs_driver_before_full_compile(self):self.exercise()
    def test_scope_restores_on_compile_error(self):
        with self.assertRaises(RuntimeError):self.exercise('compile')
    def test_scope_restores_on_body_error(self):
        with self.assertRaises(RuntimeError):self.exercise('body')
    def test_existing_qgki_never_silently_disabled(self):
        with self.assertRaises(ValueError):self.exercise('qgki')
    def test_precompile_warnings_cannot_hide_in_incremental_build(self):
        with self.assertRaises(ValueError):self.exercise('warning')
    def test_precompile_configuration_drift_rejected(self):
        with self.assertRaises(ValueError):self.exercise('drift')
    def test_duplicate_configure_rejected(self):
        with self.assertRaises(ValueError):self.exercise('duplicate')


if __name__=='__main__':unittest.main(verbosity=2)
