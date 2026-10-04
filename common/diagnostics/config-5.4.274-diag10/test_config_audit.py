#!/usr/bin/env python3
"""Exercise real pinned Kbuild gzip rules and fail-closed binary/config checks."""
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import config_audit as a

SOURCE = Path(__file__).parent/'source'
from test_vintf_kernel import repaired_fixture
REAL = repaired_fixture()


class ConfigTests(unittest.TestCase):
    def setup_tree(self, root):
        src, out = root/'src', root/'out'
        shutil.copytree(SOURCE, src)
        (out/'kernel').mkdir(parents=True)
        (out/'include/config').mkdir(parents=True)
        (out/'.config').write_bytes(REAL)
        (out/'include/config/auto.conf').write_bytes(REAL)
        (out/'kernel/.fork.o.cmd').write_text('cmd_kernel/fork.o := clang -flto=thin -fsanitize=cfi -fsanitize-cfi-cross-dso -fstack-protector-strong -c kernel/fork.c -o kernel/fork.o\n')
        (out/'System.map').write_text('ffff0000 T __cfi_check\nffff0010 T __stack_chk_fail\n')
        (out/'Makefile').write_text(f'''srctree := {src}
obj := kernel
KCONFIG_CONFIG ?= .config
KGZIP := gzip
PHONY += FORCE
VPATH := {src}
.DEFAULT_GOAL := kernel/config_data.gz
include {src}/scripts/Kbuild.include
include {src}/kernel/Makefile
include {src}/scripts/Makefile.lib
-include kernel/.config_data.gz.cmd
.PHONY: FORCE
FORCE:
''')
        return src, out

    def make(self, out, *args, success=True):
        p = subprocess.run(['make', '--no-print-directory', *args], cwd=out,
                           text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if success:
            self.assertEqual(p.returncode, 0, p.stdout)
            return gzip.decompress((out/'kernel/config_data.gz').read_bytes())
        self.assertNotEqual(p.returncode, 0, p.stdout)

    def test_original_fault_and_corrected_actual_kbuild_out_of_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, out = self.setup_tree(Path(tmp))
            old = self.make(out)
            self.assertEqual(old, (src/'arch/arm64/configs/stock_defconfig').read_bytes())
            self.assertNotEqual(old, REAL)
            a.apply(src)
            self.assertEqual(self.make(out), REAL)
            self.assertEqual((out/'.config').read_bytes(), REAL)
            # The dependency follows subsequent configuration changes.
            updated = REAL+b'CONFIG_TEST_NEW=y\n'
            (out/'.config').write_bytes(updated)
            self.assertEqual(self.make(out), updated)

    def test_custom_kconfig_path_and_missing_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, out = self.setup_tree(Path(tmp)); a.apply(src)
            alternate = out/'custom.config'; alternate.write_bytes(REAL+b'CONFIG_CUSTOM=y\n')
            self.assertEqual(self.make(out, 'KCONFIG_CONFIG='+str(alternate)), alternate.read_bytes())
            alternate.unlink()
            self.make(out, 'KCONFIG_CONFIG='+str(alternate), success=False)

    def test_patch_changes_two_reviewed_lines_and_rejects_unreviewed_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, out = self.setup_tree(Path(tmp))
            before = {p.relative_to(src):p.read_bytes() for p in src.rglob('*') if p.is_file()}
            a.apply(src)
            changed = [p for p, data in before.items() if (src/p).read_bytes() != data]
            self.assertEqual(set(changed), {Path('kernel/Makefile'),Path('kernel/sched/debug.c')})
            for name in changed:
                old, new = before[name].splitlines(), (src/name).read_bytes().splitlines()
                self.assertEqual(len(old), len(new))
                self.assertEqual(sum(x != y for x,y in zip(old,new)), 1)
            with self.assertRaisesRegex(a.e.Blocked, 'baseline drift'):
                a.apply(src)

    def test_image_extraction_rejects_truncated_corrupt_duplicate_and_missing_data(self):
        good = b'prefixIKCFG_ST'+gzip.compress(REAL)+b'IKCFG_EDsuffix'
        self.assertEqual(a.extract(good), REAL)
        for data in (b'no config', good[:-15], good+good,
                     b'IKCFG_ST'+gzip.compress(REAL)[:-6]+b'BADCRC'+b'IKCFG_ED'):
            with self.subTest(data=data[:15]), self.assertRaises(a.e.Blocked):
                a.extract(data)

    def audit_fixture(self, root):
        src, out = self.setup_tree(root); manifest = a.apply(src); self.make(out)
        image = out/'Image'
        image.write_bytes(b'IKCFG_ST'+(out/'kernel/config_data.gz').read_bytes()+b'IKCFG_ED')
        reports = root/'reports'; reports.mkdir()
        return src, out, image, reports, manifest

    def test_consistent_config_image_and_core_flags_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            src,out,image,reports,manifest = self.audit_fixture(Path(tmp))
            result = a.verify_build(src,out,image,REAL,reports,manifest)
            self.assertEqual(result['cfi'], 'configured-and-core-instrumented')
            self.assertEqual(result['actual_config_sha256'], result['embedded_config_sha256'])
            self.assertEqual(result['options']['CFI_CLANG'], 'y')
            self.assertEqual(result['vintf_kernel']['passed'],261)
            self.assertFalse(result['device'])

    def test_bad_config_image_auto_or_compiler_evidence_blocks(self):
        for fault in ('changed-config','wrong-image','wrong-gzip','auto-conf','cfi-flag','missing-command','makefile'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                src,out,image,reports,manifest = self.audit_fixture(Path(tmp))
                if fault == 'changed-config': (out/'.config').write_bytes(REAL+b'CONFIG_NEW=y\n')
                if fault == 'wrong-image': image.write_bytes(b'IKCFG_ST'+gzip.compress(b'wrong')+b'IKCFG_ED')
                if fault == 'wrong-gzip': (out/'kernel/config_data.gz').write_bytes(gzip.compress(b'wrong'))
                if fault == 'auto-conf': (out/'include/config/auto.conf').write_text('CONFIG_CFI_CLANG=y\n')
                if fault == 'cfi-flag': (out/'kernel/.fork.o.cmd').write_text('clang -fsanitize=cfi -c fork.c')
                if fault == 'missing-command': (out/'kernel/.fork.o.cmd').unlink()
                if fault == 'makefile': (src/'kernel/Makefile').write_text('wrong')
                with self.assertRaises((a.e.Blocked, OSError)):
                    a.verify_build(src,out,image,REAL,reports,manifest)

    def test_compile_wrapper_captures_real_config_and_restores_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); src,out = self.setup_tree(root)
            work=root; state={'source':str(src),'variables':['O='+str(out)]}
            reports=root/'reports'; orig_run=a.e.run
            def compile_fixture(label,state,targets,work,jobs):
                build=work/'build'; shutil.copytree(out,build)
                a.e.run(['true'],log=work/'compile.log')
                self.make(build)
                image=build/'Image'; image.write_bytes(b'IKCFG_ST'+(build/'kernel/config_data.gz').read_bytes()+b'IKCFG_ED')
                return image, {}
            with mock.patch.object(a.e, 'compile_kernel', side_effect=compile_fixture) as original:
                with a.compiler_audit(reports):
                    _,result=a.e.compile_kernel('5.4.274',state,{},work,1)
                    self.assertEqual(result['config_audit']['status'],'PASS')
                self.assertIs(a.e.compile_kernel,original)
            self.assertIs(a.e.run,orig_run)
            self.assertEqual((reports/'actual-build.config').read_bytes(),REAL)

    def test_compile_failure_preserves_config_and_restores_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src,out=self.setup_tree(root)
            original_run=a.e.run
            def fail(label,state,targets,work,jobs):
                shutil.copytree(out,root/'build')
                a.e.run(['false'],log=work/'compile.log')
            with mock.patch.object(a.e,'compile_kernel',side_effect=fail) as original:
                with self.assertRaises(a.e.Blocked):
                    with a.compiler_audit(root/'reports'):
                        a.e.compile_kernel('5.4.274',{'source':str(src),'variables':['O='+str(out)]},{},root,1)
                self.assertIs(a.e.compile_kernel,original)
            self.assertIs(a.e.run,original_run)
            self.assertEqual((root/'reports/final-build.config').read_bytes(),REAL)


if __name__ == '__main__':
    unittest.main()
