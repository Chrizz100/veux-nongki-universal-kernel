#!/usr/bin/env python3
"""Exercise transport failure using a real local Git mirror and archive."""
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock
import veux_source_transport as t
import veux_update_engine as e


class SourceTransportTests(unittest.TestCase):
    def fixture(self, root):
        mirror = root / 'mirror'
        mirror.mkdir()
        e.git(mirror, 'init', '-q')
        e.git(mirror, 'config', 'user.name', 'test')
        e.git(mirror, 'config', 'user.email', 'test@example.invalid')
        clang = mirror / 'clang-r547379/bin/clang'
        clang.parent.mkdir(parents=True)
        clang.write_bytes(b'compiler-fixture\n')
        clang.chmod(0o755)
        (mirror / 'clang-r547379/bin/cc').symlink_to('clang')
        (mirror / 'clang-r547379/BUILD_INFO').write_text('build-fixture\n')
        (mirror / 'unrelated').write_text('must not enter the archive')
        e.git(mirror, 'add', '.')
        e.git(mirror, 'commit', '-qm', 'fixture')
        pin = dict(t.PIN, repo=str(mirror), commit=e.git(mirror, 'rev-parse', 'HEAD'),
                   root_tree=e.git(mirror, 'rev-parse', 'HEAD^{tree}'),
                   subtree=e.git(mirror, 'rev-parse', 'HEAD:clang-r547379'))
        source, work = root / 'source', root / 'work'
        source.mkdir()
        work.mkdir()
        env = {'VEUX_SOURCE_WORK': str(source), 'VEUX_TRANSPORT_WORK': str(work)}
        return pin, env, source / 'clang.tar.gz'

    def test_http_failure_exports_exact_subtree_and_preserves_executable_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            pin, env, output = self.fixture(Path(tmp))
            output.write_bytes(b'incomplete-primary-download')
            with mock.patch.object(t, 'PIN', pin), mock.patch.dict(os.environ, env), \
                 mock.patch.object(t, 'primary_download', return_value=False):
                t.transport_curl(['--fail', pin['url'], '-o', str(output)])
            with tarfile.open(output) as archive:
                self.assertEqual(archive.extractfile('bin/clang').read(), b'compiler-fixture\n')
                self.assertEqual(archive.getmember('bin/clang').mode & 0o111, 0o111)
                self.assertTrue(archive.getmember('bin/cc').issym())
                self.assertEqual(archive.getmember('bin/cc').linkname, 'clang')
                self.assertNotIn('unrelated', archive.getnames())
                self.assertNotIn('clang-r547379', archive.getnames())
            self.assertEqual(list(Path(env['VEUX_TRANSPORT_WORK']).iterdir()), [])

    def test_wrong_tree_blocks_archive_export(self):
        for field in ('root_tree', 'subtree'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                pin, env, output = self.fixture(Path(tmp))
                pin[field] = '0' * 40
                with mock.patch.object(t, 'PIN', pin), mock.patch.dict(os.environ, env), \
                     mock.patch.object(t, 'primary_download', return_value=False):
                    with self.assertRaisesRegex(e.Blocked, 'mismatch'):
                        t.transport_curl([pin['url'], '-o', str(output)])
                self.assertFalse(output.exists())

    def test_primary_success_does_not_fetch_mirror(self):
        with tempfile.TemporaryDirectory() as tmp:
            pin, env, output = self.fixture(Path(tmp))
            with mock.patch.object(t, 'PIN', pin), mock.patch.dict(os.environ, env), \
                 mock.patch.object(t, 'primary_download', return_value=True), \
                 mock.patch.object(e, 'git') as git:
                t.transport_curl([pin['url'], '-o', str(output)])
                git.assert_not_called()

    def test_rejects_output_escape_before_network_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pin, env, _ = self.fixture(root)
            for args in ([pin['url']], [pin['url'], '-o', str(root/'outside')],
                         [pin['url'], '-o', 'a', '--output', 'b']):
                with mock.patch.dict(os.environ, env), mock.patch.object(t, 'primary_download') as primary:
                    with self.assertRaises(e.Blocked):
                        t.transport_curl(args)
                    primary.assert_not_called()

    def test_other_urls_retain_legacy_r416183b_transport(self):
        for url in (e.config()['toolchain_transport']['url'], 'https://example.invalid/file'):
            args = [url, '-o', '/unused']
            with mock.patch.object(e, 'transport_curl') as legacy, \
                 mock.patch.object(t, 'primary_download') as primary:
                t.transport_curl(args)
                legacy.assert_called_once_with(args)
                primary.assert_not_called()

    def test_timeout_and_failed_curl_request_fallback(self):
        for result in (subprocess.CompletedProcess([], 22), subprocess.TimeoutExpired('curl', 180)):
            with mock.patch.object(t.subprocess, 'run') as run:
                if isinstance(result, Exception):
                    run.side_effect = result
                else:
                    run.return_value = result
                self.assertFalse(t.primary_download(['--fail', t.PIN['url']]))

    def test_materializer_uses_new_shim_and_restores_legacy_entry_on_success_or_failure(self):
        original = e.HERE
        for fail in (False, True):
            def materialize(label, work):
                self.assertEqual(e.HERE, Path(t.__file__).resolve())
                if fail:
                    raise e.Blocked('injected materialization failure')
                return {'source': str(work)}
            with mock.patch.object(e, 'materialize', side_effect=materialize):
                if fail:
                    with self.assertRaises(e.Blocked):
                        t.materialize('5.4.292', Path('/unused'))
                else:
                    self.assertEqual(t.materialize('5.4.292', Path('/unused')), {'source': '/unused'})
            self.assertEqual(e.HERE, original)

    def test_workflow_runs_transport_tests(self):
        workflow = e.yaml_read(e.REPO / '.github/workflows/veux-all-in-one-updater-v4.yml')
        scripts = '\n'.join(s.get('run', '') for s in workflow['jobs']['update']['steps'])
        self.assertIn('test_veux_source_transport.py', scripts)

    def test_real_child_shim_captures_make_without_compiling(self):
        cfg = {'lineages': {'5.4.292': {'workflow': 'fixture.yml'}}}
        recipe = {'jobs': {'fixture': {'steps': [
            {'name': 'capture fixture', 'run': 'mkdir kernel\ncd kernel\nmake ARCH=arm64 O=out Image dtbs\nexit 91\n'}
        ]}}}
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            with mock.patch.object(e, 'check_repo', return_value=(cfg, {})), \
                 mock.patch.object(e, 'yaml_read', return_value=recipe):
                state = t.materialize('5.4.292', work)
            self.assertEqual(state['targets'], ['Image', 'dtbs'])
            self.assertEqual(state['variables'], ['ARCH=arm64', 'O=out'])
            self.assertEqual(Path(state['source']), work / 'source-work/kernel')
            for name in ('make', 'curl'):
                self.assertIn(str(Path(t.__file__).resolve()), (work / 'source-temp/bin' / name).read_text())


if __name__ == '__main__':
    unittest.main()
