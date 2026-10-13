#!/usr/bin/env python3
"""R3 workflow-compatible entrypoint: runs R1 hook-failure tests and checks
source-only staging, without any GitHub Action/YAML mutation.

Existing R3 gate selects test_veux_*r3.py.  Importing this TestCase is
intentional: unittest discovery executes all real R1 test methods as well.
"""
from pathlib import Path
import ast, hashlib, re, unittest
from test_veux_bakasu_unhook_guard_r1 import SourceGuardTests
import veux_bakasu_unhook_guard_r1 as guard

REPO=Path(__file__).resolve().parents[1]

class SourceOnlyIntegrationR3(unittest.TestCase):
    def test_r3_preflight_real_hook_guard_order(self):
        text=(REPO/'common/scripts/veux_fleet_35222_selinux_r3.py').read_text()
        begin=text.index('def check_src(')
        end=text.index('def build(',begin)
        body=text[begin:end]
        self.assertEqual(body.count('apply_source_guard('),1)
        self.assertLess(body.index('selinux_r3.apply_source_backport('),
                        body.index('apply_source_guard('))
        self.assertLess(body.index('apply_source_guard('),
                        body.index('fixes.apply(src,kernel,work)'))
        self.assertIn("root/'report/BAKASU-UNHOOK-R1.json'",body)
        self.assertIn("status['unhook_guard_r1']",body)
        self.assertIn("'report': 'report/BAKASU-UNHOOK-R1.json'",body)
        self.assertIn("'source_only_staged': True",body)
        self.assertIn('UNHOOK_R1_SOURCE_PROOF_INCOMPLETE',body)
        self.assertIn("status['source_preflight']=True",body)

    def test_preflight_not_dependent_on_build_flag(self):
        source=(REPO/'common/scripts/veux_fleet_35222_selinux_r3.py').read_text()
        body=source[source.index('def check_src('):source.index('def build(')]
        self.assertNotRegex(body, r'(?m)^\s*(?:if|elif)\s+[^\n]*enable_build')
        self.assertLess(body.index('apply_source_guard('),body.index("status['source_preflight']=True"))
        self.assertTrue(guard.R4_EFFECTIVE_BAKASU_SHA256)

    def test_r3_filename_runs_R1_cases_in_existing_gate(self):
        workflow=(REPO/'.github/workflows/VEUX_V4_BakaSU_35222_SELinux_Backport_R3.yml').read_text()
        self.assertIn("-p 'test_veux_*r3.py'", workflow)
        self.assertIn("${{ runner.temp }}/veux-selinux-r3-5.4.274/report/",workflow)
        self.assertIn('class SourceGuardTests(', (REPO/'Tests/test_veux_bakasu_unhook_guard_r1.py').read_text())
        self.assertTrue(Path(__file__).name.endswith('r3.py'))
        self.assertTrue(isinstance(SourceGuardTests, type))

    def test_unchanged_workflow_and_existing_runtime_backport(self):
        flow=REPO/'.github/workflows/VEUX_V4_BakaSU_35222_SELinux_Backport_R3.yml'
        self.assertEqual(hashlib.sha256(flow.read_bytes()).hexdigest(),
                         'ff171df9661d7edb311930e9f94966b85e8d50377b04d1686d55c2d6c0323317')
        backport=(REPO/'common/scripts/veux_bakasu_selinux_backport_r3.py').read_text()
        self.assertLess(backport.index('apply_source_backport('),backport.index('apply_source_guard('))
        self.assertIn("result['unhook_guard_r1'] = unhook_guard_r1",backport)
        ast.parse((REPO/'common/scripts/veux_fleet_35222_selinux_r3.py').read_text())
