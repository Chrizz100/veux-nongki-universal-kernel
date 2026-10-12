#!/usr/bin/env python3
"""Offline regressions for SUSFS GitLab transient transport handling.

Run by unchanged R3 GitHub workflow: unittest discover -s Tests -p test_veux_*r3.py
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'common/scripts'))
import veux_fleet_35222_selinux_r3 as fleet

OVERLOADED = 'COMMAND_FAILURE git rc=128: fatal: remote error: GitLab is currently unable to handle this request due to load'


class GitLabTransportR3Tests(unittest.TestCase):
    def test_exact_frozen_software_and_gitlab_pin(self):
        self.assertEqual(fleet.TARGETS['resukisu']['version'], '35222')
        self.assertEqual(fleet.TARGETS['resukisu']['commit'], '5b76b884c75f729a220bb317aa4a4fc78f0e0e9c')
        self.assertEqual(fleet.TARGETS['susfs']['url'], fleet.SUSFS_GITLAB_URL)
        self.assertEqual(fleet.TARGETS['susfs']['commit'], fleet.SUSFS_GITLAB_PIN)
        self.assertEqual(fleet.TARGETS['susfs']['ref'], fleet.SUSFS_GITLAB_REF)
        self.assertEqual(fleet.TARGETS['nomount']['version'], '21')
        self.assertEqual(fleet.EXPECTED_KERNEL_R3, '5.4.274')

    def test_five_attempts_with_bounded_realistic_backoff(self):
        self.assertEqual(fleet.SUSFS_GITLAB_RETRY_DELAYS, (5, 15, 30, 45))
        self.assertEqual(len(fleet.SUSFS_GITLAB_RETRY_DELAYS) + 1, 5)

    def test_exact_gitlab_load_error_is_retryable(self):
        self.assertTrue(fleet.gitlab_is_transient(fleet.FleetBlocked(OVERLOADED)))
        self.assertTrue(fleet.gitlab_is_transient(RuntimeError('RPC failed: the requested URL returned error: 503')))
        self.assertTrue(fleet.gitlab_is_transient(RuntimeError('502 Bad Gateway')))

    def test_commit_identity_failure_is_not_retryable(self):
        for reason in ('UPSTREAM_NON_FAST_FORWARD susfs', 'UNKNOWN_UPSTREAM_TIP susfs',
                       'PINNED_DONOR_IDENTITY_MISMATCH susfs',
                       'fatal: not a git repository', 'invalid source sha'):
            with self.subTest(reason=reason):
                self.assertFalse(fleet.gitlab_is_transient(fleet.FleetBlocked(reason)))

    def test_temporary_remote_head_errors_recover(self):
        results = [fleet.FleetBlocked(OVERLOADED), fleet.FleetBlocked(OVERLOADED), 'a' * 40]
        calls = []
        def op():
            calls.append(1)
            item = results.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        with tempfile.TemporaryDirectory() as temp, patch.object(fleet.time, 'sleep') as sleeper:
            result = fleet.retry_susfs_gitlab('head', op, audit=Path(temp))
            self.assertEqual(result, 'a' * 40)
            self.assertEqual(len(calls), 3)
            self.assertEqual([x.args[0] for x in sleeper.call_args_list], [5, 15])
            audit = json.loads((Path(temp) / 'SUSFS_GITLAB_HEAD.json').read_text())
            self.assertEqual(audit['status'], 'PASS')
            self.assertEqual(len(audit['attempts']), 3)
            self.assertEqual(audit['pinned_commit'], fleet.SUSFS_GITLAB_PIN)
            self.assertTrue(audit['head_is_not_a_build_pin'])
            self.assertFalse(audit['fallback_mirror_used'])

    def test_early_success_is_zero_sleep(self):
        with patch.object(fleet.time, 'sleep') as sleeper:
            self.assertEqual(fleet.retry_susfs_gitlab('head', lambda: 'verified'), 'verified')
            sleeper.assert_not_called()

    def test_exhaustion_reports_cleanly_without_claiming_pass(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(fleet.time, 'sleep') as sleeper:
            def op():
                raise fleet.FleetBlocked(OVERLOADED)
            with self.assertRaisesRegex(fleet.FleetBlocked, 'SUSFS_GITLAB_OVERLOAD_RETRY_EXHAUSTED head'):
                fleet.retry_susfs_gitlab('head', op, audit=Path(temp))
            self.assertEqual(sleeper.call_count, 4)
            audit = json.loads((Path(temp) / 'SUSFS_GITLAB_HEAD.json').read_text())
            self.assertEqual(audit['status'], 'EXHAUSTED')
            self.assertEqual(len(audit['attempts']), 5)

    def test_unknown_error_does_not_sleep_or_hide_error(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(fleet.time, 'sleep') as sleeper:
            with self.assertRaisesRegex(fleet.FleetBlocked, 'SUSFS_SOURCE_PIN_CHANGED'):
                fleet.retry_susfs_gitlab('head', lambda: (_ for _ in ()).throw(fleet.FleetBlocked('SUSFS_SOURCE_PIN_CHANGED')), audit=Path(temp))
            sleeper.assert_not_called()
            self.assertFalse((Path(temp) / 'SUSFS_GITLAB_HEAD.json').exists())

    def test_wrong_stage_fail_closed(self):
        with self.assertRaisesRegex(fleet.FleetBlocked, 'UNEXPECTED_GITLAB_RETRY_STAGE'):
            fleet.retry_susfs_gitlab('build', lambda: True)

    def test_clone_partial_directory_cleaned_before_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            donor = Path(temp) / 'bundle' / 'susfs'
            donor.parent.mkdir()
            class FakeEngine:
                def __init__(self):
                    self.calls = []
                def checkout(self, url, commit, dest, full=False):
                    self.calls.append((url,commit,dest,full))
                    if dest.exists():
                        raise AssertionError('Partial clone not cleaned')
                    dest.mkdir()
                    (dest / 'tracking.txt').write_text(str(len(self.calls)))
                    if len(self.calls) < 3:
                        raise fleet.FleetBlocked(OVERLOADED)
            engine = FakeEngine()
            with patch.object(fleet.time, 'sleep') as sleeper:
                fleet.checkout_exact_susfs_with_retry(engine, fleet.TARGETS['susfs'], donor, audit=Path(temp)/'report')
            self.assertEqual(len(engine.calls), 3)
            self.assertEqual((donor/'tracking.txt').read_text(), '3')
            self.assertEqual([x.args[0] for x in sleeper.call_args_list], [5,15])
            self.assertEqual(json.loads((Path(temp)/'report/SUSFS_GITLAB_CLONE.json').read_text())['status'], 'PASS')

    def test_wrong_pin_and_mirror_refused_before_any_network(self):
        with tempfile.TemporaryDirectory() as temp:
            donor=Path(temp)/'bundle/susfs'; donor.parent.mkdir()
            class ExplodingEngine:
                def checkout(self,*args,**kwargs):
                    raise AssertionError('MUST NOT CALL GIT')
            for tweak in ({'commit':'f'*40},{'url':'https://github.com/third-party/unverified.git'},
                          {'ref':'refs/heads/master'}):
                entry={**fleet.TARGETS['susfs'], **tweak}
                with self.assertRaisesRegex(fleet.FleetBlocked,'SUSFS_SOURCE_PIN_OR_URL_CHANGED'):
                    fleet.checkout_exact_susfs_with_retry(ExplodingEngine(),entry,donor)

    def test_cleanup_confined_to_susfs_bundle_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            d=Path(temp)
            for bad in (d/'bundle/resukisu',d/'assets/susfs'):
                bad.parent.mkdir(exist_ok=True)
                bad.mkdir()
                with self.assertRaisesRegex(fleet.FleetBlocked,'SUSFS_PARTIAL_CHECKOUT_SCOPE_CHANGED'):
                    fleet._remove_partial_susfs_checkout(bad)
                self.assertTrue(bad.exists())

    def test_cleanup_rejects_symlink_outside_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            (p/'bundle').mkdir()
            victim=p/'victim';victim.mkdir()
            (victim/'keep').write_text('DO NOT DELETE')
            (p/'bundle/susfs').symlink_to(victim, target_is_directory=True)
            with self.assertRaisesRegex(fleet.FleetBlocked,'SUSFS_PARTIAL_CHECKOUT_SYMLINK'):
                fleet._remove_partial_susfs_checkout(p/'bundle/susfs')
            self.assertEqual((victim/'keep').read_text(),'DO NOT DELETE')

    def test_clone_unrelated_error_does_not_retry_or_remove_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            donor=Path(temp)/'bundle/susfs';donor.parent.mkdir()
            class Engine:
                calls=0
                def checkout(self,*args,**kwargs):
                    self.calls+=1
                    donor.mkdir()
                    raise fleet.FleetBlocked('PINNED_DONOR_IDENTITY_MISMATCH')
            e=Engine()
            with patch.object(fleet.time,'sleep') as sleeper:
                with self.assertRaisesRegex(fleet.FleetBlocked,'PINNED_DONOR_IDENTITY_MISMATCH'):
                    fleet.checkout_exact_susfs_with_retry(e,fleet.TARGETS['susfs'],donor)
                sleeper.assert_not_called()
            self.assertEqual(e.calls,1)
            self.assertTrue(donor.exists())

    def test_pins_untouched_and_no_repository_mutation(self):
        text=(REPO/'common/scripts/veux_fleet_35222_selinux_r3.py').read_text()
        self.assertNotIn('git push ',text)
        self.assertNotIn('contents: write',text)
        self.assertIn("'only_update':'resukisu'",text)
        self.assertIn("'device_pass':False",text)
        self.assertIn('e.checkout',text)
        self.assertIn('SUSFS_GITLAB_RETRY_DELAYS',text)
        self.assertIn('gitlab_is_transient',text)

    def test_existing_r3_workflow_discovers_new_tests_unchanged(self):
        path=REPO/'.github/workflows/VEUX_V4_BakaSU_35222_SELinux_Backport_R3.yml'
        self.assertTrue(path.is_file(), 'Load the unchanged R3 workflow into the test checkout')
        text=path.read_text()
        self.assertIn("-p 'test_veux_*r3.py'",text)
        self.assertIn('ACTIONLINT_R3=PASS',text)
        self.assertIn('NO_MAIN_PROMOTION=PASS',text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
