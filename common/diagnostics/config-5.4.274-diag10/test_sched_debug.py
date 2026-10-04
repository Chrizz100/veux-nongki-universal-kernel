#!/usr/bin/env python3
"""Compile the real PM macro before/after the fix and exercise masked output."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import config_audit as a

HERE = Path(__file__).resolve().parent
SOURCE = HERE/'source/kernel/sched/debug.c'


def harness(source):
    macro = re.search(r'^#define\s+PM\(F, M\).*$', source, re.M).group(0)
    call = re.search(r'^\s*PM\(se.avg.util_est.enqueued, ~UTIL_AVG_UNCHANGED\);$',source,re.M).group(0)
    return r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define UTIL_AVG_UNCHANGED 0x80000000U
struct seq_file { char text[128]; };
struct task_struct { struct { struct { struct { uint32_t enqueued; } util_est; } avg; } se; };
#define SEQ_printf(m, ...) snprintf((m)->text, sizeof((m)->text), __VA_ARGS__)
''' + macro + r'''
static void show(struct task_struct *p, struct seq_file *m) {
''' + call + r'''
}
int main(void) {
    const uint32_t inputs[] = {0U, 1U, 1024U, 0x7fffffffU, 0x80000000U, 0x80000001U, 0x80000400U, 0xffffffffU};
    const long long expected[] = {0LL, 1LL, 1024LL, 2147483647LL, 0LL, 1LL, 1024LL, 2147483647LL};
    struct task_struct task = {0};
    struct seq_file output = {{0}};
    for (unsigned int i = 0; i < sizeof(inputs)/sizeof(inputs[0]); i++) {
        task.se.avg.util_est.enqueued = inputs[i];
        show(&task, &output);
        if (strncmp(output.text, "se.avg.util_est.enqueued", strlen("se.avg.util_est.enqueued"))) return 1;
        char *colon = strchr(output.text, ':');
        long long actual = -1;
        if (!colon || sscanf(colon+1, "%lld", &actual) != 1 || actual != expected[i]) return 2;
        if (task.se.avg.util_est.enqueued != inputs[i]) return 3;
    }
    puts("SCHED_DEBUG_MASKED_OUTPUT=PASS; cases=8");
    return 0;
}
'''


class SchedulerTests(unittest.TestCase):
    def tree(self, root):
        path=root/'kernel/sched/debug.c';path.parent.mkdir(parents=True)
        shutil.copy2(SOURCE,path)
        return path

    def compile(self, root, source):
        path=root/'macro.c';path.write_text(harness(source))
        return subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror',str(path),'-o',str(root/'macro')],
                              text=True,capture_output=True)

    def test_original_error_reproduces_with_a_real_compiler(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=self.compile(Path(tmp),SOURCE.read_text())
            self.assertNotEqual(result.returncode,0)
            self.assertIn('__PS',result.stderr)
            self.assertIn('implicit declaration',result.stderr)

    def test_repaired_real_macro_compiles_and_preserves_mask_and_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=self.tree(root);a.apply_sched_debug(root)
            result=self.compile(root,path.read_text())
            self.assertEqual(result.returncode,0,result.stderr)
            run=subprocess.run([str(root/'macro')],text=True,capture_output=True)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertIn('cases=8',run.stdout)

    def test_patch_applies_exactly_and_changes_one_macro_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=self.tree(root);before=path.read_bytes()
            subprocess.run(['git','apply','--check',str(HERE/'sched-debug-pm.patch')],cwd=root,check=True)
            subprocess.run(['git','apply',str(HERE/'sched-debug-pm.patch')],cwd=root,check=True)
            after=path.read_bytes();m=json.loads((HERE/'sched-debug-manifest.json').read_text())
            self.assertEqual(a.sha(after),m['after_sha256'])
            old,new=before.splitlines(),after.splitlines()
            self.assertEqual(len(old),len(new))
            self.assertEqual(sum(x!=y for x,y in zip(old,new)),1)
            self.assertIn(b'~UTIL_AVG_UNCHANGED',after)

    def test_unreviewed_source_and_second_application_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=self.tree(root)
            path.write_bytes(path.read_bytes()+b'/* changed */\n')
            with self.assertRaises(a.e.Blocked):a.apply_sched_debug(root)
            shutil.copy2(SOURCE,path);a.apply_sched_debug(root)
            with self.assertRaises(a.e.Blocked):a.apply_sched_debug(root)


if __name__=='__main__':
    unittest.main()
