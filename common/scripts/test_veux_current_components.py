#!/usr/bin/env python3
"""Reject unknown UAPI changes; exercise the actual reviewed services handler."""
from pathlib import Path
import shutil
import tempfile
import unittest
import veux_current_components as c


class CurrentComponentsTests(unittest.TestCase):
    def donor(self, root):
        ref=c.REPO/'common/upstream/resukisu/uapi5'
        (root/'uapi').mkdir()
        (root/'kernel/supercall').mkdir(parents=True)
        shutil.copy2(ref/'supercall.h',root/'uapi/supercall.h')
        (root/'kernel/supercall/dispatch.c').write_text(
            (ref/'report_event.c').read_text()+'\nstatic int do_set_sepolicy(void *arg)\n{}\n')

    def test_reviewed_uapi5_actual_c_event_protocol(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.donor(root)
            self.assertEqual(c.checked_uapi(root),5)

    def test_unknown_or_modified_interfaces_fail_closed(self):
        for mode in ('future','duplicate','header','event','missing'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.donor(root);header=root/'uapi/supercall.h'
                if mode=='future':
                    header.write_text(header.read_text().replace('UAPI_VERSION = 5;', 'UAPI_VERSION = 6;'))
                elif mode=='duplicate':
                    header.write_text(header.read_text()+'\nstatic const __u32 KERNEL_SU_UAPI_VERSION = 5;\n')
                elif mode=='header':
                    header.write_text(header.read_text().replace('EVENT_SERVICES, 4)', 'EVENT_SERVICES, 99)'))
                elif mode=='event':
                    event=root/'kernel/supercall/dispatch.c'
                    event.write_text(event.read_text().replace('return 1;', 'return 2;'))
                else:
                    header.unlink()
                with self.assertRaises((c.Blocked,OSError)):
                    c.checked_uapi(root)

    def test_previous_uapi4_remains_recognized(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'uapi').mkdir()
            (root/'uapi/supercall.h').write_text('static const __u32 KERNEL_SU_UAPI_VERSION = 4;\n')
            self.assertEqual(c.checked_uapi(root),4)


if __name__=='__main__':
    unittest.main()
