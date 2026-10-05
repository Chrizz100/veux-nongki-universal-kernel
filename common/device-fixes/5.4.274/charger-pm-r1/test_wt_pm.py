#!/usr/bin/env python3
"""Verify the complete WT diff against the flashed driver, without simulating PM."""
import argparse
import hashlib
from pathlib import Path
import re

FLASHED_SHA256 = '107cbc7bc8c1816f9821bcef8a201ef2977c948e5acd171ec2b7a4c4c1650ce4'
QUEUE = re.compile(r'queue_delayed_work\(system_freezable_wq, &(chg|batt_chg)->batt_chg_work,')


def reviewed_baseline(source):
    restored, count = QUEUE.subn(r'schedule_delayed_work(&\1->batt_chg_work,', source)
    if count != 8 or hashlib.sha256(restored.encode()).hexdigest() != FLASHED_SHA256:
        raise ValueError('WT PM scope drift: require exactly eight queue changes and the flashed baseline')
    return restored


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    source = args.source.read_text()
    baseline = reviewed_baseline(source)
    # Source-regression checks, not a model of the kernel scheduler.
    rejected = 0
    mutations = [baseline]
    for match in QUEUE.finditer(source):
        mutations.append(source[:match.start()] +
                         f'schedule_delayed_work(&{match[1]}->batt_chg_work,' +
                         source[match.end():])
    mutations.extend([
        source.replace('system_freezable_wq', 'system_wq', 1),
        source.replace('msecs_to_jiffies(1000)', 'msecs_to_jiffies(1001)', 1),
        source.replace('chg->charge_voltage_max = 4450000;',
                       'chg->charge_voltage_max = 4500000;', 1),
    ])
    for changed in mutations:
        if changed == source:
            raise AssertionError('mutation did not change the source')
        try:
            reviewed_baseline(changed)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError('unsafe or unrelated change accepted')
    print(f'WT_PM_SOURCE=PASS; FREEZABLE_ENTRY_POINTS=8; NEGATIVE_CASES={rejected}; '
          'CHARGING_POLICY=BYTE_IDENTICAL; KERNEL_BUILD=NOT_RUN; DEVICE_PASS=NO')


if __name__ == '__main__':
    main()
