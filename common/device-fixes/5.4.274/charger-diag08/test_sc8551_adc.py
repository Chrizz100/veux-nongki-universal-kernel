#!/usr/bin/env python3
"""Compile actual SC8551 ADC/IIO functions and inject read failures on the host."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def function(source, name):
    match = re.search(r'^static int ' + re.escape(name) + r'\(', source, re.M)
    if not match:
        raise ValueError('missing function: ' + name)
    end = source.index('\n}', match.start()) + 2
    return source[match.start():end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--baseline', action='store_true')
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    manifest = json.loads((folder / 'candidate.json').read_text())
    raw = args.source.read_bytes()
    expected = manifest['before_sha256' if args.baseline else 'after_sha256']
    if hashlib.sha256(raw).hexdigest() != expected:
        raise SystemExit('SC8551 source hash mismatch')
    source = raw.decode()
    adc = function(source, 'sc8551_get_adc_data')
    iio = function(source, 'sc_iio_read_raw')
    scope = source.replace(adc, '<ADC_GETTER>\n', 1)
    if hashlib.sha256(scope.encode()).hexdigest() != manifest['unchanged_scope_sha256']:
        raise SystemExit('unrelated SC8551 code changed')
    for name, digest in manifest['test_assets_sha256'].items():
        if hashlib.sha256((folder / name).read_bytes()).hexdigest() != digest:
            raise SystemExit('SC8551 test asset drift: ' + name)
    enum = re.search(r'typedef enum \{\s*ADC_IBUS,.*?\}ADC_CH;', source, re.S)[0]
    macros = '\n'.join(line for line in source.splitlines()
        if re.match(r'#define\s+(?:VBAT_INSERT|VBUS_INSERT|ADC_REG_BASE|\w+_(?:ALARM|FAULT)_SHIFT)\s', line))
    fields = sorted(set(re.findall(r'sc->(\w+)', adc + iio)))
    prefix = r'''
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sc8551_reg.h"
#include "qti_power_supply_iio.h"
typedef uint8_t u8;
typedef uint16_t u16;
#define BIT(n) (1U << (n))
#define IIO_VAL_INT 1
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)
'''
    prefix += enum + '\n' + macros + '\n'
    prefix += 'struct sc8551 { ' + ''.join('int ' + f + '; ' for f in fields) + ' };\n'
    prefix += r'''
struct iio_dev { struct sc8551 *chip; };
struct iio_chan_spec { int channel; };
static void *iio_priv(struct iio_dev *dev) { return dev->chip; }
static int calls, fail_at, failure, poison, expected_channel, sample;
static int assertions;
static struct sc8551 chip;
static struct iio_dev dev = { &chip };
static int sc8551_read_byte(struct sc8551 *sc, u8 reg, u8 *out) {
    (void)sc;
    if (calls >= 2 || reg != ADC_REG_BASE + (expected_channel << 1) + calls) abort();
    calls++;
    if (calls == fail_at) {
        /* Poisoned failure output makes the original-bug reproduction defined.
         * Fixed-path tests also cover the real accessor leaving output untouched. */
        if (poison) *out = 0x12;
        return failure;
    }
    *out = calls == 1 ? (u8)(sample >> 8) : (u8)sample;
    return 0;
}
static int sc8551_check_charge_enabled(struct sc8551 *sc, int *out) { (void)sc; (void)out; abort(); }
static int sc8551_check_alarm_status(struct sc8551 *sc) { (void)sc; abort(); }
static int sc8551_check_fault_status(struct sc8551 *sc) { (void)sc; abort(); }
static int sc8551_check_vbus_error_status(struct sc8551 *sc) { (void)sc; abort(); }
#define CHECK(x) do { assertions++; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); return 1; } } while (0)
static void reset(int variant, int channel, int value, int where, int error, int overwrite) {
    memset(&chip, 0, sizeof(chip)); chip.is_sc8551 = variant;
    calls = 0; expected_channel = channel; sample = value;
    fail_at = where; failure = error; poison = overwrite;
}
static int expected_value(int variant, int channel, int raw) {
    /* Independently listed pre-existing scaling; no calibration changes. */
    static const int numerator[] = {15625, 375, 5, 125, 125, 3125, 9766, 9766, 5};
    static const int denominator[] = {10000, 100, 1, 100, 100, 1000, 100000, 100000, 10};
    /* The existing driver stores the scaled result in u16, including truncation
     * at synthetic full-register extremes. Preserve that behavior here. */
    return variant ? (uint16_t)(raw * numerator[channel] / denominator[channel]) : raw;
}
static int success_cases(void) {
    const int raw_values[] = {0, 1, 255, 256, 1234, 32768, 65535};
    for (int variant = 0; variant < 2; variant++)
        for (int channel = 0; channel < ADC_MAX_NUM; channel++)
            for (unsigned n = 0; n < sizeof(raw_values)/sizeof(raw_values[0]); n++) {
                int out = -991;
                reset(variant, channel, raw_values[n], 0, 0, 0);
                CHECK(sc8551_get_adc_data(&chip, channel, &out) == 0);
                CHECK(calls == 2);
                CHECK(out == expected_value(variant, channel, raw_values[n]));
            }
    return 0;
}
'''
    baseline = r'''
int main(void) {
    CHECK(success_cases() == 0);
    int out = -991;
    reset(0, ADC_VBAT, 7, 1, -EIO, 1);
    int rc = sc8551_get_adc_data(&chip, ADC_VBAT, &out);
    CHECK(rc == 0); CHECK(calls == 2); CHECK(out == 0x1207);
    printf("SC8551_ORIGINAL_ERROR_OVERWRITE=REPRODUCED; high_read=-EIO; returned=%d; reads=%d\n", rc, calls);
    reset(0, ADC_VBAT, 7, 1, -EIO, 1);
    struct iio_chan_spec channel = {PSY_IIO_SC_BATTERY_VOLTAGE};
    chip.vbat_volt = 4321;
    rc = sc_iio_read_raw(&dev, &channel, &out, NULL, 0);
    CHECK(rc == IIO_VAL_INT); CHECK(chip.vbat_volt == 0x1207);
    printf("SC8551_ORIGINAL_IIO_FALSE_SUCCESS=REPRODUCED\n");
    return 0;
}
'''
    fixed = r'''
int main(void) {
    CHECK(success_cases() == 0);
    const int errors[] = {-EIO, -ENXIO, -ETIMEDOUT};
    for (int variant = 0; variant < 2; variant++)
        for (int channel = 0; channel < ADC_MAX_NUM; channel++)
            for (unsigned e = 0; e < sizeof(errors)/sizeof(errors[0]); e++)
                for (int where = 1; where <= 2; where++)
                    for (int overwrite = 0; overwrite < 2; overwrite++) {
                        int out = -991;
                        reset(variant, channel, 0xffff, where, errors[e], overwrite);
                        CHECK(sc8551_get_adc_data(&chip, channel, &out) == errors[e]);
                        CHECK(calls == where); CHECK(out == -991);
                    }
    const int invalid[] = {INT_MIN, -1, ADC_MAX_NUM, INT_MAX};
    for (unsigned n = 0; n < sizeof(invalid)/sizeof(invalid[0]); n++) {
        int out = -991;
        reset(1, 0, 0, 0, 0, 0);
        CHECK(sc8551_get_adc_data(&chip, invalid[n], &out) == -EINVAL);
        CHECK(calls == 0); CHECK(out == -991);
    }
    const struct { int channel, adc; size_t offset; } bindings[] = {
        {PSY_IIO_SC_BATTERY_VOLTAGE, ADC_VBAT, offsetof(struct sc8551, vbat_volt)},
        {PSY_IIO_SC_BATTERY_CURRENT, ADC_IBAT, offsetof(struct sc8551, ibat_curr)},
        {PSY_IIO_SC_BATTERY_TEMPERATURE, ADC_TBAT, offsetof(struct sc8551, bat_temp)},
        {PSY_IIO_SC_BUS_VOLTAGE, ADC_VBUS, offsetof(struct sc8551, vbus_volt)},
        {PSY_IIO_SC_BUS_CURRENT, ADC_IBUS, offsetof(struct sc8551, ibus_curr)},
        {PSY_IIO_SC_BUS_TEMPERATURE, ADC_TBUS, offsetof(struct sc8551, bus_temp)},
        {PSY_IIO_SC_DIE_TEMPERATURE, ADC_TDIE, offsetof(struct sc8551, die_temp)},
    };
    for (int variant = 0; variant < 2; variant++)
        for (unsigned n = 0; n < sizeof(bindings)/sizeof(bindings[0]); n++) {
            struct iio_chan_spec channel = {bindings[n].channel};
            int *cache = (int *)((char *)&chip + bindings[n].offset);
            for (unsigned e = 0; e < sizeof(errors)/sizeof(errors[0]); e++)
                for (int where = 1; where <= 2; where++)
                    for (int overwrite = 0; overwrite < 2; overwrite++) {
                        int out = -991;
                        reset(variant, bindings[n].adc, 0xffff, where, errors[e], overwrite);
                        *cache = 4321;
                        CHECK(sc_iio_read_raw(&dev, &channel, &out, NULL, 0) == errors[e]);
                        CHECK(calls == where); CHECK(*cache == 4321);
                    }
            int out = -991;
            reset(variant, bindings[n].adc, 1234, 0, 0, 0);
            CHECK(sc_iio_read_raw(&dev, &channel, &out, NULL, 0) == IIO_VAL_INT);
            CHECK(calls == 2); CHECK(out == *cache);
            CHECK(out == expected_value(variant, bindings[n].adc, 1234));
        }
    printf("SC8551_ADC_HOST_TESTS=PASS; assertions=%d; both read errors, 9 ADC channels, 7 IIO callers, 2 variants\n", assertions);
    return 0;
}
'''
    # Put actual driver bodies before helpers that invoke them.
    split = prefix.index('static int success_cases(void)')
    program = prefix[:split] + adc + '\n' + iio + '\n' + prefix[split:] + (baseline if args.baseline else fixed)
    with tempfile.TemporaryDirectory(prefix='sc8551-adc-host-') as tmp:
        root = Path(tmp)
        (root / 'test.c').write_text(program)
        subprocess.run(['cc', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-parameter', '-fsanitize=undefined', '-fno-sanitize-recover=all',
                        '-I', str(folder), str(root / 'test.c'), '-o', str(root / 'test')], check=True)
        subprocess.run([str(root / 'test')], check=True)
    print('SC8551_SCOPE=ADC_GETTER_ONLY; HOST_TEST_ONLY; KERNEL_BUILD=NOT_PERFORMED; DEVICE_TEST=NOT_PERFORMED')


if __name__ == '__main__':
    main()
