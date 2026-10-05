#!/usr/bin/env python3
"""Compile the actual USB getter and exercise its return values and errors."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def getter(source):
    start = source.index('static int usb_psy_get_prop(')
    end = source.index('\nstatic int usb_psy_set_prop(', start)
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    function = getter(args.source.read_text())
    properties = list(dict.fromkeys(re.findall(r'\bPOWER_SUPPLY_PROP_\w+', function)))
    header = '#include <assert.h>\n#include <errno.h>\n#include <limits.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
    header += 'enum power_supply_property { ' + ', '.join(properties) + ' };\n'
    header += r'''
enum { BMS=1, MAIN=2, CP_MASTER=3, BATT_QG_PRESENT=10,
       BATT_QG_VOLTAGE_NOW=11, BATT_QG_CURRENT_NOW=12,
       CHARGE_PUMP_SC_BUS_VOLTAGE=20, POWER_SUPPLY_TYPE_USB=30,
       POWER_SUPPLY_TYPE_USB_CDP=31, POWER_SUPPLY_TYPE_USB_PD=32,
       POWER_SUPPLY_SCOPE_SYSTEM=40, QUICK_CHARGE_NORMAL=50 };
struct batt_chg {
    int charge_design_voltage_max, charge_voltage_max, batt_voltage_now;
    int batt_current_now, batt_current_max, input_batt_current_max, battery_temp;
};
struct power_supply { struct batt_chg *data; };
union power_supply_propval { int intval; };
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)
static int cp_mv, read_error, read_calls, read_type, read_channel;
static int real_type, quick_type, assertions;
static struct batt_chg chip;
static struct power_supply psy = { &chip };
static void *power_supply_get_drvdata(struct power_supply *p) { return p->data; }
static int get_real_type(struct batt_chg *p) { (void)p; return real_type; }
static int get_quick_charge_type(struct batt_chg *p) { (void)p; return quick_type; }
static int batt_get_iio_channel(struct batt_chg *p, int type, int channel, int *out) {
    (void)p; read_calls++; read_type=type; read_channel=channel;
    if (read_error) return read_error; /* A failed read need not initialize out. */
    if (type==CP_MASTER && channel==CHARGE_PUMP_SC_BUS_VOLTAGE) *out=cp_mv;
    else if (type==BMS && channel==BATT_QG_CURRENT_NOW) *out=-500000;
    else if (type==BMS && channel==BATT_QG_VOLTAGE_NOW) *out=4400000;
    else if (type==BMS && channel==BATT_QG_PRESENT) *out=1;
    else abort();
    return 0;
}
#define CHECK(x) do { assertions++; if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); return 1; } } while(0)
static void reset(void) {
    memset(&chip,0,sizeof(chip)); chip.batt_voltage_now=1234567;
    chip.charge_voltage_max=4480000; chip.charge_design_voltage_max=4480000;
    chip.batt_current_max=12200000; chip.input_batt_current_max=6100000;
    real_type=POWER_SUPPLY_TYPE_USB_PD; quick_type=77;
    cp_mv=5000; read_error=read_calls=read_type=read_channel=0;
}
'''
    if 'wt_get_usb_type(' in function:
        header += 'static int wt_get_usb_type(struct batt_chg *p, int *v) { (void)p; (void)v; abort(); }\n'
    tests = r'''
int main(void) {
    union power_supply_propval value;
    int rc, n;
    const int samples[]={0,4600,4680,4700,4743,5100,9000,12000,20000,INT_MAX/1000};
    for(n=0;n<(int)(sizeof(samples)/sizeof(samples[0]));n++) {
        reset(); cp_mv=samples[n]; value.intval=-999;
        rc=usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&value);
        CHECK(rc==0); CHECK(value.intval==samples[n]*1000);
        CHECK(read_calls==1); CHECK(read_type==CP_MASTER);
        CHECK(read_channel==CHARGE_PUMP_SC_BUS_VOLTAGE);
        CHECK(chip.batt_voltage_now==1234567);
    }
    const int failures[]={-EIO,-EREMOTEIO,-ENODEV,-ESHUTDOWN,-517};
    for(n=0;n<(int)(sizeof(failures)/sizeof(failures[0]));n++) {
        reset(); read_error=failures[n]; value.intval=456789;
        rc=usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&value);
        CHECK(rc==-ENODATA); CHECK(value.intval==0); CHECK(read_calls==1);
        CHECK(chip.batt_voltage_now==1234567);
    }
    const int invalid[]={-1,INT_MIN,INT_MAX/1000+1,INT_MAX};
    for(n=0;n<(int)(sizeof(invalid)/sizeof(invalid[0]));n++) {
        reset(); cp_mv=invalid[n]; value.intval=456789;
        CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&value)==-ENODATA);
        CHECK(value.intval==0);
    }
    /* Existing unrelated property behavior is retained. */
    reset();
    CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_MAX,&value)==0);
    CHECK(value.intval==4480000); CHECK(read_calls==0);
    CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_MAX_DESIGN,&value)==0);
    CHECK(value.intval==4480000);
    CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_CURRENT_NOW,&value)==0);
    CHECK(value.intval==500000); CHECK(read_type==BMS);
    CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_CURRENT_MAX,&value)==0);
    CHECK(value.intval==12200000);
    CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_INPUT_CURRENT_LIMIT,&value)==0);
    CHECK(value.intval==6100000);
    CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_PRESENT,&value)==0); CHECK(value.intval==1);
    CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_ONLINE,&value)==0); CHECK(value.intval==1);
    real_type=0;
    CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_ONLINE,&value)==0); CHECK(value.intval==0);
    real_type=POWER_SUPPLY_TYPE_USB;
    CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_TYPE,&value)==0); CHECK(value.intval==POWER_SUPPLY_TYPE_USB);
    real_type=POWER_SUPPLY_TYPE_USB_PD;
    CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_TYPE,&value)==0); CHECK(value.intval==POWER_SUPPLY_TYPE_USB_PD);
    CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_SCOPE,&value)==0); CHECK(value.intval==POWER_SUPPLY_SCOPE_SYSTEM);
    CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_QUICK_CHARGE_TYPE,&value)==0); CHECK(value.intval==77);
    chip.battery_temp=580;
    CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_QUICK_CHARGE_TYPE,&value)==0); CHECK(value.intval==QUICK_CHARGE_NORMAL);
    CHECK(usb_psy_get_prop(&psy,(enum power_supply_property)999,&value)==-ENODATA);
    printf("USB_VOLTAGE_HOST_TESTS=PASS; assertions=%d; mV-to-uV, source, errors and unchanged properties checked\n", assertions);
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='wt-usb-voltage-') as tmp:
        root = Path(tmp)
        cfile, binary = root / 'test.c', root / 'test'
        cfile.write_text(header + '\n' + function + '\n' + tests)
        subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=undefined', '-fno-sanitize-recover=all',
                        str(cfile), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=20)


if __name__ == '__main__':
    main()
