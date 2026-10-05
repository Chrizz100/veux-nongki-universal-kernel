#!/usr/bin/env python3
"""Compile the actual battery getter; test source selection and read failures."""
import argparse
import hashlib
from pathlib import Path
from test_wt_pm import reviewed_baseline
import re
import subprocess
import tempfile

SCOPE_SHA256 = '83b307229ba9c9070b58381e8d261cb6528eaa76e0c459ee2bf6a33f444595b1'


def getter(source):
    start = source.index('static int batt_psy_get_prop(')
    end = source.index('\nstatic int batt_psy_set_prop(', start)
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--baseline', action='store_true', help='reproduce the two original bugs')
    args = parser.parse_args()
    source = reviewed_baseline(args.source.read_text())
    start = source.index('\tcase POWER_SUPPLY_PROP_VOLTAGE_NOW:', source.index('static int batt_psy_get_prop('))
    end = source.index('\tcase POWER_SUPPLY_PROP_VOLTAGE_MAX:', start)
    scope = source[:start] + '<BATTERY_VOLTAGE_CASE>\n' + source[end:]
    if hashlib.sha256(scope.encode()).hexdigest() != SCOPE_SHA256:
        raise SystemExit('battery voltage scope drift: unrelated driver code changed')
    function = getter(source)
    properties = list(dict.fromkeys(re.findall(r'\bPOWER_SUPPLY_PROP_\w+', function)))
    channels = sorted(set(re.findall(r'\b(?:BATT_QG_|MAIN_|CHARGE_PUMP_)\w+', function)))
    fields = sorted(set(re.findall(r'chg->(\w+)', function)))
    header = '#include <errno.h>\n#include <limits.h>\n#include <stdbool.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
    header += 'enum power_supply_property { ' + ', '.join(properties) + ' };\n'
    header += 'enum { ' + ', '.join(channels) + ' };\n'
    header += 'struct batt_chg { ' + ''.join('int '+v+'; ' for v in fields) + ' };\n'
    header += r'''
enum { BMS=1, CP_MASTER=2, MAIN=3, POWER_SUPPLY_STATUS_DISCHARGING=10,
       POWER_SUPPLY_STATUS_CHARGING=11, POWER_SUPPLY_STATUS_FULL=12,
       POWER_SUPPLY_HEALTH_GOOD=13, POWER_SUPPLY_TECHNOLOGY_LIPO=14 };
struct power_supply { struct batt_chg *data; };
union power_supply_propval { int intval; };
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)
static struct batt_chg chip;
static struct power_supply psy = { &chip };
static int values[4], errors[4], calls, devices[4], chans[4], poison;
static int assertions;
static void *power_supply_get_drvdata(struct power_supply *p) { return p->data; }
static int get_real_type(struct batt_chg *p) { (void)p; abort(); }
static int get_prop_batt_health(struct batt_chg *p, union power_supply_propval *v) { (void)p; (void)v; abort(); }
static int batt_get_prop_batt_charge_type(struct batt_chg *p, union power_supply_propval *v) { (void)p; (void)v; abort(); }
static int get_boot_mode(void) { abort(); }
static int batt_get_iio_channel(struct batt_chg *p, int type, int channel, int *out) {
    (void)p;
    if (calls >= 4 || type < BMS || type > MAIN) abort();
    devices[calls] = type; chans[calls] = channel; calls++;
    if (type==BMS && channel!=BATT_QG_VOLTAGE_NOW) abort();
    if (type==CP_MASTER && channel!=CHARGE_PUMP_SC_BATTERY_VOLTAGE) abort();
    if (type==MAIN && channel!=MAIN_VBAT_VOLTAGE) abort();
    if (errors[type] < 0) {
        if (poison) *out=INT_MAX; /* Even a failed provider may overwrite its output. */
        return errors[type];
    }
    *out=values[type];
    return errors[type];
}
#define CHECK(x) do { assertions++; if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); return 1; } } while(0)
static void reset(int temp, int online, int present) {
    memset(&chip,0,sizeof(chip)); memset(errors,0,sizeof(errors));
    memset(devices,0,sizeof(devices)); memset(chans,0,sizeof(chans));
    chip.battery_temp=temp; chip.real_type=online; chip.is_battery_on=present;
    chip.charge_voltage_max=4480000; chip.batt_current_max=12200000;
    chip.input_batt_current_max=6100000; chip.system_temp_level=5;
    calls=poison=0; values[BMS]=4200000; values[CP_MASTER]=4050; values[MAIN]=4170;
}
'''
    baseline = r'''
int main(void) {
    union power_supply_propval v; int rc;
    reset(100,1,1); v.intval=-999;
    rc=batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&v);
    CHECK(rc==0); CHECK(calls==2); CHECK(devices[0]==CP_MASTER); CHECK(devices[1]==BMS);
    CHECK(v.intval==4200000);
    printf("REPRO_COLD_OVERWRITE=CONFIRMED; temperature=10.0C; CP=4050mV; expected=4055000uV; actual=%duV; reads=%d\n",v.intval,calls);
    reset(250,1,1); errors[BMS]=-EIO; v.intval=1234567;
    rc=batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&v);
    CHECK(rc==0); CHECK(v.intval==1234567); CHECK(calls==1);
    printf("REPRO_IGNORED_BMS_ERROR=CONFIRMED; IIO=-EIO; returned=%d; stale_value=%d\n",rc,v.intval);
    return 0;
}
'''
    tests = r'''
int main(void) {
    union power_supply_propval v;
    struct batt_chg saved;
    int i,j,k,rc,src,expected;
    const struct { int temp, online, source; } cases[] = {
        {INT_MIN,1,BMS},{-100,1,BMS},{0,1,BMS},{1,1,CP_MASTER},
        {100,1,CP_MASTER},{149,1,CP_MASTER},{150,1,BMS},{250,1,BMS},
        {479,1,BMS},{480,1,MAIN},{600,1,MAIN},{INT_MAX,1,MAIN},
        {0,0,BMS},{1,0,BMS},{100,0,BMS},{149,0,BMS},{150,0,BMS},
        {479,0,BMS},{480,0,BMS},{600,0,BMS}
    };
    /* Boundary table covers temperatures in tenths of a degree Celsius. */
    for(i=0;i<(int)(sizeof(cases)/sizeof(cases[0]));i++) {
        for(j=0;j<2;j++) {
            reset(cases[i].temp,cases[i].online,j); saved=chip; v.intval=-999;
            src=cases[i].source;
            expected=!j ? 3800000 : src==BMS ? 4200000 : src==CP_MASTER ? 4055000 : 4175000;
            rc=batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&v);
            CHECK(rc==0); CHECK(v.intval==expected); CHECK(calls==1);
            CHECK(devices[0]==src);
            CHECK(chans[0]==(src==BMS ? BATT_QG_VOLTAGE_NOW : src==CP_MASTER ? CHARGE_PUMP_SC_BATTERY_VOLTAGE : MAIN_VBAT_VOLTAGE));
            CHECK(memcmp(&chip,&saved,sizeof(chip))==0);
        }
    }
    /* Failure on every selected provider: no stale data or fallback read. */
    const int failure_codes[]={-EIO,-EREMOTEIO,-ENODEV,-ESHUTDOWN,-517};
    const int temps[]={250,100,480};
    const int sources[]={BMS,CP_MASTER,MAIN};
    for(i=0;i<3;i++) for(j=0;j<5;j++) for(k=0;k<2;k++) {
        reset(temps[i],1,1); saved=chip; errors[sources[i]]=failure_codes[j];
        poison=k; v.intval=1234567;
        CHECK(batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&v)==-ENODATA);
        CHECK(v.intval==0); CHECK(calls==1); CHECK(devices[0]==sources[i]);
        CHECK(memcmp(&chip,&saved,sizeof(chip))==0);
    }
    /* IIO status may be non-negative; neither mV conversion nor BMS gets scaled twice. */
    for(i=0;i<3;i++) {
        reset(temps[i],1,1); errors[sources[i]]=1;
        CHECK(batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&v)==0);
        CHECK(v.intval==(sources[i]==BMS ? 4200000 : sources[i]==CP_MASTER ? 4055000 : 4175000));
    }
    const int invalid[]={-1,INT_MIN,INT_MAX/1000-4,INT_MAX};
    for(i=1;i<3;i++) for(j=0;j<4;j++) {
        reset(temps[i],1,1); values[sources[i]]=invalid[j]; v.intval=123;
        CHECK(batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&v)==-ENODATA);
        CHECK(v.intval==0); CHECK(calls==1);
    }
    const int valid_mv[]={0,3500,4200,4500,INT_MAX/1000-5};
    for(i=1;i<3;i++) for(j=0;j<5;j++) {
        reset(temps[i],1,1); values[sources[i]]=valid_mv[j];
        CHECK(batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&v)==0);
        CHECK(v.intval==(valid_mv[j]+5)*1000); CHECK(calls==1);
    }
    /* Independent calls cannot retain a previous temperature's selected source. */
    reset(100,1,1);
    CHECK(batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&v)==0); CHECK(v.intval==4055000);
    chip.battery_temp=250;
    CHECK(batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&v)==0); CHECK(v.intval==4200000);
    chip.battery_temp=480;
    CHECK(batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&v)==0); CHECK(v.intval==4175000);
    chip.real_type=0;
    CHECK(batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_NOW,&v)==0); CHECK(v.intval==4200000);
    /* Related configured limits are read back unchanged and need no provider access. */
    reset(250,1,1); saved=chip;
    CHECK(batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_VOLTAGE_MAX,&v)==0); CHECK(v.intval==4480000);
    CHECK(batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_CONSTANT_CHARGE_CURRENT_MAX,&v)==0); CHECK(v.intval==12200000);
    CHECK(batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_INPUT_CURRENT_LIMIT,&v)==0); CHECK(v.intval==6100000);
    CHECK(batt_psy_get_prop(&psy,POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT,&v)==0); CHECK(v.intval==5);
    CHECK(calls==0); CHECK(memcmp(&chip,&saved,sizeof(chip))==0);
    printf("BATTERY_VOLTAGE_HOST_TESTS=PASS; assertions=%d; temperature boundaries, provider errors, units and unchanged limits checked\n",assertions);
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='wt-battery-voltage-') as tmp:
        root = Path(tmp)
        cfile, binary = root / 'test.c', root / 'test'
        cfile.write_text(header + '\n' + function + '\n' + (baseline if args.baseline else tests))
        subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
                        '-fsanitize=undefined','-fno-sanitize-recover=all',
                        str(cfile),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True,timeout=20)
    print('BATTERY_VOLTAGE_SCOPE_GUARD=PASS; remaining driver matches charger-temp-r1 scope')


if __name__ == '__main__':
    main()
