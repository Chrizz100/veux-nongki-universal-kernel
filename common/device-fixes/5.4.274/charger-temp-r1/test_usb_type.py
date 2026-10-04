#!/usr/bin/env python3
"""Exercise the actual USB_TYPE callback, descriptor and kernel sysfs formatter."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def function(s, name):
    m = re.search(r'^static [^\n]+\b' + name + r'\([^;]+?\n\{', s, re.M)
    if not m:
        raise ValueError(name)
    return s[m.start():s.index('\n}', m.end()) + 2]


def declaration(s, name):
    m = re.search(r'^static [^\n]*\b' + name + r'(?:\[\])? = \{', s, re.M)
    if not m:
        raise ValueError(name)
    return s[m.start():s.index('\n};', m.end()) + 3]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source', type=Path)
    a = p.parse_args()
    s = a.source.read_text()
    refs = Path(__file__).with_name('usb_type_reference.h').read_text()
    prefix = r'''
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#define READ_ONCE(x) (x)
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)
#define dev_warn(...) (warnings++)
enum { BMS=1, MAIN=2, CP_MASTER=3, BATT_QG_PRESENT=10,
       BATT_QG_CURRENT_NOW=12, MAIN_CHARGER_TYPE=13,
       CHARGE_PUMP_SC_BUS_VOLTAGE=20, POWER_SUPPLY_SCOPE_SYSTEM=40,
       QUICK_CHARGE_NORMAL=50 };
struct batt_chg {
 int otg_enable, mishow_flag, vbus_cnt, pd_active;
 int charge_design_voltage_max, charge_voltage_max, batt_current_now;
 int batt_current_max, input_batt_current_max, battery_temp;
};
struct power_supply { struct batt_chg *data; };
struct device { int unused; };
union power_supply_propval { int intval; };
struct power_supply_desc {
 const char *name;
 enum power_supply_type type;
 enum power_supply_usb_type *usb_types;
 size_t num_usb_types;
 enum power_supply_property *properties;
 size_t num_properties;
 int (*get_property)(struct power_supply *,enum power_supply_property,union power_supply_propval *);
 int (*set_property)(struct power_supply *,enum power_supply_property,const union power_supply_propval *);
 int (*property_is_writeable)(struct power_supply *,enum power_supply_property);
};
static int main_type, read_error, reads, read_type, read_channel, policy_calls, warnings, assertions;
static void *power_supply_get_drvdata(struct power_supply *p) { return p->data; }
static int get_real_type(struct batt_chg *p) { (void)p; policy_calls++; return main_type; }
static int get_quick_charge_type(struct batt_chg *p) { (void)p; policy_calls++; return 0; }
static int batt_get_iio_channel(struct batt_chg *p, int type, int channel, int *v) {
 (void)p; reads++; read_type=type; read_channel=channel;
 if(read_error < 0) return read_error;
 if(type!=MAIN || channel!=MAIN_CHARGER_TYPE) abort();
 *v=main_type; return 0;
}
#define CHECK(x) do { assertions++; if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); return 1;} } while(0)
static struct batt_chg chip;
static struct power_supply psy={&chip};
static void reset(int type) {
 memset(&chip,0,sizeof(chip)); main_type=type;
 reads=read_error=read_type=read_channel=policy_calls=warnings=0;
}
'''
    # Keep enum declarations ahead of structures while using real pinned values.
    includes, rest = prefix.split('enum { BMS=', 1)
    source = includes + refs.split('/* SYSFS FORMATTER */')[0] + 'enum { BMS=' + rest
    for name in ('wt_get_usb_type', 'usb_psy_get_prop', 'usb_psy_set_prop', 'usb_psy_prop_is_writeable'):
        source += '\n' + function(s, name)
    for name in ('wt_usb_types', 'usb_psy_props', 'usb_psy_desc'):
        source += '\n' + declaration(s, name)
    source += '\n' + refs.split('/* SYSFS FORMATTER */')[1]
    source += r'''
int main(void) {
 const int mapping[][2]={
  {POWER_SUPPLY_TYPE_UNKNOWN,POWER_SUPPLY_USB_TYPE_UNKNOWN},
  {POWER_SUPPLY_TYPE_USB,POWER_SUPPLY_USB_TYPE_SDP},
  {POWER_SUPPLY_TYPE_USB_DCP,POWER_SUPPLY_USB_TYPE_DCP},
  {POWER_SUPPLY_TYPE_USB_CDP,POWER_SUPPLY_USB_TYPE_CDP},
  {POWER_SUPPLY_TYPE_USB_ACA,POWER_SUPPLY_USB_TYPE_ACA},
  {POWER_SUPPLY_TYPE_USB_TYPE_C,POWER_SUPPLY_USB_TYPE_C},
  {POWER_SUPPLY_TYPE_USB_PD,POWER_SUPPLY_USB_TYPE_PD},
  {POWER_SUPPLY_TYPE_USB_PD_DRP,POWER_SUPPLY_USB_TYPE_PD_DRP},
  {POWER_SUPPLY_TYPE_APPLE_BRICK_ID,POWER_SUPPLY_USB_TYPE_APPLE_BRICK_ID},
  {POWER_SUPPLY_TYPE_USB_HVDCP,POWER_SUPPLY_USB_TYPE_DCP},
  {POWER_SUPPLY_TYPE_USB_HVDCP_3,POWER_SUPPLY_USB_TYPE_DCP},
  {POWER_SUPPLY_TYPE_USB_HVDCP_3P5,POWER_SUPPLY_USB_TYPE_DCP},
  {POWER_SUPPLY_TYPE_USB_FLOAT,POWER_SUPPLY_USB_TYPE_UNKNOWN},
  {POWER_SUPPLY_TYPE_BATTERY,POWER_SUPPLY_USB_TYPE_UNKNOWN},
  {POWER_SUPPLY_TYPE_WIRELESS,POWER_SUPPLY_USB_TYPE_UNKNOWN},
  {-1,POWER_SUPPLY_USB_TYPE_UNKNOWN},{INT_MAX,POWER_SUPPLY_USB_TYPE_UNKNOWN}
 };
 union power_supply_propval v;
 struct device dev={0}; char buf[256]; int found=0;
 CHECK(POWER_SUPPLY_PROP_USB_TYPE==64);
 CHECK(POWER_SUPPLY_TYPE_USB!=POWER_SUPPLY_USB_TYPE_SDP);
 for(size_t n=0;n<usb_psy_desc.num_properties;n++)
  if(usb_psy_desc.properties[n]==POWER_SUPPLY_PROP_USB_TYPE) found++;
 CHECK(found==1);
 CHECK(usb_psy_desc.get_property==usb_psy_get_prop);
 CHECK(usb_psy_desc.property_is_writeable(&psy,POWER_SUPPLY_PROP_USB_TYPE)==0);
 CHECK(usb_psy_desc.num_usb_types==10);
 for(size_t n=0;n<usb_psy_desc.num_usb_types;n++) {
  CHECK((int)usb_psy_desc.usb_types[n]==(int)n);
  v.intval=n;
  CHECK(power_supply_show_usb_type(&dev,&usb_psy_desc,&v,buf)>0);
  char expected[32]; snprintf(expected,sizeof(expected),"[%s]",POWER_SUPPLY_USB_TYPE_TEXT[n]);
  CHECK(strstr(buf,expected)!=NULL); CHECK(warnings==0);
 }
 for(size_t n=0;n<ARRAY_SIZE(mapping);n++) {
  reset(mapping[n][0]); struct batt_chg before=chip; v.intval=-999;
  CHECK(usb_psy_desc.get_property(&psy,POWER_SUPPLY_PROP_USB_TYPE,&v)==0);
  CHECK(v.intval==mapping[n][1]); CHECK(reads==1);
  CHECK(read_type==MAIN && read_channel==MAIN_CHARGER_TYPE);
  CHECK(policy_calls==0); CHECK(memcmp(&chip,&before,sizeof(chip))==0);
  CHECK(power_supply_show_usb_type(&dev,&usb_psy_desc,&v,buf)>0); CHECK(warnings==0);
 }
 for(int pd=QTI_POWER_SUPPLY_PD_ACTIVE;pd<=QTI_POWER_SUPPLY_PD_PPS_ACTIVE;pd++) {
  reset(POWER_SUPPLY_TYPE_UNKNOWN); chip.pd_active=pd; read_error=-EIO;
  struct batt_chg before=chip;
  CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_USB_TYPE,&v)==0);
  CHECK(v.intval==(pd==QTI_POWER_SUPPLY_PD_ACTIVE?POWER_SUPPLY_USB_TYPE_PD:POWER_SUPPLY_USB_TYPE_PD_PPS));
  CHECK(reads==0 && policy_calls==0); CHECK(memcmp(&chip,&before,sizeof(chip))==0);
 }
 for(int guard=0;guard<3;guard++) for(int pd=0;pd<=2;pd++) {
  reset(POWER_SUPPLY_TYPE_USB_CDP); chip.pd_active=pd;
  if(guard==0) chip.otg_enable=1;
  if(guard==1) chip.mishow_flag=1;
  if(guard==2) chip.vbus_cnt=4;
  struct batt_chg before=chip; v.intval=99;
  CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_USB_TYPE,&v)==0);
  CHECK(v.intval==POWER_SUPPLY_USB_TYPE_UNKNOWN); CHECK(reads==0 && policy_calls==0);
  CHECK(memcmp(&chip,&before,sizeof(chip))==0);
 }
 const int failures[]={-EIO,-EREMOTEIO,-ENODEV,-ESHUTDOWN,-517};
 for(size_t n=0;n<ARRAY_SIZE(failures);n++) {
  reset(POWER_SUPPLY_TYPE_USB_DCP); read_error=failures[n]; v.intval=99;
  struct batt_chg before=chip;
  CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_USB_TYPE,&v)==-ENODATA);
  CHECK(v.intval==POWER_SUPPLY_USB_TYPE_UNKNOWN); CHECK(reads==1 && policy_calls==0);
  CHECK(memcmp(&chip,&before,sizeof(chip))==0);
 }
 /* Sequential attach/detach must not retain a previous successful type. */
 const int sequence[]={POWER_SUPPLY_TYPE_USB_DCP,0,POWER_SUPPLY_TYPE_USB_CDP,0,POWER_SUPPLY_TYPE_USB};
 const int expected[]={POWER_SUPPLY_USB_TYPE_DCP,0,POWER_SUPPLY_USB_TYPE_CDP,0,POWER_SUPPLY_USB_TYPE_SDP};
 reset(0);
 for(size_t n=0;n<ARRAY_SIZE(sequence);n++) {
  main_type=sequence[n]; CHECK(usb_psy_get_prop(&psy,POWER_SUPPLY_PROP_USB_TYPE,&v)==0);
  CHECK(v.intval==expected[n]); CHECK(policy_calls==0);
 }
 printf("USB_TYPE_HOST_TESTS=PASS; assertions=%d; real enums, registration, sysfs, errors, detach and no policy side effects\n",assertions);
 return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='usb-type-test-') as tmp:
        root=Path(tmp);c=root/'test.c';exe=root/'test';c.write_text(source)
        subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
                        '-Wno-unused-parameter','-Wno-sign-compare','-Wno-enum-compare',
                        '-fsanitize=undefined','-fno-sanitize-recover=all',str(c),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True,timeout=20)

if __name__=='__main__':
    main()
