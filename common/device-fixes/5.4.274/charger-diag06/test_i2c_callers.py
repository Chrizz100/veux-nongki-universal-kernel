#!/usr/bin/env python3
"""Execute real driver callbacks with per-operation failure injection."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def function(source, name):
    match = re.search(r'^static (?:int|void) ' + name + r'\([^;]+?\n\{', source, re.M)
    if not match:
        raise ValueError(name)
    return source[match.start():source.index('\n}', match.end()) + 2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    source = args.source.read_text()
    names = ['bq2589x_init_device', 'bq2589x_adapter_in_workfunc', 'bq2589x_adapter_out_workfunc']
    definitions = '\n'.join(x for x in args.source.with_name('bq2589x_reg.h').read_text().splitlines()
                            if x.startswith('#define BQ2589X_'))
    enum = source[source.index('enum bq2589x_vbus_type {'):source.index('enum bq2589x_part_no {')]
    prefix = r'''
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
struct work_struct { int id; };
struct delayed_work { struct work_struct work; };
struct config {
 bool enable_auto_dpdm, enable_term, enable_ico, use_absolute_vindpm;
 int term_current, charge_voltage, charge_current, otg_vol, otg_current;
};
struct bq2589x {
 void *dev, *batt_psy, *usb_psy;
 bool stopping, is_bq25890h;
 struct config cfg;
 int curr_flag, vbus_type;
 struct work_struct adapter_in_work, adapter_out_work;
 struct delayed_work ico_work, monitor_work;
};
union power_supply_propval { int intval; };
#define POWER_SUPPLY_PROP_CAPACITY 1
#define READ_ONCE(x) (x)
#define container_of(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
#define msecs_to_jiffies(x) (x)
#define dev_info(dev,...) do { if (0) printf(__VA_ARGS__); } while(0)
#define dev_err(dev,...) do { errors++; if (0) printf(__VA_ARGS__); } while(0)
struct operation { int id, a, b, c; };
static struct operation trace[64], reference[64];
static int calls, fail_at, failure, capacity, errors, ico, monitor, notify, canceled, adjust, switches;
static int assertions;
static int op(int id, int a, int b, int c) {
 trace[calls++] = (struct operation){id,a,b,c};
 return calls == fail_at ? failure : 0;
}
#define SIMPLE(name,id) static int name(struct bq2589x *bq) { return op(id,0,0,0); }
#define VALUE(name,id) static int name(struct bq2589x *bq,int value) { return op(id,value,0,0); }
SIMPLE(bq2589x_disable_watchdog_timer,1)
VALUE(bq2589x_enable_auto_dpdm,2)
VALUE(bq2589x_enable_term,3)
VALUE(bq2589x_enable_ico,4)
VALUE(bq2589x_use_absolute_vindpm,5)
VALUE(bq2589x_set_vindpm_offset,6)
VALUE(bq2589x_set_term_current,7)
VALUE(bq2589x_set_chargevoltage,8)
VALUE(bq2589x_set_charge_current,9)
VALUE(bq2589x_set_otg_volt,10)
VALUE(bq2589x_set_otg_current,11)
SIMPLE(bq2589x_enable_charger,12)
VALUE(bq2589x_adc_start,14)
VALUE(bq2589x_set_input_volt_limit,15)
VALUE(bq2589x_set_input_current_limit,16)
static int bq2589x_update_bits(struct bq2589x *bq,int reg,int mask,int value) { return op(13,reg,mask,value); }
static int bq2589x_usb_switch(struct bq2589x *bq,bool on) { switches++; return 0; }
static void bq2589x_adjust_absolute_vindpm(struct bq2589x *bq) { adjust++; }
static int power_supply_get_property(void *psy,int key,union power_supply_propval *out) {
 int ret=op(17,key,0,0); if (!ret) out->intval=capacity; return ret;
}
static void schedule_delayed_work(struct delayed_work *work,int delay) {
 if(work->work.id==1) ico++; else monitor++;
}
static void cancel_delayed_work_sync(struct delayed_work *work) { canceled++; }
static void power_supply_changed(void *psy) { notify++; }
static struct bq2589x reset(void) {
 calls=fail_at=errors=ico=monitor=notify=canceled=adjust=switches=0; failure=-EIO; capacity=50;
 memset(trace,0,sizeof(trace));
 struct bq2589x bq={0};
 bq.cfg=(struct config){true,true,true,false,250,4450,2000,5000,1200};
 bq.ico_work.work.id=1; bq.monitor_work.work.id=2; bq.batt_psy=&assertions;
 return bq;
}
#define CHECK(x) do { assertions++; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); return 1; } } while(0)
'''
    tests = r'''
int main(void) {
 int count, saved_ico, saved_switches, saved_adjust;
 int errors_to_test[]={-EIO,-EREMOTEIO};
 // All successful I2C operations, arguments and ordering must remain identical.
 for(int chip=0;chip<2;chip++) for(int auto_dpdm=0;auto_dpdm<2;auto_dpdm++) {
  struct bq2589x bq=reset(); bq.is_bq25890h=chip; bq.cfg.enable_auto_dpdm=auto_dpdm;
  CHECK(bq2589x_init_device_reference(&bq)==0);
  count=calls; memcpy(reference,trace,sizeof(trace));
  bq=reset(); bq.is_bq25890h=chip; bq.cfg.enable_auto_dpdm=auto_dpdm;
  CHECK(bq2589x_init_device(&bq)==0); CHECK(calls==count);
  CHECK(memcmp(trace,reference,count*sizeof(trace[0]))==0);
  for(int err=0;err<2;err++) for(int step=1;step<=count;step++) {
   bq=reset(); bq.is_bq25890h=chip; bq.cfg.enable_auto_dpdm=auto_dpdm;
   fail_at=step; failure=errors_to_test[err];
   CHECK(bq2589x_init_device(&bq)==failure); CHECK(calls==step);
  }
 }
 int kinds[]={BQ2589X_VBUS_MAXC,BQ2589X_VBUS_USB_DCP,BQ2589X_VBUS_USB_SDP,
              BQ2589X_VBUS_USB_CDP,BQ2589X_VBUS_UNKNOWN,BQ2589X_VBUS_NONE};
 for(unsigned k=0;k<sizeof(kinds)/sizeof(kinds[0]);k++) for(int full=0;full<2;full++) for(int batt=0;batt<2;batt++) {
  struct bq2589x bq=reset(); bq.vbus_type=kinds[k]; capacity=full?100:50; if(!batt)bq.batt_psy=NULL;
  bq2589x_adapter_in_workfunc_reference(&bq.adapter_in_work);
  count=calls; memcpy(reference,trace,sizeof(trace)); saved_ico=ico; saved_switches=switches; saved_adjust=adjust;
  bq=reset(); bq.vbus_type=kinds[k]; capacity=full?100:50; if(!batt)bq.batt_psy=NULL;
  bq2589x_adapter_in_workfunc(&bq.adapter_in_work);
  CHECK(calls==count); CHECK(memcmp(trace,reference,count*sizeof(trace[0]))==0);
  CHECK(ico==saved_ico); CHECK(switches==saved_switches); CHECK(adjust==saved_adjust);
  CHECK(notify==1 && monitor==1 && canceled==1 && errors==0);
  for(int err=0;err<2;err++) for(int step=1;step<=count;step++) {
   bq=reset(); bq.vbus_type=kinds[k]; capacity=full?100:50; if(!batt)bq.batt_psy=NULL;
   fail_at=step; failure=errors_to_test[err];
   bq2589x_adapter_in_workfunc(&bq.adapter_in_work);
   CHECK(calls==step); CHECK(errors==1); CHECK(ico==0); CHECK(adjust==0);
   CHECK(notify==1 && monitor==1 && canceled==1);
  }
  bq=reset(); bq.vbus_type=kinds[k]; bq.stopping=true;
  bq2589x_adapter_in_workfunc(&bq.adapter_in_work);
  CHECK(calls==0 && ico==0 && monitor==0 && notify==0);
 }
 // Detach must attempt both independent resets and report either failure.
 struct bq2589x ref_bq=reset();
 bq2589x_adapter_out_workfunc_reference(&ref_bq.adapter_out_work);
 CHECK(calls==2); memcpy(reference,trace,sizeof(trace));
 for(int step=0;step<=2;step++) {
  struct bq2589x bq=reset(); fail_at=step;
  bq2589x_adapter_out_workfunc(&bq.adapter_out_work);
  CHECK(calls==2); CHECK(memcmp(trace,reference,2*sizeof(trace[0]))==0); CHECK(trace[0].id==16 && trace[0].a==500);
  CHECK(trace[1].id==15 && trace[1].a==4400); CHECK(errors==(step?1:0));
 }
 struct bq2589x bq=reset(); bq.stopping=true;
 bq2589x_adapter_out_workfunc(&bq.adapter_out_work);
 CHECK(calls==0);
 printf("BQ_I2C_CALLER_TESTS=PASS; assertions=%d; init and adapter faults plus original success traces checked\n",assertions);
 return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='bq-callers-test-') as tmp:
        root=Path(tmp)
        target=root/'drivers/power/supply/qcom/bq2589x_charger.c'
        target.parent.mkdir(parents=True);target.write_text(source)
        patch=Path(__file__).resolve().with_name('0003-bq2589x-check-init-and-adapter-errors.patch')
        subprocess.run(['git','apply','--reverse',str(patch)],cwd=root,check=True,capture_output=True)
        baseline=target.read_text()
        # This patch is deliberately confined to the three tested callbacks.
        neutral=source
        for name in names: neutral=neutral.replace(function(source,name),function(baseline,name))
        if neutral!=baseline: raise ValueError('patch changed an untested function')
        reference_body='\n'.join(function(baseline,n).replace(n+'(',n+'_reference(',1) for n in names)
        body='\n'.join(function(source,n) for n in names)
        c=root/'test.c';c.write_text(prefix+'\n'+definitions+'\n'+enum+'\n'+reference_body+'\n'+body+'\n'+tests)
        exe=root/'test'
        subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-parameter',str(c),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True,timeout=20)


if __name__=='__main__':
    main()
