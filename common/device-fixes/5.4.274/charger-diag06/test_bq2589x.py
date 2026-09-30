#!/usr/bin/env python3
"""Compile the actual driver functions and inject bus/shutdown failures.

Host tests do not claim a device test. Full kernel build and static boot gates
remain mandatory in the diagnostic workflow.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def function(source, name):
    match = re.search(r'^(?:static )?[^\n;]+\b' + name + r'\([^;]+?\n\{', source, re.M)
    if not match:
        raise ValueError('missing function: ' + name)
    end = source.index('\n}', match.end()) + 2
    return source[match.start():end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('driver', type=Path)
    args = parser.parse_args()
    source = args.driver.read_text()
    registers = (args.driver.parent / 'bq2589x_reg.h').read_text()
    # Real header values, with a compile failure if a required definition changes.
    definitions = '\n'.join(line for line in registers.splitlines() if line.startswith('#define BQ2589X_'))
    channels = list(dict.fromkeys(re.findall(r'\bPSY_IIO_[A-Z_]+', source)))
    constants = '''
#define IIO_VAL_INT 1
#define POWER_SUPPLY_TYPE_UNKNOWN 0
#define POWER_SUPPLY_TYPE_USB 1
#define POWER_SUPPLY_TYPE_USB_CDP 2
#define POWER_SUPPLY_TYPE_USB_DCP 3
#define POWER_SUPPLY_TYPE_USB_FLOAT 4
#define POWER_SUPPLY_TYPE_USB_HVDCP 5
#define POWER_SUPPLY_CHARGE_TYPE_NONE 0
#define POWER_SUPPLY_CHARGE_TYPE_FAST 1
#define POWER_SUPPLY_CHARGE_TYPE_TRICKLE 2
#define POWER_SUPPLY_CHARGE_TYPE_UNKNOWN 3
#define POWER_SUPPLY_PROP_CAPACITY 1
#define POWER_SUPPLY_PROP_TEMP 2
#define BQ2589X_STATUS_CHARGE_ENABLE 4
#define BQ2589X_5V_VINDPM_MV 4400
#define GFP_KERNEL 0
#define HZ 100
'''
    constants += '\n'.join(f'#define {name} {n}' for n, name in enumerate(channels))
    enum = source[source.index('enum bq2589x_vbus_type {'):source.index('enum bq2589x_part_no {')]
    prefix = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <sched.h>
typedef uint8_t u8;
struct mutex { pthread_mutex_t value; };
#define DEFINE_MUTEX(n) struct mutex n = { PTHREAD_MUTEX_INITIALIZER }
#define mutex_init(m) pthread_mutex_init(&(m)->value, NULL)
#define mutex_lock(m) pthread_mutex_lock(&(m)->value)
#define mutex_unlock(m) pthread_mutex_unlock(&(m)->value)
#define READ_ONCE(x) __atomic_load_n(&(x), __ATOMIC_SEQ_CST)
#define WRITE_ONCE(x,v) __atomic_store_n(&(x),(v), __ATOMIC_SEQ_CST)
#define dev_err(...) ((void)0)
#define dev_info(dev,...) do { if (0) printf(__VA_ARGS__); } while (0)
#define pr_debug(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_err_ratelimited(...) ((void)0)
#define udelay(x) ((void)0)
#define msleep(x) ((void)0)
#define __pm_stay_awake(x) ((void)0)
#define __pm_relax(x) ((void)0)
struct device { int kobj; };
struct i2c_client { int irq; struct device dev; void *data; };
struct work_struct { int id; };
struct delayed_work { struct work_struct work; int id; };
#define container_of(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
static void schedule_delayed_work(struct delayed_work *w, int delay) {}
struct bq2589x_config {
 bool enable_term, otg_status;
 int input_current, charge_voltage, term_current, battery_voltage_term;
};
struct bq2589x {
 struct device *dev;
 struct i2c_client *client;
 struct mutex io_lock;
 bool stopping, is_bq25890h, hz_flag, usb_switch_flag;
 struct bq2589x_config cfg;
 unsigned int status;
 int old_type, charge_type, otg_gpio, irq_gpio, wakeup_flag;
 void *batt_psy, *wt_ws;
 struct work_struct irq_work, adapter_in_work, adapter_out_work;
 struct delayed_work force_work, ico_work, monitor_work;
};
struct iio_dev { struct bq2589x *data; };
struct iio_chan_spec { int channel; };
union power_supply_propval { int intval; };
struct i2c_device_id { int unused; };
static struct bq2589x *g_bq;
static DEFINE_MUTEX(bq2589x_i2c_lock);
static unsigned char registers[256];
static int fail_read, fail_write, read_calls, write_calls, fail_count;
static int shutdown_phase, drain_count, late_checks, priv_calls, alloc_fail;
static atomic_int hold_read, read_entered, release_read, shutdown_entered;
static void *iio_priv(struct iio_dev *d) { assert(d); priv_calls++; return d->data; }
static struct iio_dev *devm_iio_device_alloc(struct device *dev, size_t n) {
 static struct bq2589x data;
 static struct iio_dev d = { &data };
 return alloc_fail ? NULL : &d;
}
static int gpio_direction_output(int gpio, int val) { return 0; }
static int bq2589x_usb_switch(struct bq2589x *bq, bool enabled) { return 0; }
static int power_supply_get_property(void *psy, int prop, union power_supply_propval *v) {
 v->intval = prop == POWER_SUPPLY_PROP_TEMP ? 250 : 50;
 return 0;
}
static void *i2c_get_clientdata(struct i2c_client *c) { return c->data; }
static int bq2589x_attr_group;
static void disable_irq(int irq) { assert(g_bq->stopping); shutdown_phase = 1; }
static void sysfs_remove_group(void *obj, void *attr) { assert(shutdown_phase == 1); }
static void cancel_work_sync(struct work_struct *w) {
 assert(shutdown_phase == 1); assert(w->id == ++drain_count);
}
static void cancel_delayed_work_sync(struct delayed_work *w) {
 assert(shutdown_phase == 1); assert(w->id == ++drain_count);
}
static void free_irq(int irq, void *data) { assert(drain_count == 6); }
static void gpio_free(int gpio) { assert(drain_count == 6); }
static void check_final_bus_access(void);
static int i2c_smbus_read_byte_data(struct i2c_client *c, u8 reg) {
 read_calls++;
 if (atomic_load(&hold_read)) {
  atomic_store(&read_entered, 1);
  while (!atomic_load(&release_read)) sched_yield();
 }
 if (shutdown_phase) check_final_bus_access();
 if (fail_read && (fail_count < 0 || fail_count-- > 0)) return fail_read;
 return registers[reg];
}
static int i2c_smbus_write_byte_data(struct i2c_client *c, u8 reg, u8 data) {
 write_calls++;
 if (shutdown_phase) check_final_bus_access();
 if (fail_write) return fail_write;
 registers[reg] = data;
 return 0;
}
'''
    names = ['bq2589x_read_byte','bq2589x_write_byte','bq2589x_update_bits',
             'bq2589x_get_vbus_type','bq2589x_get_chg_type',
             'bq2589x_enable_otg','bq2589x_disable_otg','bq2589x_set_otg_volt','bq2589x_set_otg_current',
             'bq2589x_enable_charger','bq2589x_disable_charger','bq2589x_adc_start','bq2589x_adc_stop',
             'bq2589x_adc_read_battery_volt','bq2589x_adc_read_vbus_volt','bq2589x_read_vindpm_volt',
             'bq2589x_adc_read_charge_current','bq2589x_set_charge_current','bq2589x_set_term_current',
             'bq2589x_set_chargevoltage','bq2589x_is_5v_input','bq2589x_set_input_volt_limit',
             'bq2589x_restore_5v_vindpm','bq2589x_set_input_current_limit','bq2589x_is_dpdm_done',
             'bq2589x_force_dpdm','bq2589x_force_dpdm_done','bq2589x_enter_hiz_mode','bq2589x_exit_hiz_mode',
             'bq2589x_get_hiz_mode','bq2589x_force_ico','bq2589x_check_force_ico_done','bq2589x_ico_workfunc','bq2589x_enable_term','bq2589x_is_charge_done','bq2589x_charge_status',
             'bq_iio_read_raw_unlocked','bq_iio_write_raw_unlocked','bq_iio_read_raw','bq_iio_write_raw',
             'bq2589x_charger_shutdown']
    body = '\n\n'.join(function(source, name) for name in names)
    # Execute the real allocation path up to its first initialized private field.
    probe = function(source, 'bq2589x_charger_probe')
    allocation = probe[:probe.index('\n\tbq->indio_dev')] + '\n\t(void)irqn; (void)ret;\n\treturn 0;\n}'
    tests = r'''
static atomic_int tests;
#define CHECK(x) do { assert(x); tests++; } while (0)
static struct bq2589x bq;
static struct device dev;
static struct i2c_client client;
static struct iio_dev iio;
static void reset(void) {
 memset(&bq,0,sizeof(bq)); memset(registers,0,sizeof(registers));
 client.data = &bq; client.irq = 10; bq.dev = &dev; bq.client = &client;
 iio.data = &bq; g_bq = &bq; mutex_init(&bq.io_lock);
 bq.irq_work.id=1; bq.adapter_in_work.id=2; bq.adapter_out_work.id=3;
 bq.force_work.id=4; bq.ico_work.id=5; bq.monitor_work.id=6;
 fail_read=fail_write=read_calls=write_calls=0; fail_count=-1;
 shutdown_phase=drain_count=late_checks=0;
 atomic_store(&hold_read,0); atomic_store(&read_entered,0);
 atomic_store(&release_read,0); atomic_store(&shutdown_entered,0);
}
static void check_final_bus_access(void) {
 struct iio_chan_spec channel={PSY_IIO_MAIN_INPUT_VOLTAGE_SETTLED};
 int before=read_calls+write_calls;
 assert(drain_count==6);
 assert(bq_iio_write_raw(&iio,&channel,8500,0,0)==-ESHUTDOWN);
 assert(read_calls+write_calls==before); late_checks++;
}
static void *reader(void *arg) {
 struct iio_chan_spec ch={PSY_IIO_SC_BUS_VOLTAGE}; int value=-123, other;
 CHECK(bq_iio_read_raw(&iio,&ch,&value,&other,0)==IIO_VAL_INT);
 CHECK(value==2600); return NULL;
}
static void *shutdown_thread(void *arg) {
 atomic_store(&shutdown_entered,1);
 bq2589x_charger_shutdown(&client); return NULL;
}
int main(void) {
 u8 out; int value, other, done, n, before;
 struct iio_chan_spec ch;
 pthread_t r,s;
 reset(); out=0xa5; fail_read=-EIO;
 CHECK(bq2589x_read_byte(&bq,&out,0)==-EIO);
 CHECK(out==0xa5); CHECK(read_calls==3);
 reset(); fail_read=-EIO; fail_count=2; registers[0]=0x6b;
 CHECK(bq2589x_read_byte(&bq,&out,0)==0); CHECK(out==0x6b); CHECK(read_calls==3);
 reset(); fail_read=-EREMOTEIO;
 CHECK(bq2589x_update_bits(&bq,0,0xff,1)==-EREMOTEIO); CHECK(write_calls==0);
 CHECK(bq2589x_get_vbus_type(&bq)==-EREMOTEIO);
 bq.charge_type=99; CHECK(bq2589x_get_chg_type(&bq)==-EREMOTEIO); CHECK(bq.charge_type==99);
 CHECK(bq2589x_charge_status(&bq)==-EREMOTEIO);
 CHECK(bq2589x_is_charge_done(&bq)==-EREMOTEIO);
 done=42; CHECK(bq2589x_is_dpdm_done(&bq,&done)==-EREMOTEIO); CHECK(done==42);
 CHECK(bq2589x_force_dpdm_done(&bq)==-EREMOTEIO);
 int reads[]={PSY_IIO_CHARGE_DONE,PSY_IIO_MAIN_CHAGER_HZ,PSY_IIO_MAIN_CHAGER_CURRENT,
 PSY_IIO_CHARGING_ENABLED,PSY_IIO_SC_BUS_VOLTAGE,PSY_IIO_SC_BATTERY_VOLTAGE,
 PSY_IIO_CHARGER_STATUS,PSY_IIO_CHARGE_TYPE};
 for(n=0;n<(int)(sizeof(reads)/sizeof(reads[0]));n++) {
  ch.channel=reads[n]; value=123456;
  CHECK(bq_iio_read_raw(&iio,&ch,&value,&other,0)==-EREMOTEIO); CHECK(value==123456);
 }
 reset(); fail_write=-EIO; bq.cfg.input_current=500;
 int writes[]={PSY_IIO_MAIN_CHAGER_HZ,PSY_IIO_MAIN_INPUT_CURRENT_SETTLED,
 PSY_IIO_MAIN_INPUT_VOLTAGE_SETTLED,PSY_IIO_MAIN_CHAGER_CURRENT,
 PSY_IIO_CHARGING_ENABLED,PSY_IIO_OTG_ENABLE,PSY_IIO_MAIN_CHAGER_TERM,
 PSY_IIO_BATTERY_VOLTAGE_TERM,PSY_IIO_ENABLE_CHAGER_TERM};
 for(n=0;n<(int)(sizeof(writes)/sizeof(writes[0]));n++) {
  ch.channel=writes[n]; CHECK(bq_iio_write_raw(&iio,&ch,1000,0,0)==-EIO);
 }
 CHECK(bq.cfg.input_current==500); CHECK(!bq.cfg.enable_term); CHECK(!bq.cfg.otg_status);
 reset(); bq2589x_ico_workfunc(&bq.ico_work.work);
 before=read_calls; fail_read=-EIO;
 bq2589x_ico_workfunc(&bq.ico_work.work);
 CHECK(read_calls-before==3); // REG14 failure must not trigger a REG13 result read
 reset(); CHECK(bq2589x_force_dpdm_done(&bq)==-ETIMEDOUT);
 bq.stopping=true; before=read_calls+write_calls;
 CHECK(bq2589x_force_dpdm_done(&bq)==-ESHUTDOWN); CHECK(read_calls+write_calls==before);
 // Regression: keep Diag02's 5 V recovery, while preserving 9 V, OTG and CP paths.
 reset(); bq.cfg.enable_term=true;
 registers[BQ2589X_REG_11]=(5100-BQ2589X_VBUSV_BASE)/BQ2589X_VBUSV_LSB;
 registers[BQ2589X_REG_0D]=BQ2589X_FORCE_VINDPM_MASK | ((8500-BQ2589X_VINDPM_BASE)/BQ2589X_VINDPM_LSB);
 CHECK(bq2589x_restore_5v_vindpm(&bq)==0); CHECK(bq2589x_read_vindpm_volt(&bq)==4400);
 CHECK(bq2589x_set_input_volt_limit(&bq,8550)==0); CHECK(bq2589x_read_vindpm_volt(&bq)==4400);
 registers[BQ2589X_REG_11]=(9000-BQ2589X_VBUSV_BASE)/BQ2589X_VBUSV_LSB;
 CHECK(bq2589x_set_input_volt_limit(&bq,8550)==0); CHECK(bq2589x_read_vindpm_volt(&bq)==8500);
 registers[BQ2589X_REG_11]=(5100-BQ2589X_VBUSV_BASE)/BQ2589X_VBUSV_LSB;
 bq.cfg.otg_status=true; CHECK(bq2589x_restore_5v_vindpm(&bq)==0); CHECK(bq2589x_read_vindpm_volt(&bq)==8500);
 bq.cfg.otg_status=false; bq.cfg.enable_term=false;
 CHECK(bq2589x_restore_5v_vindpm(&bq)==0); CHECK(bq2589x_read_vindpm_volt(&bq)==8500);
 reset(); alloc_fail=1; priv_calls=0;
 CHECK(bq2589x_charger_probe(&client,NULL)==-ENOMEM); CHECK(priv_calls==0);
 alloc_fail=0; CHECK(bq2589x_charger_probe(&client,NULL)==0); CHECK(priv_calls==1);
 reset(); bq2589x_charger_shutdown(&client); CHECK(drain_count==6); CHECK(late_checks>0);
 before=read_calls+write_calls; ch.channel=PSY_IIO_SC_BUS_VOLTAGE; value=876;
 CHECK(bq_iio_read_raw(&iio,&ch,&value,&other,0)==-ESHUTDOWN);
 CHECK(value==876); CHECK(read_calls+write_calls==before);
 reset(); atomic_store(&hold_read,1);
 CHECK(!pthread_create(&r,NULL,reader,NULL));
 while(!atomic_load(&read_entered)) sched_yield();
 CHECK(!pthread_create(&s,NULL,shutdown_thread,NULL));
 while(!atomic_load(&shutdown_entered)) sched_yield();
 CHECK(!READ_ONCE(bq.stopping)); // active IIO owns io_lock; no final writes can begin
 atomic_store(&release_read,1);
 CHECK(!pthread_join(r,NULL)); CHECK(!pthread_join(s,NULL));
 CHECK(drain_count==6); CHECK(late_checks>0);
 printf("BQ2589X_HOST_TESTS=PASS; assertions=%d; active-IIO shutdown drain checked\n",tests);
 return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='bq2589x-test-') as tmp:
        tmp = Path(tmp)
        cfile = tmp / 'test.c'
        cfile.write_text(constants + '\n' + prefix + '\n' + enum + '\n' + definitions + '\n' + body + '\n' + allocation + tests)
        subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
                        '-Wno-unused-parameter','-Wno-unused-function','-pthread',
                        str(cfile),'-o',str(tmp / 'test')],check=True)
        subprocess.run([str(tmp / 'test')],check=True,timeout=20)
    # Reachability/scope guards supplement, rather than replace, execution tests.
    assert 'msleep(1)' not in function(source, 'bq2589x_monitor_workfunc')
    assert 'if (ret > 0)' in function(source, 'bq2589x_ico_workfunc')
    assert 'bq2589x_read_byte(g_bq' not in source
    for name in ('bq2589x_adapter_in_workfunc','bq2589x_adapter_out_workfunc',
                 'bq2589x_force_workfunc','bq2589x_ico_workfunc',
                 'bq2589x_monitor_workfunc','bq2589x_charger_irq_workfunc','bq2589x_charger_interrupt'):
        assert 'READ_ONCE(bq->stopping)' in function(source,name), name
    print('BQ2589X_SCOPE_GUARDS=PASS')


if __name__ == '__main__':
    main()
