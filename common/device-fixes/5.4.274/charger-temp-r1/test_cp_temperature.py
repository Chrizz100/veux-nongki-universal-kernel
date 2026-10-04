#!/usr/bin/env python3
"""Compile the actual wt_chg readers, sysfs callbacks and worker telemetry.

IIO errors may modify the temporary output: they must never escape as a valid
sample. No target hardware or manually rewritten driver functions are used.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile


def function(source, name):
    match = re.search(r'^(?:static )?(?:int|void|ssize_t) ' + name + r'\([^;]+?\n\{', source, re.M)
    assert match, 'missing C function: ' + name
    start = match.start()
    # These selected functions have no braces in comments or string literals.
    depth = 1
    for end in range(match.end(), len(source)):
        depth += (source[end] == '{') - (source[end] == '}')
        if not depth:
            return source[start:end + 1]
    raise AssertionError('unterminated function: ' + name)


PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#define PAGE_SIZE 4096
#define WRITE_ONCE(x,v) ((x)=(v))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define scnprintf snprintf
struct class { int unused; };
struct class_attribute { int unused; };
struct iio_channel { int rc, value, calls; };
struct batt_chg {
 struct class battery_class;
 struct iio_channel *cp_master_therm, *cp_slave_therm;
 int cp_master_temp, cp_slave_temp;
};
static int null_reads, checks;
static char logs[16384];
static void record(const char *fmt, ...) {
 va_list ap; va_start(ap,fmt);
 vsnprintf(logs+strlen(logs),sizeof(logs)-strlen(logs),fmt,ap);
 va_end(ap);
}
#define pr_err record
#define pr_err_ratelimited record
#define pr_debug record
static int iio_read_channel_processed(struct iio_channel *c, int *v) {
 if (!c) { null_reads++; return -EINVAL; }
 c->calls++; *v=c->value; return c->rc;
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); return 1; } checks++; } while(0)
'''

BODY = r'''
int main(void) {
 struct iio_channel master={0,24500,0}, slave={0,23700,0};
 struct batt_chg chg={.cp_master_therm=&master,.cp_slave_therm=&slave,
                      .cp_master_temp=1234,.cp_slave_temp=5678};
 char buf[PAGE_SIZE]; int out, rc;
 int errors[]={-ETIMEDOUT,-EIO,-ENODATA,-EAGAIN,-517};
 for (int which=0; which<2; which++) {
  struct iio_channel *channel=which?&slave:&master;
  int (*read_temp)(struct batt_chg *,int *)=which?get_charger_pump_slave_temp:get_charger_pump_master_temp;
  ssize_t (*show)(struct class *,struct class_attribute *,char *)=which?cp_temp_slave_show:cp_temp_master_show;
  int *cache=which?&chg.cp_slave_temp:&chg.cp_master_temp;
  for (unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++) {
   channel->rc=errors[i]; channel->value=99000; out=9876;
   rc=read_temp(&chg,&out); CHECK(rc==errors[i]); CHECK(out==9876);
   *cache=1234; strcpy(buf,"unchanged");
   CHECK(show(&chg.battery_class,NULL,buf)==errors[i]);
   CHECK(!strcmp(buf,"unchanged")); CHECK(*cache==1234);
  }
  int values[]={24500,0,-5000,199,55000};
  for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
   char expected[64]; channel->rc=0; channel->value=values[i];
   CHECK(read_temp(&chg,&out)==0); CHECK(out==values[i]/100);
   snprintf(expected,sizeof(expected),"%d\n",values[i]/100);
   CHECK(show(&chg.battery_class,NULL,buf)==(ssize_t)strlen(expected));
   CHECK(!strcmp(buf,expected)); CHECK(*cache==values[i]/100);
  }
  channel->rc=0;
 }
 chg.cp_master_therm=NULL; slave.rc=0; slave.value=23700;
 out=77; CHECK(get_charger_pump_master_temp(&chg,&out)==-ENODATA); CHECK(out==77);
 CHECK(get_charger_pump_slave_temp(&chg,&out)==0); CHECK(out==237);
 strcpy(buf,"unchanged"); CHECK(cp_temp_master_show(&chg.battery_class,NULL,buf)==-ENODATA);
 CHECK(!strcmp(buf,"unchanged"));
 chg.cp_master_therm=&master; chg.cp_slave_therm=NULL;
 out=88; CHECK(get_charger_pump_slave_temp(&chg,&out)==-ENODATA); CHECK(out==88);
 strcpy(buf,"unchanged"); CHECK(cp_temp_slave_show(&chg.battery_class,NULL,buf)==-ENODATA);
 CHECK(!strcmp(buf,"unchanged")); CHECK(null_reads==0);
 chg.cp_slave_therm=&slave;
 for(int mask=0;mask<4;mask++) {
  master.rc=(mask&1)?-ETIMEDOUT:0; slave.rc=(mask&2)?-EIO:0;
  master.value=24500; slave.value=23700; master.calls=slave.calls=0;
  chg.cp_master_temp=1234; chg.cp_slave_temp=5678; logs[0]=0;
  batt_update_cp_temperatures(&chg);
  CHECK(master.calls==1); CHECK(slave.calls==1);
  CHECK(chg.cp_master_temp==((mask&1)?1234:245));
  CHECK(chg.cp_slave_temp==((mask&2)?5678:237));
  CHECK(strstr(logs,(mask&1)?"cp_master_temp unavailable, rc=-110":"cp_master_temp 245")!=NULL);
  CHECK(strstr(logs,(mask&2)?"cp_slave_temp unavailable, rc=-5":"cp_slave_temp 237")!=NULL);
  CHECK(!strstr(logs,"1234")); CHECK(!strstr(logs,"5678"));
  if(mask&1) CHECK(!strstr(logs,"cp_master_temp 245"));
  if(mask&2) CHECK(!strstr(logs,"cp_slave_temp 237"));
 }
 // Both channels absent is handled without passing NULL into IIO.
 chg.cp_master_therm=chg.cp_slave_therm=NULL; logs[0]=0;
 batt_update_cp_temperatures(&chg); CHECK(null_reads==0);
 CHECK(strstr(logs,"cp_master_temp unavailable")!=NULL);
 CHECK(strstr(logs,"cp_slave_temp unavailable")!=NULL);
 // A later successful conversion recovers without resetting the driver.
 chg.cp_master_therm=&master; chg.cp_slave_therm=&slave;
 master.rc=slave.rc=0; master.value=26000; slave.value=25000;
 batt_update_cp_temperatures(&chg);
 CHECK(chg.cp_master_temp==260); CHECK(chg.cp_slave_temp==250);
 printf("CP_TEMPERATURE_HOST_ASSERTIONS=%d; PASS\n",checks);
 return 0;
}
'''

OLD_BODY = r'''
int main(void) {
 struct iio_channel master={-ETIMEDOUT,99000,0}, slave={0,23700,0};
 struct batt_chg chg={.cp_master_therm=&master,.cp_slave_therm=&slave,
                      .cp_master_temp=245};
 char buf[PAGE_SIZE]; int out=99;
 CHECK(get_charger_pump_master_temp(&chg,&out)==-ETIMEDOUT); CHECK(out==99);
 CHECK(cp_temp_master_show(&chg.battery_class,NULL,buf)==4);
 CHECK(!strcmp(buf,"245\n"));
 chg.cp_master_therm=NULL;
 CHECK(get_charger_pump_slave_temp(&chg,&out)==-ENODATA); CHECK(slave.calls==0);
 chg.cp_master_therm=&master; chg.cp_slave_therm=NULL;
 (void)cp_temp_slave_show(&chg.battery_class,NULL,buf); CHECK(null_reads==1);
 printf("OLD_DEFECTS_REPRODUCED=3; PASS\n"); return 0;
}
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path)
    p.add_argument('--expect-old-defects',action='store_true')
    args=p.parse_args()
    source=args.source.read_text()
    names=['get_charger_pump_master_temp','get_charger_pump_slave_temp',
           'cp_temp_master_show','cp_temp_slave_show']
    if args.expect_old_defects:
        assert hashlib.sha256(args.source.read_bytes()).hexdigest() == 'c8c785d03e2c723c9a23b89f7728e16ee3bb07e888e8cfc221ce406b6f73d1ef'
    else:
        names.append('batt_update_cp_temperatures')
        worker=function(source,'batt_chg_main')
        assert worker.count('batt_update_cp_temperatures(chg);')==1
        assert 'cp_master_temp' not in worker and 'cp_slave_temp' not in worker
        prefix, policy=worker.split('\tif(chg->mishow_flag)',1)
        assert hashlib.sha256(policy.encode()).hexdigest() == '59d37e5bdfbb644bdd7b1e8c6b0b9da032428d142638580629c57a2bcd242620'
        # The original NULL guard is the only exit before charging policy.
        assert prefix.count('return;')==1
        assert prefix.index('return;') < prefix.index('batt_update_cp_temperatures(chg);')
    code=PRELUDE+'\n'.join(function(source,name) for name in names)+(OLD_BODY if args.expect_old_defects else BODY)
    with tempfile.TemporaryDirectory(prefix='cp-temp-test-') as tmp:
        root=Path(tmp); (root/'test.c').write_text(code)
        flags=['-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-parameter']
        if args.expect_old_defects:
            flags += ['-Wno-unused-but-set-variable']
        subprocess.run(['gcc',*flags,str(root/'test.c'),'-o',str(root/'test')],check=True)
        subprocess.run([str(root/'test')],check=True)


if __name__=='__main__':
    main()
