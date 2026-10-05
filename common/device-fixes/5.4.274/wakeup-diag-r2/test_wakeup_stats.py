#!/usr/bin/env python3
"""Exercise actual wakeup_stats.c with modeled driver-core facilities.

Checks allocation failures, lifetime, PM ownership, read-only attributes and
accounting. A host model does not validate the ROM's live SELinux policy.
"""
from pathlib import Path
import re
import subprocess
import tempfile

STUB = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#define __init
#define THIS_MODULE NULL
#define GFP_KERNEL 0
#define MKDEV(a,b) 0
#define postcore_initcall(x)
#define ERR_PTR(x) ((void *)(intptr_t)(x))
#define PTR_ERR(x) ((intptr_t)(x))
#define IS_ERR(x) ((uintptr_t)(x) >= (uintptr_t)-4095)
#define PTR_ERR_OR_ZERO(x) (IS_ERR(x) ? PTR_ERR(x) : 0)
typedef long long ktime_t;
static ktime_t now;
static ktime_t ktime_get(void) {return now;}
static ktime_t ktime_sub(ktime_t a,ktime_t b) {return a-b;}
static ktime_t ktime_add(ktime_t a,ktime_t b) {return a+b;}
static long long ktime_to_ms(ktime_t a) {return a/1000000;}
#define sysfs_emit sprintf
struct task_struct {char comm[16];int pid;};
static struct task_struct task={"fixture-worker",1234};
#define current (&task)
static int task_pid_nr(struct task_struct *t) {return t->pid;}
static int log_calls;
static char message[256];
static void capture_log(const char *fmt,...) {
 va_list ap;va_start(ap,fmt);vsnprintf(message,sizeof(message),fmt,ap);va_end(ap);log_calls++;
}
#define pr_info_ratelimited capture_log
struct attribute {const char *name;unsigned int mode;};
struct attribute_group {struct attribute **attrs;};
struct device;
struct device_attribute {
 struct attribute attr;
 ssize_t (*show)(struct device *,struct device_attribute *,char *);
};
#define DEVICE_ATTR_RO(n) struct device_attribute dev_attr_##n={{#n,0444},n##_show}
#define ATTRIBUTE_GROUPS(n) \
 static const struct attribute_group n##_group={n##_attrs}; \
 static const struct attribute_group *n##_groups[]={&n##_group,NULL}
struct class {const char *name;};
struct kobject {char name[64];};
struct wakeup_source;
struct device {
 int devt;struct class *class;struct device *parent;
 const struct attribute_group **groups;void (*release)(struct device *);
 void *data;struct kobject kobj;bool initialized,added,pm_not_required;
 struct {struct wakeup_source *wakeup;} power;
};
struct wakeup_source {
 int id;const char *name;struct device *dev;
 unsigned long active_count,event_count,wakeup_count,expire_count;
 bool active,autosleep_enabled;
 ktime_t last_time,total_time,max_time,prevent_sleep_time,start_prevent_time;
};
static int failure,allocated,added,released;
static void *kzalloc(size_t n,int flags) {
 (void)flags;if(failure==1)return NULL;allocated++;return calloc(1,n);
}
static void kfree(void *p) {if(p){allocated--;released++;free(p);}}
static void device_initialize(struct device *d) {d->initialized=true;}
static void dev_set_drvdata(struct device *d,void *v) {d->data=v;}
static void *dev_get_drvdata(struct device *d) {return d->data;}
static void device_set_pm_not_required(struct device *d) {d->pm_not_required=true;}
static int kobject_set_name(struct kobject *k,const char *fmt,int id) {
 if(failure==2)return -ENOMEM;snprintf(k->name,sizeof(k->name),fmt,id);return 0;
}
static int device_add(struct device *d) {
 assert(d->initialized && d->release && d->class && d->groups);
 if(failure==3)return -EIO;d->added=true;added++;return 0;
}
static void put_device(struct device *d) {if(d){assert(!d->added);d->release(d);}}
static void device_unregister(struct device *d) {
 assert(d && d->added);d->added=false;added--;put_device(d);
}
static struct class fixture_class;
static struct class *class_create(void *module,const char *name) {
 (void)module;if(failure==4)return ERR_PTR(-ENOMEM);
 fixture_class.name=name;return &fixture_class;
}
'''

CASES = r'''
static int assertions;
#define CHECK(x) do {assertions++;if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static char buf[4096];
static void value(struct device *d,struct device_attribute *a,const char *wanted) {
 memset(buf,0,sizeof(buf));CHECK(a->show(d,a,buf)==(ssize_t)strlen(wanted));CHECK(!strcmp(buf,wanted));
}
int main(void) {
 failure=4;CHECK(wakeup_sources_sysfs_init()==-ENOMEM);
 failure=0;CHECK(wakeup_sources_sysfs_init()==0);CHECK(!strcmp(wakeup_class->name,"wakeup"));
 struct wakeup_source ws={.id=89,.name="battery%p"};
 struct device parent={.power={.wakeup=&ws}};
 CHECK(pm_wakeup_source_sysfs_add(&(struct device){0})==0);CHECK(allocated==0);
 for(failure=1;failure<=3;failure++) {
  CHECK(pm_wakeup_source_sysfs_add(&parent)<0);CHECK(ws.dev==NULL);
  CHECK(allocated==0 && added==0);CHECK(parent.power.wakeup==&ws);CHECK(log_calls==0);
 }
 failure=0;
 CHECK(pm_wakeup_source_sysfs_add(&parent)==0);CHECK(allocated==1 && added==1);
 CHECK(ws.dev->parent==NULL);CHECK(parent.power.wakeup==&ws);
 CHECK(ws.dev->pm_not_required);CHECK(dev_get_drvdata(ws.dev)==&ws);
 CHECK(!strcmp(ws.dev->kobj.name,"wakeup89"));CHECK(log_calls==0);
 CHECK(pm_wakeup_source_sysfs_add(&parent)==0);CHECK(allocated==1 && added==1);
 CHECK(ws.dev->groups[0]==&wakeup_source_group && ws.dev->groups[1]==NULL);
 int count=0;while(wakeup_source_attrs[count]) {CHECK(wakeup_source_attrs[count]->mode==0444);count++;}
 CHECK(count==10);
 value(ws.dev,&dev_attr_name,"battery%p\n");
 ws.active_count=3;ws.event_count=9;ws.wakeup_count=2;ws.expire_count=1;
 value(ws.dev,&dev_attr_active_count,"3\n");value(ws.dev,&dev_attr_event_count,"9\n");
 value(ws.dev,&dev_attr_wakeup_count,"2\n");value(ws.dev,&dev_attr_expire_count,"1\n");
 now=100000000;ws.last_time=70000000;ws.total_time=40000000;ws.max_time=20000000;
 ws.prevent_sleep_time=50000000;ws.start_prevent_time=90000000;
 value(ws.dev,&dev_attr_active_time_ms,"0\n");value(ws.dev,&dev_attr_total_time_ms,"40\n");
 value(ws.dev,&dev_attr_max_time_ms,"20\n");value(ws.dev,&dev_attr_last_change_ms,"70\n");
 value(ws.dev,&dev_attr_prevent_suspend_time_ms,"50\n");
 ws.active=true;
 value(ws.dev,&dev_attr_active_time_ms,"30\n");value(ws.dev,&dev_attr_total_time_ms,"70\n");
 value(ws.dev,&dev_attr_max_time_ms,"30\n");value(ws.dev,&dev_attr_prevent_suspend_time_ms,"50\n");
 ws.autosleep_enabled=true;value(ws.dev,&dev_attr_prevent_suspend_time_ms,"60\n");
 CHECK(ws.total_time==40000000 && ws.max_time==20000000 && ws.prevent_sleep_time==50000000);
 wakeup_source_sysfs_remove(&ws);ws.dev=NULL;CHECK(allocated==0 && added==0);
 CHECK(parent.power.wakeup==&ws);CHECK(ws.active);
 /* Empty sources remain functional and visibly empty, with creator evidence. */
 ws.name="";CHECK(wakeup_source_sysfs_add(NULL,&ws)==0);
 CHECK(log_calls==1);CHECK(!strcmp(message,"wakeup_stats: empty source wakeup89 registered by fixture-worker[1234]\n"));
 CHECK(ws.dev->parent==NULL && dev_get_drvdata(ws.dev)==&ws && ws.active);
 value(ws.dev,&dev_attr_name,"\n");value(ws.dev,&dev_attr_total_time_ms,"70\n");
 wakeup_source_sysfs_remove(&ws);ws.dev=NULL;CHECK(allocated==0 && added==0);
 /* A failed registration must not be logged as a successful creation. */
 failure=3;CHECK(wakeup_source_sysfs_add(NULL,&ws)<0);CHECK(log_calls==1);
 CHECK(allocated==0 && added==0 && ws.dev==NULL);failure=0;
 ws.name="[timerfd]";CHECK(wakeup_source_sysfs_add(NULL,&ws)==0);
 CHECK(log_calls==1 && ws.dev->parent==NULL);value(ws.dev,&dev_attr_name,"[timerfd]\n");
 wakeup_source_sysfs_remove(&ws);CHECK(allocated==0 && added==0);CHECK(released==6);
 printf("WAKEUP_STATS_ACTUAL_C=PASS; ASSERTIONS=%d; SELINUX_DEVICE_CHECK=NOT_RUN\n",assertions);
 return 0;
}
'''


def check(source):
    code = (source / 'drivers/base/power/wakeup_stats.c').read_text()
    with tempfile.TemporaryDirectory(prefix='wakeup-stats-c-') as tmp:
        root = Path(tmp)
        for name in re.findall(r'#include [<"]([^>"]+)[>"]', code):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('')
        (root / 'test.c').write_text(STUB + code + CASES)
        binary = root / 'test'
        subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-parameter', '-Wno-misleading-indentation',
                        '-fsanitize=undefined', '-fno-sanitize-recover=all',
                        '-I', str(root), str(root / 'test.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    check(parser.parse_args().source.resolve())
