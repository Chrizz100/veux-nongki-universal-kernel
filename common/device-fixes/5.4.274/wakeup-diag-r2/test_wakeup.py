#!/usr/bin/env python3
"""Compile the actual new C implementation and pending-source collector on host.
Kernel facilities are modeled: this is not an ARM64 build or device test.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile
from test_wakeup_stats import check as check_stats

STUB = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <sys/types.h>
#define PAGE_SIZE 4096
#define MAX_SUSPEND_ABORT_LEN 256
#define CONFIG_SUSPEND 1
#define __init
#define EXPORT_SYMBOL_GPL(x)
#define late_initcall(x)
#define GFP_ATOMIC 0
#define unlikely(x) (x)
#define WARN_ON(x) (x)
#define NOTIFY_DONE 0
#define PM_SUSPEND_PREPARE 1
#define PM_POST_SUSPEND 2
#define TK_OFFS_BOOT 0
#define max_t(t,a,b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define pr_warn(...) ((void)0)
#define pr_info(...) ((void)0)
#define DEFINE_SPINLOCK(x) int x
static int locks;
#define spin_lock_irqsave(l,f) do { (f)=0; (void)(l); assert(locks++ == 0); } while(0)
#define spin_unlock_irqrestore(l,f) do { (void)(l); (void)(f); assert(--locks == 0); } while(0)
typedef int64_t ktime_t;
static ktime_t now_mono, now_offset;
static ktime_t ktime_get(void) { return now_mono; }
static ktime_t ktime_mono_to_any(ktime_t x, int offs) { assert(offs==TK_OFFS_BOOT); return x+now_offset; }
static ktime_t ktime_sub(ktime_t a, ktime_t b) { return a-b; }
static int64_t ktime_to_ns(ktime_t a) { return a; }
struct timespec64 { int64_t tv_sec; long tv_nsec; };
static struct timespec64 ktime_to_timespec64(ktime_t a) {
 return (struct timespec64){ a/1000000000, a%1000000000 };
}
static int scnprintf(char *p, size_t n, const char *f, ...) {
 va_list a; int r; va_start(a,f); r=vsnprintf(p,n,f,a); va_end(a);
 return n ? (r < (int)n ? r : (int)n-1) : 0;
}
struct list_head { struct list_head *next,*prev; };
#define LIST_HEAD(n) struct list_head n={&n,&n}
#define INIT_LIST_HEAD(h) do { (h)->next=(h); (h)->prev=(h); } while(0)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_entry(p,t,m) container_of(p,t,m)
#define list_first_entry(h,t,m) list_entry((h)->next,t,m)
#define list_for_each_entry(p,h,m) \
 for(p=list_entry((h)->next,__typeof__(*p),m); &(p)->m!=(h); p=list_entry((p)->m.next,__typeof__(*p),m))
#define list_for_each_entry_rcu list_for_each_entry
static bool list_empty(struct list_head *h) { return h->next==h; }
static void list_add(struct list_head *n, struct list_head *h) {
 n->next=h->next; n->prev=h; h->next->prev=n; h->next=n;
}
static void list_add_tail(struct list_head *n, struct list_head *h) {list_add(n,h->prev);}
static void list_del(struct list_head *n) {n->next->prev=n->prev; n->prev->next=n->next;}
static void list_del_init(struct list_head *n) {list_del(n);INIT_LIST_HEAD(n);}
struct irqaction { const char *name; };
struct irq_desc { struct irqaction *action; };
static struct irqaction action={"rpm-glink"};
static struct irq_desc desc={&action};
static struct irq_desc *irq_to_desc(int irq) {return irq==999 ? NULL : &desc;}
struct kmem_cache {size_t size;};
static int init_failure, allocation_failure, outstanding, caches, objects, groups, notifiers;
static struct kmem_cache *kmem_cache_create(const char *n,size_t s,int a,int b,void *c) {
 struct kmem_cache *p; (void)n;(void)a;(void)b;(void)c;
 if(init_failure==1)return NULL;
 p=malloc(sizeof(*p));p->size=s;caches++;return p;
}
static void *kmem_cache_alloc(struct kmem_cache *p,int flags) {
 (void)flags; assert(p); if(allocation_failure)return NULL;
 outstanding++;return calloc(1,p->size);
}
static void kmem_cache_free(struct kmem_cache *p,void *n) {(void)p;outstanding--;free(n);}
static void kmem_cache_destroy(struct kmem_cache *p) {caches--;free(p);}
struct kobject {int unused;};
struct attribute {const char *name;unsigned mode;};
struct kobj_attribute {struct attribute attr;ssize_t (*show)(struct kobject *,struct kobj_attribute *,char *);};
struct attribute_group {struct attribute **attrs;};
#define __ATTR_RO(n) {{#n,0444},n##_show}
static struct kobject kernel_object, *kernel_kobj=&kernel_object;
static struct kobject *kobject_create_and_add(const char *n,struct kobject *p) {
 assert(!strcmp(n,"wakeup_reasons") && p==kernel_kobj);
 if(init_failure==2)return NULL; objects++;return malloc(sizeof(*p));
}
static void kobject_put(struct kobject *p) {objects--;free(p);}
static int sysfs_create_group(struct kobject *p,struct attribute_group *g) {
 (void)p;assert(g->attrs[0]->mode==0444 && g->attrs[1]->mode==0444);
 if(init_failure==3)return -EIO;groups++;return 0;
}
static void sysfs_remove_group(struct kobject *p,struct attribute_group *g) {(void)p;(void)g;groups--;}
struct notifier_block {int (*notifier_call)(struct notifier_block *,unsigned long,void *);};
static int register_pm_notifier(struct notifier_block *p) {
 assert(p && caches==1);if(init_failure==4)return -EINVAL;notifiers++;return 0;
}
static int srcu_depth,wakeup_srcu;
static int srcu_read_lock(int *s) {(void)s;assert(srcu_depth++==0);return 7;}
static void srcu_read_unlock(int *s,int idx) {(void)s;assert(idx==7 && --srcu_depth==0);}
struct wakeup_source {struct list_head entry;const char *name;bool active;ktime_t last_time;};
static LIST_HEAD(wakeup_sources);
'''
CASES = r'''
static int assertions;
#define CHECK(x) do {assertions++;if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static char buf[PAGE_SIZE];
static void reason(void){memset(buf,0,sizeof(buf));last_resume_reason_show(NULL,NULL,buf);}
static void times(void){memset(buf,0,sizeof(buf));last_suspend_time_show(NULL,NULL,buf);}
static void prepare(ktime_t mono,ktime_t off){now_mono=mono;now_offset=off;wakeup_reason_pm_event(NULL,PM_SUSPEND_PREPARE,NULL);}
static void finish(ktime_t mono,ktime_t off){now_mono=mono;now_offset=off;wakeup_reason_pm_event(NULL,PM_POST_SUSPEND,NULL);}
int main(void) {
 for(init_failure=1;init_failure<=4;init_failure++) {
  CHECK(wakeup_reason_init()<0);CHECK(caches==0);CHECK(objects==0);CHECK(groups==0);CHECK(notifiers==0);
  clear_wakeup_reasons();log_irq_wakeup_reason(193);log_suspend_abort_reason("failed init");
  reason();CHECK(buf[0]==0);CHECK(!capture_reasons);CHECK(outstanding==0);
 }
 init_failure=0;CHECK(wakeup_reason_init()==0);CHECK(caches==1 && objects==1 && groups==1 && notifiers==1);
 times();CHECK(!strcmp(buf,"0.000000000 0.000000000\n"));
 log_suspend_abort_reason("out of cycle");reason();CHECK(buf[0]==0);
 prepare(1000000000,2000000000);log_irq_wakeup_reason(193);log_irq_wakeup_reason(193);log_irq_wakeup_reason(5);
 reason();CHECK(!strcmp(buf,"5 rpm-glink\n193 rpm-glink\n"));CHECK(outstanding==2);
 finish(1200000000,32000000000LL);times();CHECK(!strcmp(buf,"0.200000000 30.000000000\n"));
 log_irq_wakeup_reason(777);reason();CHECK(strstr(buf,"777")==NULL);
 prepare(2000000000,32000000000LL);CHECK(outstanding==0);times();CHECK(!strcmp(buf,"0.200000000 30.000000000\n"));
 log_suspend_abort_reason("Callback %s returned %d","alarmtimer.0.auto",-16);
 log_suspend_abort_reason("later unrelated failure");log_irq_wakeup_reason(193);reason();
 CHECK(!strcmp(buf,"Abort: Callback alarmtimer.0.auto returned -16"));
 finish(2100000000,32000000000LL);times();CHECK(!strcmp(buf,"0.100000000 0.000000000\n"));
 prepare(3000000000,32000000000LL);log_abnormal_wakeup_reason("non-IRQ %d",42);reason();CHECK(!strcmp(buf,"-1 non-IRQ 42"));
 finish(3000000000,32000000000LL);times();CHECK(!strcmp(buf,"0.000000000 0.000000000\n"));
 prepare(4000000000,40000000000LL);finish(3999999999,39999999999LL);times();CHECK(!strcmp(buf,"0.000000000 0.000000000\n"));
 finish(99999999999LL,99999999999LL);times();CHECK(!strcmp(buf,"0.000000000 0.000000000\n"));
 prepare(0,0);log_irq_wakeup_reason(999);reason();CHECK(!strcmp(buf,"999 (unnamed)\n"));
 clear_wakeup_reasons();CHECK(outstanding==0);allocation_failure=1;log_irq_wakeup_reason(193);reason();CHECK(buf[0]==0);
 allocation_failure=0;clear_wakeup_reasons();log_irq_wakeup_reason(193);log_threaded_irq_wakeup_reason(194,193);log_threaded_irq_wakeup_reason(195,193);
 reason();CHECK(!strcmp(buf,"194 rpm-glink\n195 rpm-glink\n"));CHECK(outstanding==3);
 log_irq_wakeup_reason(193);log_threaded_irq_wakeup_reason(194,193);CHECK(outstanding==3);
 clear_wakeup_reasons();log_threaded_irq_wakeup_reason(194,193);reason();CHECK(buf[0]==0);
 log_suspend_abort_reason("%s", "percent %s %n remains data");reason();CHECK(!strcmp(buf,"Abort: percent %s %n remains data"));
 clear_wakeup_reasons();pm_log_pending_wakeup();reason();CHECK(!strcmp(buf,"Abort: Pending wakeup (source unavailable)"));
 struct wakeup_source a={.name="battery",.active=false,.last_time=10};
 struct wakeup_source b={.name="usb%p",.active=false,.last_time=20};
 list_add_tail(&a.entry,&wakeup_sources);list_add_tail(&b.entry,&wakeup_sources);
 clear_wakeup_reasons();pm_log_pending_wakeup();reason();CHECK(!strcmp(buf,"Abort: Wakeup pending; last active source: usb%p"));
 a.active=true;clear_wakeup_reasons();pm_log_pending_wakeup();reason();CHECK(!strcmp(buf,"Abort: Pending wakeup sources: battery "));
 b.active=true;clear_wakeup_reasons();pm_log_pending_wakeup();reason();CHECK(!strcmp(buf,"Abort: Pending wakeup sources: battery usb%p "));
 char long_name[2048];memset(long_name,'X',sizeof(long_name)-1);long_name[sizeof(long_name)-1]=0;
 a.name=long_name;clear_wakeup_reasons();pm_log_pending_wakeup();reason();CHECK(strlen(buf)==7+255);CHECK(srcu_depth==0 && locks==0);
 list_del(&a.entry);list_del(&b.entry);clear_wakeup_reasons();
 for(int i=0;i<1000;i++)log_irq_wakeup_reason(i);
 reason();CHECK(strlen(buf)<PAGE_SIZE);CHECK(outstanding==1000);
 clear_wakeup_reasons();CHECK(outstanding==0);
 sysfs_remove_group(kobj,&attr_group);kobject_put(kobj);kmem_cache_destroy(wakeup_irq_nodes_cache);
 CHECK(caches==0 && objects==0 && groups==0);
 printf("WAKEUP_ACTUAL_C=PASS; ASSERTIONS=%d; KERNEL_BUILD=NOT_RUN; DEVICE_PASS=NO\n",assertions);
 return 0;
}
'''

def check(source):
    c=(source/'kernel/power/wakeup_reason.c').read_text()
    wake=(source/'drivers/base/power/wakeup.c').read_text()
    start=wake.index('static void pm_log_pending_wakeup(void)')
    end=wake.index('/**\n * pm_wakeup_pending',start)
    collector=wake[start:end]
    with tempfile.TemporaryDirectory(prefix='wakeup-c-') as tmp:
        root=Path(tmp);inc=root/'linux';inc.mkdir()
        for name in re.findall(r'#include <linux/([^>]+)>',c):
            (inc/name).write_text('')
        (root/'test.c').write_text(STUB+c+'\n'+collector+CASES)
        exe=root/'test'
        subprocess.run(['gcc','-std=gnu11','-Wall','-Wextra','-Werror',
                        '-Wno-unused-parameter','-Wno-misleading-indentation',
                        '-fsanitize=undefined','-fno-sanitize-recover=all','-I',str(root),
                        str(root/'test.c'),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
        # Header stubs must also compile when CONFIG_SUSPEND is disabled.
        (root/'disabled.c').write_text('#include "'+str(source/'include/linux/wakeup_reason.h')+'"\n'
            'int main(void){clear_wakeup_reasons();log_irq_wakeup_reason(1);'
            'log_threaded_irq_wakeup_reason(1,2);log_suspend_abort_reason("x");'
            'log_abnormal_wakeup_reason("x");return 0;}\n')
        subprocess.run(['gcc','-Wall','-Werror',str(root/'disabled.c'),'-o',str(root/'disabled')],check=True)
        subprocess.run([str(root/'disabled')],check=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('source',type=Path)
    source = parser.parse_args().source.resolve()
    check(source)
    check_stats(source)
