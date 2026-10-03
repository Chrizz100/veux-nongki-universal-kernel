#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#define __user
#define MAX_ONE_RECORD_SIZE 128
struct file { int unused; };
static size_t copy_from_user(void *d,const void *s,size_t n) {memcpy(d,s,n);return 0;}
static char stored[MAX_ONE_RECORD_SIZE];
static void perflock_record(const char *msg) {snprintf(stored,sizeof(stored),"%s",msg);}
static ssize_t perflock_records_write(struct file *file, const char __user *userbuf,
		size_t count, loff_t *data)
{
	char buf[MAX_ONE_RECORD_SIZE + 1] = {0};

	if (count > MAX_ONE_RECORD_SIZE)
		return -EINVAL;

	if (copy_from_user(buf, userbuf, count))
		return -EFAULT;

	perflock_record(buf);

	return count;
}

int main(int argc, char **argv) {
 size_t n = argc>1 ? (size_t)strtoul(argv[1],NULL,10) : 128;
 char input[129]; memset(input,'A',sizeof(input));
 ssize_t ret=perflock_records_write(NULL,input,n,NULL);
 if (n>128) return ret==-EINVAL ? 0:2;
 if(ret!=(ssize_t)n || strlen(stored)!=(n>127?127:n)) return 3;
 return 0;
}
