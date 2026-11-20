#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* Generic Linux benign same-mm timing; no exec, timers or exploit. */
#define TR "/sys/kernel/tracing/"
#define OUT "A5_BENIGN "
#define COUNT 6
static atomic_int wg,rg,wrdy,rrdy,wtid,rtid,wdone,rdone,werr,rerr;
static atomic_llong handler_ns;
static void *range;
static size_t range_len;

static long long ns(void) {
    struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
    return (long long)t.tv_sec*1000000000LL+t.tv_nsec;
}
static int put(const char *p,const char *v) {
    int f=open(p,O_WRONLY|O_CLOEXEC);if(f<0)return -1;
    ssize_t n=write(f,v,strlen(v));close(f);return n==(ssize_t)strlen(v)?0:-1;
}
static long long ts(const char *s,const char *name) {
    const char *p=strstr(s,name);
    if(!p || p-s<2 || p[-2]!=':' || p[-1]!=' ')return -1;
    const char *c=p-2,*a=c;
    while(a>s && a[-1]!=' ')a--;
    char *end;double v=strtod(a,&end);
    return end==c&&v>0?(long long)(v*1e9+0.5):-1;
}
static int tid(const char *s) {
    const char *b=strstr(s," [");if(!b)return -1;
    const char *a=b;
    while(a>s && a[-1]!='-')a--;
    char *end;long n=strtol(a,&end,10);
    return a>s&&end==b&&n>0&&n<100000000?(int)n:-1;
}
static int nfield(const char *s,const char *key) {
    const char *p=strstr(s,key);return p?atoi(p+strlen(key)):-1;
}
static int mmfield(const char *s,char out[80]) {
    const char *p=strstr(s,"mm=");if(!p)return -1;p+=3;
    size_t i=0;
    while(p[i]&&p[i]!=' '&&p[i]!='\t'&&i<79){out[i]=p[i];i++;}
    out[i]=0;return i?0:-1;
}
static void handler(int sig){if(sig==SIGUSR1)atomic_store(&handler_ns,ns());}
static void *wfn(void *arg){
    (void)arg;atomic_store(&wtid,(int)syscall(SYS_gettid));atomic_store(&wrdy,1);
    while(!atomic_load(&wg))sched_yield();
    int r=mprotect(range,range_len,PROT_NONE);atomic_store(&werr,r?errno:0);
    atomic_store(&wdone,1);return NULL;
}
static void *rfn(void *arg){
    (void)arg;
    sigset_t s;sigemptyset(&s);sigaddset(&s,SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK,&s,NULL);
    int f=open("/proc/self/maps",O_RDONLY|O_CLOEXEC);
    if(f<0){atomic_store(&rerr,errno);atomic_store(&rdone,1);return NULL;}
    atomic_store(&rtid,(int)syscall(SYS_gettid));atomic_store(&rrdy,1);
    while(!atomic_load(&rg))sched_yield();
    char b[8192];ssize_t r=read(f,b,sizeof(b));
    atomic_store(&rerr,r<0?errno:0);atomic_store(&rdone,1);close(f);return NULL;
}
static int prep(size_t pages) {
    size_t p=(size_t)sysconf(_SC_PAGESIZE);range_len=pages*p;
    range=mmap(NULL,range_len,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0);
    if(range==MAP_FAILED)return -1;
    for(size_t i=0;i<pages;i+=2)
        if(mprotect((char*)range+i*p,p,PROT_READ))return -1;
    return 0;
}
struct rec {
    long long wa,wr,rs,ra,sg,sd;
    char wm[80],rm[80];
    int sent,send_rc;
};
static void parse(char *line,struct rec *x,int control) {
    int t=tid(line);if(t<0)return;
    long long n;char m[80];
    if(t==atomic_load(&wtid)&&strstr(line,"write=true")&&
       strstr(line,"mmap_lock_acquire_returned:")&&strstr(line,"success=true")) {
        n=ts(line,"mmap_lock_acquire_returned:");
        if(n>0&&x->wa<0&&!mmfield(line,m)){
            x->wa=n;strcpy(x->wm,m);
            if(!control)atomic_store(&rg,1);
        }
    }
    if(t==atomic_load(&wtid)&&strstr(line,"write=true")&&
       strstr(line,"mmap_lock_released:")) {
        n=ts(line,"mmap_lock_released:");
        if(n>0&&x->wr<0){x->wr=n;if(control)atomic_store(&rg,1);}
    }
    if(t==atomic_load(&rtid)&&strstr(line,"write=false")&&
       strstr(line,"mmap_lock_start_locking:")) {
        n=ts(line,"mmap_lock_start_locking:");
        if(n>0&&x->rs<0&&!mmfield(line,m)){
            x->rs=n;strcpy(x->rm,m);
            x->send_rc=(int)syscall(SYS_tgkill,getpid(),atomic_load(&rtid),SIGUSR1);
            x->sent=1;
        }
    }
    if(t==atomic_load(&rtid)&&strstr(line,"write=false")&&
       strstr(line,"mmap_lock_acquire_returned:")&&strstr(line,"success=true")) {
        n=ts(line,"mmap_lock_acquire_returned:");
        if(n>0&&x->ra<0)x->ra=n;
    }
    if(t==(int)syscall(SYS_gettid)&&strstr(line,"signal_generate:")&&
       nfield(line,"sig=")==SIGUSR1&&nfield(line,"pid=")==atomic_load(&rtid)){
        n=ts(line,"signal_generate:");if(n>0&&x->sg<0)x->sg=n;
    }
    if(t==atomic_load(&rtid)&&strstr(line,"signal_deliver:")&&
       nfield(line,"sig=")==SIGUSR1){
        n=ts(line,"signal_deliver:");if(n>0&&x->sd<0)x->sd=n;
    }
}
static int sample(int f,int id,size_t pages,int control,int *positive) {
    atomic_store(&wg,0);atomic_store(&rg,0);
    atomic_store(&wrdy,0);atomic_store(&rrdy,0);
    atomic_store(&wdone,0);atomic_store(&rdone,0);
    atomic_store(&werr,0);atomic_store(&rerr,0);atomic_store(&handler_ns,-1);
    if(put(TR "tracing_on","0")||put(TR "trace","")||prep(pages))return -1;
    pthread_t w,r;
    if(pthread_create(&r,NULL,rfn,NULL))return -1;
    if(pthread_create(&w,NULL,wfn,NULL))return -1;
    while(!atomic_load(&rrdy)||!atomic_load(&wrdy))sched_yield();
    struct rec x={.wa=-1,.wr=-1,.rs=-1,.ra=-1,.sg=-1,.sd=-1,.send_rc=-1};
    if(put(TR "tracing_on","1"))return -1;
    atomic_store(&wg,1);
    char buf[16384]={0};size_t used=0;
    int total_lines=0,debug_lines=0;
    long long end=ns()+4000000000LL;
    while(ns()<end && (x.sd<0||x.ra<0||x.wr<0||!atomic_load(&rdone))){
        struct pollfd pf={.fd=f,.events=POLLIN};
        if(poll(&pf,1,20)<=0)continue;
        ssize_t z=read(f,buf+used,sizeof(buf)-used-1);
        if(z<=0)continue;
        used+=(size_t)z;buf[used]=0;
        char *p=buf,*q;
        while((q=strchr(p,'\n'))){
            *q=0;
            total_lines++;
            if(id==0 && debug_lines<16 && strstr(p,"mmap_lock")) {
                printf(OUT "TRACE_DEBUG tid=%d writer=%d reader=%d text=%.*s\n",
                       tid(p),atomic_load(&wtid),atomic_load(&rtid),225,p);
                debug_lines++;
            }
            parse(p,&x,control);
            p=q+1;
        }
        used=strlen(p);memmove(buf,p,used);
        if(used>sizeof(buf)/2)used=0;
    }
    atomic_store(&rg,1);
    pthread_join(w,NULL);pthread_join(r,NULL);
    put(TR "tracing_on","0");
    int same=x.wm[0]&&x.rm[0]&&!strcmp(x.wm,x.rm);
    int ordered=x.wa>0&&x.rs>x.wa&&x.sg>x.rs&&x.wr>x.sg&&
                x.ra>x.wr&&x.sd>=x.ra&&same;
    if(!control&&ordered&&x.sent&&x.send_rc==0&&
       !atomic_load(&werr)&&!atomic_load(&rerr))(*positive)++;
    printf(OUT "SAMPLE id=%d control=%d pages=%zu wtid=%d rtid=%d same_mm=%d "
           "wa=%lld rs=%lld sg=%lld wr=%lld ra=%lld sd=%lld "
           "hold_us=%.3f read_wait_us=%.3f ordered=%d signal_rc=%d "
           "handler_seen=%d writer_errno=%d reader_errno=%d\n",
           id,control,pages,atomic_load(&wtid),atomic_load(&rtid),same,
           x.wa,x.rs,x.sg,x.wr,x.ra,x.sd,
           x.wa>0&&x.wr>0?(x.wr-x.wa)/1000.0:-1.,
           x.rs>0&&x.ra>0?(x.ra-x.rs)/1000.0:-1.,
           ordered,x.send_rc,atomic_load(&handler_ns)>0,
           atomic_load(&werr),atomic_load(&rerr));
    printf(OUT "TRACE_LINES id=%d total=%d debug=%d\n",id,total_lines,debug_lines);
    munmap(range,range_len);
    if(atomic_load(&werr)||atomic_load(&rerr))return -1;
    if(x.wa<0||x.wr<0||x.rs<0||x.ra<0)return -1;
    return 0;
}
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"--selftest")){
        const char *s="p-123 [001] .... 123.456789: mmap_lock_start_locking: mm=abcdef write=false";
        char m[80];
        if(tid(s)!=123||ts(s,"mmap_lock_start_locking:")!=123456789000LL||
           mmfield(s,m)||strcmp(m,"abcdef"))return 12;
        puts(OUT "SELFTEST=PASS");return 0;
    }
    setvbuf(stdout,NULL,_IONBF,0);
    if(getpid()==1){
        mkdir("/proc",0555);mkdir("/sys",0555);mkdir("/sys/kernel",0555);
        mkdir(TR,0555);mount("proc","/proc","proc",0,NULL);
        mount("tracefs",TR,"tracefs",0,NULL);
    }
    puts(OUT "START PUBLIC_UPSTREAM_ONLY NO_EXEC NO_TIMERS NO_UAF");
    if(put(TR "tracing_on","0")||put(TR "trace_clock","mono")||
       put(TR "trace","")||
       put(TR "events/mmap_lock/mmap_lock_start_locking/enable","1")||
       put(TR "events/mmap_lock/mmap_lock_acquire_returned/enable","1")||
       put(TR "events/mmap_lock/mmap_lock_released/enable","1")||
       put(TR "events/signal/signal_generate/enable","1")||
       put(TR "events/signal/signal_deliver/enable","1")){
        puts(OUT "TRACEFS_UNAVAILABLE");return 2;
    }
    sigset_t s;sigemptyset(&s);sigaddset(&s,SIGUSR1);
    pthread_sigmask(SIG_BLOCK,&s,NULL);
    struct sigaction a={0};a.sa_handler=handler;sigaction(SIGUSR1,&a,NULL);
    int f=open(TR "trace_pipe",O_RDONLY|O_NONBLOCK|O_CLOEXEC);
    if(f<0)return 3;
    int failures=0,positives=0;
    for(int i=0;i<COUNT;i++)
        if(sample(f,i,i?9600:3600,!i,&positives))failures++;
    printf(OUT "RESULT total=6 positive=%d infra_failures=%d benign_only=1\n",
           positives,failures);
    close(f);fflush(stdout);
    if(getpid()==1){sync();reboot(RB_POWER_OFF);for(;;)pause();}
    return failures?4:0;
}
