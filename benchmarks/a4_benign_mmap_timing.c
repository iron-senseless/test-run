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

/* Public upstream-only, benign timing: no exec, POSIX CPU timers or UAF. */
#define TR "/sys/kernel/tracing/"
#define TAG "A4_BENIGN "
static atomic_int go, ready, target_tid, stop, sender_errno;
static atomic_llong received_ns;
static void *mapping;
static size_t mapping_len;

static long long mono(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}
static int put(const char *p, const char *s) {
    int fd = open(p, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = write(fd, s, strlen(s));
    close(fd);
    return n == (ssize_t)strlen(s) ? 0 : -1;
}
static long long timestamp(const char *line, const char *name) {
    const char *p = strstr(line, name);
    if (!p || p < line+2 || p[-2] != ':' || p[-1] != ' ') return -1;
    const char *colon = p-2, *s = colon;
    while (s > line && s[-1] != ' ') --s;
    char *end;
    double sec = strtod(s, &end);
    if (end != colon || sec <= 0) return -1;
    return (long long)(sec * 1000000000.0 + 0.5);
}
static void on_signal(int sig) {
    if (sig == SIGUSR1) atomic_store(&received_ns, mono());
}
static void *receiver(void *unused) {
    (void)unused;
    sigset_t s; sigemptyset(&s); sigaddset(&s, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &s, NULL);
    atomic_store(&target_tid, (int)syscall(SYS_gettid));
    atomic_store(&ready, 1);
    while (!atomic_load(&stop)) pause();
    return NULL;
}
static void *writer(void *unused) {
    (void)unused;
    while (!atomic_load(&go)) sched_yield();
    int r = mprotect(mapping, mapping_len, PROT_NONE);
    atomic_store(&sender_errno, r ? errno : 0);
    return NULL;
}
static int fragment(size_t pages) {
    size_t p = (size_t)sysconf(_SC_PAGESIZE);
    mapping_len = pages * p;
    mapping = mmap(NULL, mapping_len, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (mapping == MAP_FAILED) return -1;
    for (size_t i=0; i<pages; i+=2)
        if (mprotect((char*)mapping + i*p, p, PROT_READ)) return -1;
    return 0;
}
static int sample(int pipefd, int id, size_t pages) {
    atomic_store(&go, 0);
    atomic_store(&received_ns, -1);
    atomic_store(&sender_errno, 0);
    if (put(TR "tracing_on","0") || put(TR "trace","")) return -1;
    if (fragment(pages)) return -1;
    pthread_t th;
    if (pthread_create(&th, NULL, writer, NULL)) return -1;
    if (put(TR "tracing_on","1")) return -1;
    atomic_store(&go, 1);
    char buf[16384] = {0};
    size_t used = 0;
    long long acq=-1, rel=-1, notified=-1;
    int signal_rc=-1;
    long long deadline=mono()+4000000000LL;
    while (mono()<deadline && (acq<0 || rel<0)) {
        struct pollfd pf={.fd=pipefd,.events=POLLIN};
        if (poll(&pf,1,100)<=0) continue;
        ssize_t n=read(pipefd, buf+used,sizeof(buf)-used-1);
        if(n<=0) continue;
        used+=(size_t)n; buf[used]=0;
        char *begin=buf,*end;
        while((end=strchr(begin,'\n'))!=NULL) {
            *end=0;
            bool w=strstr(begin,"write=true")!=NULL;
            if(w && acq<0 && strstr(begin,"mmap_lock_acquire_returned:") &&
               strstr(begin,"success=true")) {
                acq=timestamp(begin,"mmap_lock_acquire_returned:");
                notified=mono();
                signal_rc=(int)syscall(SYS_tgkill,getpid(),atomic_load(&target_tid),SIGUSR1);
            }
            if(w && rel<0 && strstr(begin,"mmap_lock_released:"))
                rel=timestamp(begin,"mmap_lock_released:");
            begin=end+1;
        }
        used=strlen(begin); memmove(buf,begin,used);
        if(used>sizeof(buf)/2) used=0;
    }
    pthread_join(th,NULL);
    long long delivered=atomic_load(&received_ns);
    printf(TAG "SAMPLE id=%d pages=%zu hold_us=%.3f notify_us=%.3f signal_handler_us=%.3f handler_before_release=%d writer_errno=%d signal_rc=%d\n",
           id,pages,
           acq>0 && rel>acq ? (rel-acq)/1000.0 : -1.,
           acq>0 && notified>0 ? (notified-acq)/1000.0 : -1.,
           acq>0 && delivered>0 ? (delivered-acq)/1000.0 : -1.,
           acq>0 && rel>0 && delivered>0 && delivered<rel,
           atomic_load(&sender_errno),signal_rc);
    munmap(mapping,mapping_len);
    return acq>0 && rel>acq && notified>0 && signal_rc==0 &&
           delivered>0 && atomic_load(&sender_errno)==0 ? 0 : -1;
}
int main(int argc, char **argv) {
    if(argc==2 && !strcmp(argv[1],"--selftest")) {
        const char *a="p-1 [000] .... 123.456789: mmap_lock_acquire_returned: mm=x write=true success=true";
        const char *b="p-1 [000] .... 123.457123: mmap_lock_released: mm=x write=true";
        if(timestamp(a,"mmap_lock_acquire_returned:")!=123456789000LL ||
           timestamp(b,"mmap_lock_released:")!=123457123000LL) return 10;
        puts(TAG "PARSER_SELFTEST=PASS");
        return 0;
    }
    setvbuf(stdout,NULL,_IONBF,0);
    if(getpid()==1) {
        mkdir("/proc",0555); mkdir("/sys",0555); mkdir("/sys/kernel",0555);
        mkdir(TR,0555);
        (void)mount("proc","/proc","proc",0,NULL);
        (void)mount("tracefs",TR,"tracefs",0,NULL);
    }
    puts(TAG "START UPSTREAM_ONLY NO_EXEC NO_POSIX_TIMERS NO_UAF");
    if(put(TR "tracing_on","0") || put(TR "trace_clock","mono") ||
       put(TR "trace","") ||
       put(TR "events/mmap_lock/mmap_lock_acquire_returned/enable","1") ||
       put(TR "events/mmap_lock/mmap_lock_released/enable","1")) {
        puts(TAG "TRACEFS_NOT_AVAILABLE"); return 2;
    }
    sigset_t block;
    sigemptyset(&block); sigaddset(&block,SIGUSR1);
    pthread_sigmask(SIG_BLOCK,&block,NULL);
    struct sigaction sa={0}; sa.sa_handler=on_signal;
    sigaction(SIGUSR1,&sa,NULL);
    pthread_t recv;
    if(pthread_create(&recv,NULL,receiver,NULL)) return 3;
    while(!atomic_load(&ready)) sched_yield();
    int fd=open(TR "trace_pipe",O_RDONLY|O_NONBLOCK|O_CLOEXEC);
    if(fd<0) return 4;
    int failed=0;
    for(int i=0;i<6;i++) if(sample(fd,i,i<3?1800:3600)) failed++;
    put(TR "tracing_on","0"); close(fd);
    atomic_store(&stop,1);
    syscall(SYS_tgkill,getpid(),atomic_load(&target_tid),SIGUSR1);
    pthread_join(recv,NULL);
    printf(TAG "RESULT samples=6 failures=%d\n",failed);
    fflush(stdout);
    if(getpid()==1) { sync(); reboot(RB_POWER_OFF); for(;;) pause(); }
    return failed?5:0;
}
