// SPDX-License-Identifier: GPL-2.0-only
/* Independent public upstream Linux measurement. Only benign mmap,
 * /proc/self/maps, ftrace and synthetic trace_marker traffic. Disposable VM.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
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
#define TR "/sys/kernel/tracing/"
#define TAG "A6L_BENIGN "
#define PAGES 14000
#define REPS 2
#define MODES 3
static atomic_int wg,rg,ng,w_ready,r_ready,w_done,r_done,w_tid,r_tid,w_err,r_err;
static void *area;static size_t area_len;static int trace_fd=-1,marker_fd=-1,mode;
static char pending[32768];static size_t used;
static long long ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (long long)t.tv_sec*1000000000LL+t.tv_nsec;}
static int put(const char *path,const char *val){int fd=open(path,O_WRONLY|O_CLOEXEC);if(fd<0)return -1;ssize_t n=write(fd,val,strlen(val));close(fd);return n==(ssize_t)strlen(val)?0:-1;}
static int tid(const char *s){const char *p=strchr(s,'['),*e,*a;char *z;if(!p)return -1;e=p;while(e>s&&isspace((unsigned char)e[-1]))e--;a=e;while(a>s&&isdigit((unsigned char)a[-1]))a--;if(a==e||a<=s||a[-1]!='-')return -1;long n=strtol(a,&z,10);return z==e&&n>0&&n<10000000?(int)n:-1;}
static long long stamp(const char *s,const char *key){const char *p=strstr(s,key),*e,*a;char *z;if(!p||p-s<2||p[-2]!=':'||p[-1]!=' ')return -1;e=p-2;a=e;while(a>s&&a[-1]!=' ')a--;double x=strtod(a,&z);return z==e&&x>0?(long long)(x*1e9+0.5):-1;}
static int mmid(const char *s,char out[80]){const char *p=strstr(s,"mm=");if(!p)return -1;p+=3;size_t i=0;while(p[i]&&!isspace((unsigned char)p[i])&&i<79){out[i]=p[i];i++;}out[i]=0;return i>0&&!strstr(out,"ptrval")?0:-1;}
static void *writer(void *arg){(void)arg;atomic_store(&w_tid,(int)syscall(SYS_gettid));atomic_store(&w_ready,1);while(!atomic_load(&wg))sched_yield();int x=mprotect(area,area_len,PROT_NONE);atomic_store(&w_err,x?errno:0);atomic_store(&w_done,1);return NULL;}
static void *reader(void *arg){(void)arg;int f=open("/proc/self/maps",O_RDONLY|O_CLOEXEC);if(f<0){atomic_store(&r_err,errno);atomic_store(&r_done,1);return NULL;}atomic_store(&r_tid,(int)syscall(SYS_gettid));atomic_store(&r_ready,1);while(!atomic_load(&rg))sched_yield();char b[8192];ssize_t x=read(f,b,sizeof(b));atomic_store(&r_err,x<0?errno:0);atomic_store(&r_done,1);close(f);return NULL;}
static void *noise(void *arg){(void)arg;while(!atomic_load(&ng))sched_yield();if(mode){const char *x="A6L_SYNTHETIC_TRAFFIC\n";for(int i=0;i<200;i++){if(write(marker_fd,x,strlen(x))!=(ssize_t)strlen(x))break;}}return NULL;}
static int prep(void){size_t pg=(size_t)sysconf(_SC_PAGESIZE);area_len=PAGES*pg;area=mmap(NULL,area_len,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0);if(area==MAP_FAILED)return -1;for(size_t i=0;i<PAGES;i+=2)if(mprotect((char*)area+i*pg,pg,PROT_READ))return -1;return 0;}
typedef struct{long long wa,wr,rs,ra,kp;long long wa_poll,wa_read,wa_obs,rs_poll,rs_read,rs_obs,kp_poll,kp_read,kp_obs;char wm[80],rm[80];int lines,printed;} Sample;
static void parse(const char *line,long long poll_ts,long long read_ts,Sample *x){int t=tid(line);if(t<0)return;x->lines++;if(mode==2&&x->printed<40){printf(TAG "NOISE_LOG=%d\n",x->printed);x->printed++;}
long long q;char id[80];if(t==atomic_load(&w_tid)&&strstr(line,"mmap_lock_acquire_returned:")&&strstr(line,"write=true")&&strstr(line,"success=true")&&x->wa<0){q=stamp(line,"mmap_lock_acquire_returned:");if(q>0&&!mmid(line,id)){x->wa=q;strcpy(x->wm,id);x->wa_poll=poll_ts;x->wa_read=read_ts;x->wa_obs=ns();atomic_store(&rg,1);atomic_store(&ng,1);}}
if(t==atomic_load(&w_tid)&&strstr(line,"mmap_lock_released:")&&strstr(line,"write=true")&&x->wr<0)x->wr=stamp(line,"mmap_lock_released:");
if(t==atomic_load(&r_tid)&&strstr(line,"mmap_lock_start_locking:")&&strstr(line,"write=false")&&x->rs<0){q=stamp(line,"mmap_lock_start_locking:");if(q>0&&!mmid(line,id)){x->rs=q;strcpy(x->rm,id);x->rs_poll=poll_ts;x->rs_read=read_ts;x->rs_obs=ns();}}
if(t==atomic_load(&r_tid)&&strstr(line,"a6l_read:")&&x->kp<0){x->kp=stamp(line,"a6l_read:");x->kp_poll=poll_ts;x->kp_read=read_ts;x->kp_obs=ns();}
if(t==atomic_load(&r_tid)&&strstr(line,"mmap_lock_acquire_returned:")&&strstr(line,"write=false")&&strstr(line,"success=true")&&x->ra<0)x->ra=stamp(line,"mmap_lock_acquire_returned:");}
static void collect(Sample *x){struct pollfd p={.fd=trace_fd,.events=POLLIN};if(poll(&p,1,5)<=0)return;long long before=ns();char b[32768];ssize_t count=read(trace_fd,b,sizeof(b));long long after=ns();if(count<=0)return;for(ssize_t i=0;i<count;i++){if(b[i]=='\n'){pending[used]=0;parse(pending,before,after,x);used=0;}else if(used<sizeof(pending)-1)pending[used++]=b[i];else used=0;}}
static int run_one(int m,int rep){mode=m;atomic_store(&wg,0);atomic_store(&rg,0);atomic_store(&ng,0);atomic_store(&w_ready,0);atomic_store(&r_ready,0);atomic_store(&w_done,0);atomic_store(&r_done,0);atomic_store(&w_err,0);atomic_store(&r_err,0);used=0;
if(put(TR "tracing_on","0")||put(TR "trace","")||put(TR "events/kprobes/a6l_read/enable",m?"1":"0")||put(TR "events/sched/sched_switch/enable",m?"1":"0")||prep())return -1;
Sample x={.wa=-1,.wr=-1,.rs=-1,.ra=-1,.kp=-1,.wa_poll=-1,.wa_read=-1,.wa_obs=-1,.rs_poll=-1,.rs_read=-1,.rs_obs=-1,.kp_poll=-1,.kp_read=-1,.kp_obs=-1};pthread_t w,r,n;
if(pthread_create(&r,NULL,reader,NULL)||pthread_create(&w,NULL,writer,NULL)||pthread_create(&n,NULL,noise,NULL))return -1;
long long end=ns()+2000000000LL;while((!atomic_load(&r_ready)||!atomic_load(&w_ready))&&ns()<end)sched_yield();if(!atomic_load(&r_ready)||!atomic_load(&w_ready))return -1;
if(put(TR "tracing_on","1"))return -1;
atomic_store(&wg,1);end=ns()+2000000000LL;while(ns()<end&&(x.wa<0||x.wr<0||x.rs<0||x.ra<0||!atomic_load(&r_done)))collect(&x);
atomic_store(&rg,1);atomic_store(&ng,1);pthread_join(w,NULL);pthread_join(r,NULL);pthread_join(n,NULL);put(TR "tracing_on","0");
int identity=x.wm[0]&&x.rm[0]&&!strcmp(x.wm,x.rm);int complete=x.wa>0&&x.wr>0&&x.rs>0&&x.ra>0&&x.wa_poll>0&&x.rs_poll>0&&(!m||x.kp>0)&&!atomic_load(&w_err)&&!atomic_load(&r_err);int contended=complete&&identity&&x.wa<x.rs&&x.rs<x.wr&&x.wr<x.ra;
printf(TAG "SAMPLE mode=%d rep=%d complete=%d contended=%d same_mm=%d events=%d console=%d hold_us=%.3f read_wait_us=%.3f wa_poll_age_us=%.3f wa_read_us=%.3f wa_parse_age_us=%.3f rs_poll_age_us=%.3f rs_read_us=%.3f rs_parse_age_us=%.3f rs_obs_before_release=%d kp_seen=%d kp_kernel_before_release=%d kp_obs_before_release=%d kp_poll_age_us=%.3f kp_read_us=%.3f kp_parse_age_us=%.3f writer_errno=%d reader_errno=%d\n",m,rep,complete,contended,identity,x.lines,x.printed,(x.wr-x.wa)/1000.0,(x.ra-x.rs)/1000.0,(x.wa_poll-x.wa)/1000.0,(x.wa_read-x.wa_poll)/1000.0,(x.wa_obs-x.wa)/1000.0,(x.rs_poll-x.rs)/1000.0,(x.rs_read-x.rs_poll)/1000.0,(x.rs_obs-x.rs)/1000.0,x.rs_obs>0&&x.rs_obs<x.wr,x.kp>0,x.kp>0&&x.kp<x.wr,x.kp_obs>0&&x.kp_obs<x.wr,(x.kp_poll-x.kp)/1000.0,(x.kp_read-x.kp_poll)/1000.0,(x.kp_obs-x.kp)/1000.0,atomic_load(&w_err),atomic_load(&r_err));munmap(area,area_len);return complete?0:-1;}
int main(int argc,char **argv){if(argc==2&&!strcmp(argv[1],"--selftest")){const char*s="init-123       [001] .... 123.456789: mmap_lock_start_locking: mm=abcdef write=false";char mm[80];if(tid(s)!=123||stamp(s,"mmap_lock_start_locking:")!=123456789000LL||mmid(s,mm)||strcmp(mm,"abcdef"))return 81;puts(TAG "SELFTEST=PASS");return 0;}
setvbuf(stdout,NULL,_IONBF,0);if(getpid()==1){mkdir("/proc",0555);mkdir("/sys",0555);mkdir("/sys/kernel",0555);mkdir(TR,0555);mount("proc","/proc","proc",0,NULL);mount("tracefs",TR,"tracefs",0,NULL);}puts(TAG "START NO_PROCESS_EXEC NO_CPU_TIMERS NO_TERMINATING_SIGNALS");
if(put(TR "tracing_on","0")||put(TR "trace_clock","mono")||put(TR "events/mmap_lock/mmap_lock_start_locking/enable","1")||put(TR "events/mmap_lock/mmap_lock_acquire_returned/enable","1")||put(TR "events/mmap_lock/mmap_lock_released/enable","1")){puts(TAG "TRACE_SETUP_FAILED");return 2;}
int pf=open(TR "kprobe_events",O_WRONLY|O_APPEND|O_CLOEXEC);const char*def="p:a6l_read down_read_killable\n";if(pf<0||write(pf,def,strlen(def))!=(ssize_t)strlen(def)){puts(TAG "KPROBE_SETUP_FAILED");return 3;}close(pf);
marker_fd=open(TR "trace_marker",O_WRONLY|O_CLOEXEC);trace_fd=open(TR "trace_pipe",O_RDONLY|O_NONBLOCK|O_CLOEXEC);if(marker_fd<0||trace_fd<0)return 4;int bad=0;for(int m=0;m<MODES;m++)for(int i=0;i<REPS;i++)if(run_one(m,i))bad++;
printf(TAG "RESULT samples=%d incomplete=%d benign_only=1\n",MODES*REPS,bad);close(marker_fd);close(trace_fd);fflush(stdout);if(getpid()==1){sync();reboot(RB_POWER_OFF);for(;;)pause();}return bad?5:0;}
