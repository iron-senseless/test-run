#!/usr/bin/env python3
"""Read-only pinned public Linux 6.1 source gate for CVE-2026-98260.

Every downloaded source is a publicly released upstream Linux file, verified
against its Git blob SHA-1. No private repository, firmware or credentials.
"""
import hashlib
import re
import urllib.error
import urllib.request
import time

OLD = "e44cee1bf51e606f3e70a213eb5a1abb3fa56a81"
FIXED = "f6c93e8ecaaf12959b7ef6eb611351001db2ff5d"
PINS = {
    (OLD, "fs/exec.c"): "6ff6367793b9e2a5508a278c91e1fdd765fbd024",
    (FIXED, "fs/exec.c"): "7391ec00a1cc1b0a4b63fe3f84ad30528b623f6d",
    (FIXED, "kernel/time/posix-cpu-timers.c"): "c5f7ca683e7ebae00edffe3006d552076b4e12ba",
    (FIXED, "kernel/time/posix-timers.c"): "fc08d4ccdeeb9e8c54c806b8537a7edb70573701",
    (FIXED, "kernel/exit.c"): "413540df3e1855d0567c52e9c189a77d0705a450",
    (FIXED, "kernel/pid.c"): "3e78a61519ba113e8c35eefb1bf07c60fffae874",
}

def fetch_exact(rev: str, path: str) -> str:
    url = f"https://raw.githubusercontent.com/gregkh/linux/{rev}/{path}"
    last = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "GhostMyFresh-public-A1/1"})
            with urllib.request.urlopen(req, timeout=20) as response:
                raw = response.read()
            break
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last = exc
            if attempt == 2:
                raise
            time.sleep(2 * (attempt + 1))
    else:
        raise RuntimeError(f"failed to load public source {path}") from last
    sha = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if sha != PINS[(rev, path)]:
        raise AssertionError(f"PUBLIC SOURCE GIT BLOB MISMATCH {path} at {rev}: {sha}")
    print(f"A1_PUBLIC_SOURCE_PIN rev={rev[:12]} path={path} blob={sha} PASS")
    return raw.decode("utf-8")

def source_function(src: str, header: str) -> str:
    idx = src.find(header)
    if idx < 0:
        raise AssertionError(f"source function missing: {header}")
    open_at = src.find("{", idx)
    depth = 0
    for i in range(open_at, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if not depth:
                return src[idx:i+1]
    raise AssertionError("unterminated function")

def has_in_order(src, *terms):
    offsets = [src.find(q) for q in terms]
    if any(n < 0 for n in offsets) or offsets != sorted(offsets):
        raise AssertionError(f"source ordering mismatch: {terms}")

def validate(source):
    old = source_function(source[(OLD, "fs/exec.c")], "int begin_new_exec(")
    fixed = source_function(source[(FIXED, "fs/exec.c")], "int begin_new_exec(")
    prefix = ("bprm->point_of_no_return = true;", "retval = de_thread(me);")
    for text in (old, fixed):
        has_in_order(text, *prefix)
        for fail in ("retval = unshare_files();",
                     "retval = set_mm_exe_file(bprm->mm, bprm->file);",
                     "retval = exec_mmap(bprm->mm);"):
            if fail not in text:
                raise AssertionError(f"missing fallible operation: {fail}")
    has_in_order(old, "retval = de_thread(me);", "retval = exec_mmap(bprm->mm);",
                 "posix_cpu_timers_exit(me);", "exit_itimers(me);")
    has_in_order(fixed, "retval = de_thread(me);", "posix_cpu_timers_exit(me);",
                 "exit_itimers(me);", "retval = unshare_files();")
    if old.count("posix_cpu_timers_exit(me);") != 1 or fixed.count("posix_cpu_timers_exit(me);") != 1:
        raise AssertionError("unexpected POSIX CPU timer cleanup count")
    print("A1_PRE_POST_EXEC_ORDER_DIFF=PASS")

    cpu = source[(FIXED, "kernel/time/posix-cpu-timers.c")]
    lock = source_function(cpu, "static struct task_struct *timer_lock_sighand(")
    deletion = source_function(cpu, "static int posix_cpu_timer_del(")
    clear = source_function(cpu, "static void cleanup_timerqueue(")
    for needle in ("pid_task(", "if (!t)", "return NULL;"):
        if needle not in lock:
            raise AssertionError("missing PID lookup guard " + needle)
    for needle in ("timer_lock_sighand(timer", "if (likely(p))", "disarm_timer(timer, p);"):
        if needle not in deletion:
            raise AssertionError("missing conditional disarm " + needle)
    for needle in ("timerqueue_getnext(head)", "timerqueue_del(head, node)"):
        if needle not in clear:
            raise AssertionError("missing queued-node reader " + needle)
    timers = source[(FIXED, "kernel/time/posix-timers.c")]
    exit_fn = source_function(timers, "void exit_itimers(")
    delete_fn = source_function(timers, "static void itimer_delete(")
    if "itimer_delete(tmr)" not in exit_fn or "release_posix_timer(timer, IT_ID_SET);" not in delete_fn:
        raise AssertionError("missing release path")
    process_exit = source_function(source[(FIXED, "kernel/exit.c")], "void __noreturn do_exit(")
    reaping = source_function(source[(FIXED, "kernel/exit.c")], "void release_task(")
    if "exit_itimers(tsk);" not in process_exit or "__exit_signal(p);" not in reaping:
        raise AssertionError("missing exit or reap cleanup")
    pid = source_function(source[(FIXED, "kernel/pid.c")], "void exchange_tids(")
    if "hlists_swap_heads_rcu" not in pid:
        raise AssertionError("PID swap witness missing")
    print("A1_TIMER_OWNER_QUEUE_RELEASE_AND_REAP=PASS")
    print("A1_VERDICT=UPSTREAM_CONDITIONAL_LIFETIME_CHAIN")
    print("ORIGINAL_OEM_CODE_EXECUTED=NO HOST_GUEST=NO WATCH7_ACTIONS=NONE")

if __name__ == "__main__":
    src = {key: fetch_exact(*key) for key in PINS}
    validate(src)
