#!/usr/bin/env python3
"""A1 off-device state model of publicly documented CVE-2026-98260.

Zero kernel APIs, no subprocess, signal, exec, timer syscalls, emulator or
device operation. Abstract state transitions are deliberately conditional.
"""
from dataclasses import dataclass

POST_SWAP_FAILURES = ("unshare_files", "set_mm_exe_file", "exec_mmap")
SCENARIOS = ("pre_commit", "de_thread_before_swap", *POST_SWAP_FAILURES, "late_failure", "success")

@dataclass(frozen=True)
class Result:
    variant: str
    scenario: str
    nonleader: bool
    armed: bool
    pid_lookup_valid: bool
    node_queued: bool
    timer_freed: bool
    stale_node_after_exit: bool
    late_read_freed_node: bool
    uid0_proved: bool
    evidence: str
    events: tuple[str, ...]

def simulate(variant: str, scenario: str, *, nonleader: bool = True,
             armed: bool = True, parent_reaps: bool = True) -> Result:
    if variant not in ("old", "fixed"):
        raise ValueError("variant must be old or fixed")
    if scenario not in SCENARIOS:
        raise ValueError("unknown scenario")
    events = ["timer created and armed" if armed else "no armed timer"]
    queued = armed
    freed = False
    pid_valid = True
    point_no_return = False

    def cleanup_queue(reason: str) -> None:
        nonlocal queued
        if queued:
            queued = False
            events.append(reason + ": remove timerqueue node")
        else:
            events.append(reason + ": no queued node")

    def delete_timer() -> None:
        nonlocal queued, freed
        if not armed or freed:
            return
        # timer_lock_sighand uses timer.it.cpu.pid to find its task.
        if pid_valid:
            cleanup_queue("posix_cpu_timer_del PID lookup succeeded")
        else:
            events.append("posix_cpu_timer_del: PID lookup NULL; cannot disarm queued node")
        freed = True
        events.append("exit_itimers / itimer_delete: release k_itimer")

    if scenario == "pre_commit":
        events.append("pre-commit error: exec returns before PONR and de_thread")
    else:
        point_no_return = True
        events.append("point_of_no_return=true")
        if scenario == "de_thread_before_swap":
            events.append("de_thread fails before exchange_tids: no PID reassignment")
        else:
            if nonleader:
                pid_valid = False
                events.append("exchange_tids/release_task old leader: old thread PID no task")
            else:
                events.append("leader exec: no exchange_tids; thread PID resolves")

            if variant == "fixed":
                cleanup_queue("fixed begin_new_exec: posix_cpu_timers_exit directly after de_thread")
                delete_timer()
            if scenario in ("success", "late_failure") and variant == "old":
                cleanup_queue("old begin_new_exec: reached late posix_cpu_timers_exit")
                delete_timer()

        if scenario != "success":
            events.append("fatal exec error: task exits")
            delete_timer()

    stale = bool(freed and queued)
    deref = bool(stale and parent_reaps)
    if parent_reaps and point_no_return and scenario != "success":
        events.append("release_task/__exit_signal: posix_cpu_timers_exit reads tree"
                      + (" with freed node" if stale else " without dangling node"))
    if not parent_reaps and stale:
        events.append("no reaping modeled: dangling node exists, late access unobserved")
    return Result(variant, scenario, nonleader, armed, pid_valid, queued,
                  freed, stale, deref, False, "UPSTREAM_DERIVED_HOST_SYNTHETIC", tuple(events))

if __name__ == "__main__":
    for step in ("pre_commit", "de_thread_before_swap", "unshare_files",
                 "set_mm_exe_file", "exec_mmap", "late_failure", "success"):
        for version in ("old", "fixed"):
            result = simulate(version, step)
            print(f"A1_MODEL {version} stage={step} queued={int(result.node_queued)} "
                  f"freed={int(result.timer_freed)} stale={int(result.stale_node_after_exit)} "
                  f"late_uaf={int(result.late_read_freed_node)}")
    print("PUBLIC_SOURCE_ONLY=PASS WATCH7_ACTIONS=NONE PRIVILEGE_PROOF=NONE")
