import argparse
import angr
from angr import sim_options as so
from celery import Celery
import threading
import multiprocessing
import atexit
import tqdm
import time
import os

from function_models import SystemLibc
from function_models import *

# angr logging is way too verbose
import logging
from celery.result import allow_join_result

log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = True
    logger.propagate = False

try:
    import sys

    sys.stdout.encoding = (
        "UTF-8"  # AttributeError: 'LoggingProxy' object has no attribute 'encoding'
    )
except AttributeError:  # AttributeError: readonly attribute
    pass

# Hook for cmd inj
system_list = [
    "system",
    "execv",
    "execve",
    "popen",
    "execl",
    "execle",
    "execlp",
    "do_system",
    "doSystembk",
]

# function name and format arg position
printf_list = {"printf", "fprintf", "sprintf", "snprintf", "vsnprinf"}

options = {
    "broker_url": "pyamqp://guest@localhost//",
    "result_backend": "rpc://",
    "worker_max_memory_per_child": 2048000,
    "task_time_limit": 60,
    "accept_content": ["pickle", "json"],
    "result_serializer": "pickle",
    "task_serializer": "pickle",
}


app = Celery("CeleryTask")
app.config_from_object(options)


# Keep it simple. Make a blank state and let it run
# arguments are already symbolic data so we don't
# need to build a call state.
@app.task
def do_trace(proj, func_addr):
    sys.stdout.encoding = (
        "UTF-8"  # AttributeError: 'LoggingProxy' object has no attribute 'encoding'
    )
    state = proj.factory.blank_state(addr=func_addr)
    state.globals["func_addr"] = func_addr
    simgr = proj.factory.simgr(state)
    simgr.explore(find=lambda s: "exploitable" in s.globals)

    if "found" in simgr.stashes and len(simgr.found):
        return (func_addr, simgr.found[0].globals["cmd"])
    if "errored" in simgr.stashes and len(simgr.errored):
        for err_record in simgr.errored:
            print(err_record)
            print(err_record.state.globals.items())
            if "exploitable" in err_record.state.globals:
                return (func_addr, err_record.state.globals["cmd"])
    return None, None


def start_workers(worker):
    # t = threading.Thread(target=worker.start)
    p = multiprocessing.Process(target=worker.start)
    p.start()
    atexit.register(worker.stop)
    atexit.register(p.join)
    return p


# Best effort system hooks
def hook_list(p, hooks):
    for sys_type in hooks:
        try:
            p.hook_symbol(sys_type.name, SystemLibc())
        except Exception as e:
            print(e)
            pass


def hook_printf_list(p, hooks):
    for sys_type in hooks:
        try:
            p.hook_symbol(sys_type.name, printf_mapping[sys_type.name]())
        except Exception as e:
            print(e)
            pass


def get_funcs_and_prj(filename, system_check=False, printf_check=False):

    # Give us tracing information
    my_extras = {
        so.REVERSE_MEMORY_NAME_MAP,
        so.TRACK_ACTION_HISTORY,
        so.TRACK_MEMORY_ACTIONS,
        so.ACTION_DEPS,
        so.UNDER_CONSTRAINED_SYMEXEC,
    }

    # Don't fail at first issue
    my_extra = angr.options.resilience.union(my_extras)
    # Run faster
    my_extra = angr.options.unicorn.union(my_extra)

    p = angr.Project(filename, auto_load_libs=False)

    binary_system_list = [x for x in p.loader.symbols if x.name in system_list]

    binary_printf_list = [x for x in p.loader.symbols if x.name in printf_list]


    cfg = p.analyses.CFG(cross_references=True, show_progressbar=True)

    xrefs = set()


    if system_check:
        hook_list(p, binary_system_list)

        # Get all functions that have a system call
        # reference
        for func in binary_system_list:
            func_node = cfg.model.get_any_node(func.rebased_addr)
            func_callers = func_node.predecessors
            for func_caller in func_callers:
                xrefs.add(func_caller.function_address)

    if printf_check:
        hook_printf_list(p, binary_printf_list)

        # Get all functions that have a system call
        # reference
        for func in binary_printf_list:
            func_node = cfg.model.get_any_node(func.rebased_addr)
            if not func_node:
                continue
            func_callers = func_node.predecessors
            for func_caller in func_callers:
                xrefs.add(func_caller.function_address)

    xrefs = list(xrefs)

    print("Found {} test sites in binary".format(len(xrefs)))

    return xrefs, p


def async_and_iter(async_function, async_list):

    async_funcs = []

    for item in async_list:
        # n_task = async_function.delay(item)
        n_task = async_function.apply_async(args=[item[0], item[1]])
        async_funcs.append(n_task)

    bar = tqdm.tqdm(total=len(async_funcs))
    # If a process get's sigkilled, it kills this main parent
    # Sp just break when it fully fails
    while True:
        try:
            while not all([x.successful() or x.failed() for x in async_funcs]):
                done_count = len(
                    [
                        x.successful() or x.failed()
                        for x in async_funcs
                        if x.successful() or x.failed()
                    ]
                )
                bar.update(done_count - bar.n)
                time.sleep(1)
            break
        except ConnectionResetError:
            pass
    bar.close()

    with allow_join_result():
        return [x.get(propagate=False) for x in async_funcs if not x.failed()]


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Binary file to check")

    parser.add_argument(
        "-p",
        "--printf",
        help="Enable printf checking",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-s",
        "--system",
        help="Enable command injection checking",
        action="store_true",
        default=False,
    )

    args = parser.parse_args()

    if not args.system and not args.printf:
        print("Please select check mode of -p or -s. Or both")
        exit(0)

    if args.system:
        print("[~] Checking for command injections")

    if args.printf:
        print("[~] Checking for format string vulnerabilities")

    funcs, proj = get_funcs_and_prj(args.file, args.system, args.printf)

    if len(funcs) == 0:
        print("No test sites found. Exitting (Maybe no xrefs to checked functions?)")
        exit(0)

    # Remove any previous exitted runs
    app.control.purge()

    worker = app.Worker()

    t = start_workers(worker)

    pool_args = []

    for func in funcs:
        pool_args.append((proj, func))

    results = async_and_iter(do_trace, pool_args)

    app.control.shutdown()

    t.join()

    func_addres = [x for x, y in results]

    print("[-] Scanned functions:")
    for func in funcs:
        func_name = proj.loader.find_symbol(func)
        if func_name:
            func_name = func_name.name
        if func in func_addres:
            print("[+] : {} : {}".format(hex(func), func_name))
            pair = [(x, y) for x, y in results if x == func][0]
            print(pair[1])
        else:
            print("[-] : {} : {}".format(hex(func), func_name))


if __name__ == "__main__":
    main()
